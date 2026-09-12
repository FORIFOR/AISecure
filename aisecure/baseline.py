"""Synthetic normal-business traffic, for measuring false positives before deployment.

Thresholds that look obvious on a demo are wrong on real traffic: backup accounts,
indexing services, analysts and migration days all read many files quickly and are
entirely legitimate. This module generates that kind of traffic deterministically
so a threshold can be judged by how much normal work it flags.

Synthetic traffic is a rehearsal, not evidence. A threshold chosen here still has
to be re-measured against the organization's own logs before it is trusted.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import random

from .schema import iso, ValidationError, object_keys

SCENARIO_VERSION = 1
JST = timezone(timedelta(hours=9))
BEHAVIORAL_RULES = ("AS-002", "AS-003", "AS-004")
HYGIENE_RULES = ("AS-001", "AS-005")


class Builder:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.events: list[dict] = []
        self.malicious: set[str] = set()
        self.counter = 0

    def _id(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter:06}"

    def login(self, at: datetime, actor: str, session: str, gateway: str, *, success=True,
              privileged=None, device_trusted=None, approved=None, malicious=False) -> str:
        eid = self._id("lg")
        self.events.append({"id": eid, "type": "login", "at": iso(at), "actor": actor, "session": session,
                            "gateway_id": gateway, "success": success, "privileged": privileged,
                            "device_trusted": device_trusted, "approved": approved})
        if malicious:
            self.malicious.add(eid)
        return eid

    def reads(self, start: datetime, actor: str, session: str, asset: str, count: int, *,
              spread_seconds: int, folder: str, sensitive=False, unknown_ratio: float = 0.0,
              malicious=False, first_index: int = 0):
        for i in range(count):
            offset = spread_seconds * i / max(count - 1, 1)
            eid = self._id("fa")
            label: bool | None = sensitive
            if self.rng.random() < unknown_ratio:
                label = None  # Real file servers routinely lack a classification label.
            self.events.append({"id": eid, "type": "file_access", "at": iso(start + timedelta(seconds=offset)),
                                "actor": actor, "session": session, "asset_id": asset,
                                "file_id": f"{folder}/doc-{first_index + i:05}", "sensitive": label,
                                "bytes_read": self.rng.choice([None, 4096, 20480, 131072])})
            if malicious:
                self.malicious.add(eid)


def _asset(aid, kind, exposed, privileged, sensitive, patch, observed, vulnerability=None):
    return {"id": aid, "kind": kind, "internet_exposed": exposed, "privileged_path": privileged,
            "sensitive_path": sensitive, "patch_state": patch, "vulnerability": vulnerability,
            "observed_at": iso(observed)}


def scenario(name: str, *, seed: int = 1, days: int = 3, users: int = 24, attack: bool = False,
             unpatched_gateway: bool = False, start: datetime | None = None) -> dict:
    """Build one labeled scenario. Same seed and arguments produce the same bytes."""
    if not 1 <= days <= 90 or not 1 <= users <= 5000:
        raise ValidationError("daysは1〜90、usersは1〜5000で指定してください。")
    rng = random.Random(f"{name}/{seed}/{days}/{users}/{attack}/{unpatched_gateway}")
    day_zero = (start or datetime(2026, 9, 1, tzinfo=JST)).astimezone(JST).replace(hour=0, minute=0, second=0, microsecond=0)
    builder = Builder(rng)
    observed = day_zero + timedelta(days=days, hours=9)

    gateway_patch = "pending" if (attack or unpatched_gateway) else "applied"
    gateway_vuln = {"reference": "DEMO-ADV-001", "cvss": 6.5, "known_exploited": False} if gateway_patch == "pending" else None
    assets = [
        _asset("edge-vpn-01", "vpn", True, True, True, gateway_patch, observed, gateway_vuln),
        _asset("fileserver-01", "server", False, False, True, "applied", observed),
        _asset("fileserver-02", "server", False, False, True, "applied", observed),
        _asset("backup-01", "server", False, True, True, "applied", observed),
    ]

    analysts = max(1, users // 8)
    migrators = max(1, users // 12)
    for day in range(days):
        morning = day_zero + timedelta(days=day, hours=9)
        weekend = (morning.weekday() >= 5)
        for index in range(users):
            actor = f"staff-{index:03}@example.invalid"
            if weekend and rng.random() > 0.12:
                continue
            session = f"s-{day}-{index}-{rng.randrange(10**6):06}"
            login_at = morning + timedelta(minutes=rng.randrange(0, 90))
            builder.login(login_at, actor, session, "edge-vpn-01", privileged=False, device_trusted=True, approved=True)
            if rng.random() < 0.08:  # A mistyped password before a successful sign-in is normal.
                builder.login(login_at - timedelta(seconds=rng.randrange(5, 120)), actor, session, "edge-vpn-01",
                              success=False, privileged=False, device_trusted=True, approved=None)
            server = rng.choice(["fileserver-01", "fileserver-02"])
            routine = rng.randrange(8, 60)
            builder.reads(login_at + timedelta(minutes=rng.randrange(1, 30)), actor, session, server, routine,
                          spread_seconds=rng.randrange(1800, 7200), folder=f"dept/{index % 7}",
                          sensitive=False, unknown_ratio=0.25, first_index=day * 1000)
            if index < analysts and rng.random() < 0.6:
                # Analysts legitimately open a lot of files quickly: the main false-positive source.
                burst = rng.randrange(45, 165)
                builder.reads(login_at + timedelta(hours=rng.randrange(1, 6)), actor, session, server, burst,
                              spread_seconds=rng.randrange(120, 900), folder=f"analysis/{index}",
                              sensitive=rng.random() < 0.5, unknown_ratio=0.3, first_index=day * 5000)
            if index < migrators and day == days // 2:
                # Migration day: bulk copying with an approved change ticket.
                builder.reads(morning + timedelta(hours=4), actor, session, server, rng.randrange(250, 600),
                              spread_seconds=rng.randrange(600, 1800), folder=f"migration/{index}",
                              sensitive=True, unknown_ratio=0.1, first_index=day * 9000)
        # Nightly backup service account: privileged, managed, approved, and very noisy.
        night = day_zero + timedelta(days=day, hours=2)
        backup_session = f"backup-{day}"
        builder.login(night, "svc-backup@example.invalid", backup_session, "edge-vpn-01",
                      privileged=True, device_trusted=True, approved=True)
        builder.reads(night + timedelta(minutes=2), "svc-backup@example.invalid", backup_session, "backup-01",
                      rng.randrange(700, 1400), spread_seconds=rng.randrange(600, 1500), folder="backup",
                      sensitive=True, unknown_ratio=0.05, first_index=day * 20000)
        # Vendor maintenance on a personal (unmanaged) device, but with an approved window.
        if rng.random() < 0.5:
            vendor_session = f"vendor-{day}"
            builder.login(day_zero + timedelta(days=day, hours=20), "vendor-maintenance@example.invalid",
                          vendor_session, "edge-vpn-01", privileged=True, device_trusted=False, approved=True)
            builder.reads(day_zero + timedelta(days=day, hours=20, minutes=10), "vendor-maintenance@example.invalid",
                          vendor_session, "fileserver-01", rng.randrange(3, 25), spread_seconds=900,
                          folder="maintenance", sensitive=False, unknown_ratio=0.5, first_index=day * 30000)
        # Search-indexing service: managed, approved, and reads almost everything every night.
        index_session = f"index-{day}"
        builder.login(day_zero + timedelta(days=day, hours=1), "svc-indexer@example.invalid", index_session,
                      "edge-vpn-01", privileged=False, device_trusted=True, approved=True)
        for server in ("fileserver-01", "fileserver-02"):
            builder.reads(day_zero + timedelta(days=day, hours=1, minutes=5), "svc-indexer@example.invalid",
                          index_session, server, rng.randrange(400, 900), spread_seconds=rng.randrange(300, 1200),
                          folder="index", sensitive=rng.random() < 0.3, unknown_ratio=0.15, first_index=day * 40000)
        # Endpoint antivirus full scan, scheduled weekly, sweeping a file share.
        if day % 7 == 3:
            av_session = f"av-{day}"
            builder.login(day_zero + timedelta(days=day, hours=3), "svc-antivirus@example.invalid", av_session,
                          "edge-vpn-01", privileged=False, device_trusted=True, approved=True)
            builder.reads(day_zero + timedelta(days=day, hours=3, minutes=10), "svc-antivirus@example.invalid",
                          av_session, "fileserver-02", rng.randrange(600, 1200), spread_seconds=rng.randrange(600, 1800),
                          folder="avscan", sensitive=rng.random() < 0.4, unknown_ratio=0.2, first_index=day * 50000)
        # Legal hold / eDiscovery: a compliance analyst pulls a large, mostly-sensitive set with approval.
        if rng.random() < 0.2:
            legal_session = f"legal-{day}"
            builder.login(day_zero + timedelta(days=day, hours=11), "legal-review@example.invalid", legal_session,
                          "edge-vpn-01", privileged=False, device_trusted=True, approved=True)
            builder.reads(day_zero + timedelta(days=day, hours=11, minutes=20), "legal-review@example.invalid",
                          legal_session, "fileserver-01", rng.randrange(150, 500), spread_seconds=rng.randrange(300, 1500),
                          folder="ediscovery", sensitive=True, unknown_ratio=0.05, first_index=day * 60000)
        # Nightly batch ETL job reading a reporting share.
        etl_session = f"etl-{day}"
        builder.login(day_zero + timedelta(days=day, hours=4), "svc-etl@example.invalid", etl_session,
                      "edge-vpn-01", privileged=False, device_trusted=True, approved=True)
        builder.reads(day_zero + timedelta(days=day, hours=4, minutes=5), "svc-etl@example.invalid", etl_session,
                      "fileserver-02", rng.randrange(200, 700), spread_seconds=rng.randrange(300, 1000),
                      folder="etl", sensitive=rng.random() < 0.2, unknown_ratio=0.1, first_index=day * 70000)

    expect: list[str] = []
    malicious_assets: list[str] = []
    if attack:
        # The labeled incident: an unapproved privileged session from an unmanaged device
        # through an exposed, unpatched gateway, followed by bulk reads of labeled files.
        at = day_zero + timedelta(days=days - 1, hours=23, minutes=17)
        session = "incident-session"
        builder.login(at, "vendor-maintenance@example.invalid", session, "edge-vpn-01",
                      privileged=True, device_trusted=False, approved=False, malicious=True)
        builder.reads(at + timedelta(minutes=3), "vendor-maintenance@example.invalid", session, "fileserver-01",
                      130, spread_seconds=270, folder="personnel", sensitive=True, malicious=True, first_index=700000)
        expect = list(BEHAVIORAL_RULES)
        malicious_assets = ["edge-vpn-01"]

    events = sorted(builder.events, key=lambda e: (e["at"], e["id"]))
    snapshot = {"schema_version": 1, "as_of": iso(observed), "assets": assets, "events": events}
    return {"scenario_version": SCENARIO_VERSION, "name": name, "seed": seed, "days": days, "users": users,
            "attack": attack, "snapshot": snapshot,
            "labels": {"malicious_event_ids": sorted(builder.malicious), "malicious_asset_ids": malicious_assets,
                       "expect_rules": expect},
            "notes": ["合成データです。実組織のログではありません。",
                      "正常側にはバックアップ、分析作業、移行作業、承認済みの保守接続を含みます。",
                      "この結果は閾値の当たりを付けるためのもので、実環境の誤検知率ではありません。"]}


def load_scenario(raw) -> dict:
    """Validate a scenario file before it is used to judge a threshold."""
    object_keys(raw, {"scenario_version", "name", "snapshot", "labels"},
                {"seed", "days", "users", "attack", "notes"})
    if raw["scenario_version"] != SCENARIO_VERSION:
        raise ValidationError(f"scenario_versionは{SCENARIO_VERSION}が必要です。")
    if not isinstance(raw["name"], str) or not 1 <= len(raw["name"]) <= 120:
        raise ValidationError("シナリオ名は120文字以内にしてください。")
    labels = object_keys(raw["labels"], {"malicious_event_ids", "malicious_asset_ids", "expect_rules"})
    for key in labels:
        if not isinstance(labels[key], list) or any(not isinstance(v, str) for v in labels[key]):
            raise ValidationError("labelsは文字列リストが必要です。")
    return raw
