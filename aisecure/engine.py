"""Deterministic, explainable detection. A finding is not proof of compromise."""
from __future__ import annotations
from collections import Counter, defaultdict, deque
from datetime import timedelta
import hashlib
from .schema import parse_time, canonical
from .rules import RuleConfig, DEFAULT as DEFAULT_RULES

RULE_VERSION = "2026-09-12.2"
LIVE_CONNECTORS = frozenset({"okta-system-log-api"})


def finding(rule: str, priority: str, title: str, reasons: list[str], evidence: list[str], config: RuleConfig, **extra) -> dict:
    fid = "F-" + hashlib.sha256(canonical([rule, evidence]).encode()).hexdigest()[:14]
    return {"id": fid, "rule": rule, "rule_version": RULE_VERSION, "rule_config_digest": config.digest,
            "priority": priority, "title": title,
            "reasons": reasons, "evidence_ids": evidence, "verdict": "requires_review", **extra}


def suspicious_login(event: dict, config: RuleConfig) -> bool:
    """A privileged session whose conditions do not match an approved, managed one."""
    if event["privileged"] is not True:
        return False
    untrusted, unapproved = event["device_trusted"] is False, event["approved"] is False
    return (untrusted and unapproved) if config.identity_conditions == "both" else (untrusted or unapproved)


def analyze(snapshot: dict, config: RuleConfig | None = None) -> list[dict]:
    config = config or DEFAULT_RULES
    assets = {a["id"]: a for a in snapshot["assets"]}
    events = snapshot["events"]
    result = []
    exposed_pending = set()
    for aid, a in assets.items():
        v = a["vulnerability"] or {"reference": None, "cvss": None, "known_exploited": None}
        if a["patch_state"] == "pending":
            exposed = a["internet_exposed"] is True
            known = v["known_exploited"] is True
            path = a["privileged_path"] is True and a["sensitive_path"] is True
            critical = exposed and (known or path)
            p = "P1" if critical else "P2" if exposed or (v["cvss"] or 0) >= config.cvss_priority_threshold else "P3"
            reasons = ["修正プログラムが未適用と登録されています。"]
            reasons_en = ["The patch is registered as not applied."]
            if a["vulnerability"] is None:
                reasons.append("脆弱性参照が登録されていません。何を修正すべきかを台帳で確認してください。")
                reasons_en.append("No vulnerability reference is registered. Check the ledger for what needs patching.")
            if exposed:
                reasons.append("インターネットに公開されていると登録されています。")
                reasons_en.append("Registered as exposed to the internet.")
                exposed_pending.add(aid)
            if known:
                reasons.append("既知の悪用ありと入力されています（本版は外部フィードで自動検証しません）。")
                reasons_en.append("Marked as known-exploited in the input (this version does not auto-verify against external feeds).")
            if path:
                reasons.append("特権と機密情報への到達経路が台帳に登録されています。")
                reasons_en.append("A path to privilege and sensitive data is registered in the ledger.")
            if critical and v["cvss"] is not None and v["cvss"] < config.cvss_priority_threshold:
                reasons.append(f"CVSSが{config.cvss_priority_threshold:g}未満でも、公開範囲と到達経路の組み合わせを優先します。")
                reasons_en.append(f"Even below CVSS {config.cvss_priority_threshold:g}, the exposure and reachability combination is prioritised.")
            result.append(finding("AS-001", p, "公開機器の修正を優先" if exposed else "未適用パッチの確認", reasons, ["asset:" + aid], config, asset_id=aid, kind="exposure", cvss=v["cvss"], reference=v["reference"], title_en="Patch the exposed device first" if exposed else "Review the unapplied patch", reasons_en=reasons_en))
        unknown = any(a[k] is None for k in ("internet_exposed", "privileged_path", "sensitive_path")) or a["patch_state"] == "unknown"
        stale = parse_time(snapshot["as_of"]) - parse_time(a["observed_at"]) > timedelta(hours=config.stale_asset_hours)
        if unknown or stale:
            result.append(finding("AS-005", "P2", "資産情報の不足・古さを確認", [f"未確認の項目や{config.stale_asset_hours}時間を超える古い資産情報を、安全と扱いません。"], ["asset:" + aid], config, kind="coverage", asset_id=aid, title_en="Check missing or stale asset data", reasons_en=[f"Unconfirmed fields, or asset data older than {config.stale_asset_hours}h, are not treated as safe."]))

    logins = defaultdict(list)
    for e in events:
        if e["type"] != "login" or not e["success"]:
            continue
        logins[(e["actor"], e["session"])].append(e)
        if suspicious_login(e, config):
            result.append(finding("AS-002", "P2", "特権ログインの条件を確認", [("特権ログインに、未承認作業と非管理端末の条件が重なっています。" if config.identity_conditions == "both" else "特権ログインに、未承認作業または非管理端末の条件が重なっています。"), "不正利用と断定せず、作業申請と端末状態を確認してください。"], [e["id"]], config, kind="identity", actor=e["actor"], gateway_id=e["gateway_id"], at=e["at"], title_en="Check the privileged-login conditions", reasons_en=[("A privileged login combines both an unapproved change and an unmanaged device." if config.identity_conditions == "both" else "A privileged login combines an unapproved change or an unmanaged device."), "Not a conclusion of misuse; verify the change request and device state."]))

    groups = defaultdict(list)
    for e in events:
        if e["type"] == "file_access":
            groups[(e["actor"], e["session"], e["asset_id"])].append(e)
    for (actor, session, target), reads in groups.items():
        reads.sort(key=lambda e: (e["at"], e["id"]))
        window, files, best, peak = deque(), Counter(), [], 0
        for e in reads:
            t = parse_time(e["at"])
            while window and (t - parse_time(window[0]["at"])).total_seconds() > config.window_seconds:
                old = window.popleft()
                files[old["file_id"]] -= 1
                if not files[old["file_id"]]:
                    del files[old["file_id"]]
            window.append(e)
            files[e["file_id"]] += 1
            if len(files) > peak:
                peak, best = len(files), list(window)
        if peak < config.distinct_file_threshold:
            continue
        sensitive = len({e["file_id"] for e in best if e["sensitive"] is True})
        evidence = [e["id"] for e in best]
        result.append(finding("AS-003", "P2", "短時間の大量ファイル参照", [f"{config.window_seconds}秒以内に{peak}個の異なるファイルへの参照を記録しました。", f"このうち機密ラベル付きは{sensitive}個です。", "参照ログだけでは外部への送信・漏えいを証明できません。"], evidence, config, kind="bulk", actor=actor, asset_id=target, distinct_files=peak, sensitive_files=sensitive, at=best[-1]["at"], title_en="Bulk file access in a short window", reasons_en=[f"Recorded {peak} distinct file reads within {config.window_seconds} seconds.", f"Of these, {sensitive} carry a sensitive label.", "Read logs alone cannot prove exfiltration or a leak."]))
        # Match the latest successful login before the window; never mix sessions/users.
        eligible = [e for e in logins[(actor, session)] if 0 <= (parse_time(best[0]["at"]) - parse_time(e["at"])).total_seconds() <= config.login_lookback_seconds]
        if not eligible:
            continue
        login = max(eligible, key=lambda e: e["at"])
        if not suspicious_login(login, config):
            continue
        if login["gateway_id"] not in exposed_pending or sensitive < config.sensitive_file_minimum:
            continue
        result.append(finding("AS-004", "P1", "保守アカウントの侵害を疑う相関候補", ["公開・未修正の接続機器、条件に問題がある特権ログイン、機密ファイルの大量参照が関連しています。", f"同一ユーザー・同一セッションと{config.login_lookback_seconds // 60}分以内の時系列で関連付けました。", "接続機器の脆弱性が実際に悪用されたこと、外部漏えいが起きたことは未確認です。"], ["asset:" + login["gateway_id"], login["id"], *evidence], config, kind="correlation", actor=actor, gateway_id=login["gateway_id"], asset_id=target, distinct_files=peak, sensitive_files=sensitive, at=best[-1]["at"], hypothesis=True, title_en="Correlated case: suspected maintenance-account compromise", reasons_en=["An exposed, unpatched gateway, a privileged login that fails its conditions, and bulk access to sensitive files are related.", f"Linked by the same user and session within {config.login_lookback_seconds // 60} minutes.", "Whether the gateway vulnerability was actually exploited, and whether data left the network, is unconfirmed."]))
    return sorted(result, key=lambda f: (f["priority"], 0 if f["kind"] == "correlation" else 1, f["id"]))


def coverage(snapshot: dict) -> dict:
    events = snapshot["events"]
    missing = [name for name, present in (("資産台帳", bool(snapshot["assets"])), ("認証ログ", any(e["type"] == "login" for e in events)), ("ファイル参照ログ", any(e["type"] == "file_access" for e in events))) if not present]
    # File imports are verified as reads, but they are not live connectors.
    # Only provider adapters that explicitly identify themselves as live count.
    live = sorted({source.get("connector") for source in snapshot.get("provenance", [])
                   if source.get("verified") is True and source.get("connector") in LIVE_CONNECTORS})
    return {"live_connectors": len(live), "live_connector_names": live, "expected_connectors": 3,
            "snapshot_only": not live, "missing_sources": missing,
            "unknown_asset_fields": sum(a[k] is None for a in snapshot["assets"] for k in ("internet_exposed", "privileged_path", "sensitive_path")),
            "unknown_login_fields": sum(e[k] is None for e in events if e["type"] == "login" for k in ("privileged", "device_trusted", "approved")),
            "unknown_classifications": sum(e["type"] == "file_access" and e["sensitive"] is None for e in events),
            "unknown_read_sizes": sum(e["type"] == "file_access" and e["bytes_read"] is None for e in events),
            "provenance": snapshot.get("provenance", [])}
