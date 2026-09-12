"""Deterministic, explainable detection. A finding is not proof of compromise."""
from __future__ import annotations
from collections import Counter, defaultdict, deque
from datetime import timedelta
import hashlib
from .schema import parse_time, canonical

RULE_VERSION = "2026-09-12.1"
WINDOW_SECONDS = 300
DISTINCT_FILE_THRESHOLD = 100
LOGIN_LOOKBACK_SECONDS = 1800


def finding(rule: str, priority: str, title: str, reasons: list[str], evidence: list[str], **extra) -> dict:
    fid = "F-" + hashlib.sha256(canonical([rule, evidence]).encode()).hexdigest()[:14]
    return {"id": fid, "rule": rule, "rule_version": RULE_VERSION, "priority": priority, "title": title,
            "reasons": reasons, "evidence_ids": evidence, "verdict": "requires_review", **extra}


def analyze(snapshot: dict) -> list[dict]:
    assets = {a["id"]: a for a in snapshot["assets"]}
    events = snapshot["events"]
    result = []
    exposed_pending = set()
    for aid, a in assets.items():
        v = a["vulnerability"]
        if a["patch_state"] == "pending" and v:
            exposed = a["internet_exposed"] is True
            known = v["known_exploited"] is True
            path = a["privileged_path"] is True and a["sensitive_path"] is True
            critical = exposed and (known or path)
            p = "P1" if critical else "P2" if exposed or (v["cvss"] or 0) >= 7 else "P3"
            reasons = ["修正プログラムが未適用と登録されています。"]
            if exposed:
                reasons.append("インターネットに公開されていると登録されています。")
                exposed_pending.add(aid)
            if known:
                reasons.append("既知の悪用ありと入力されています（本版は外部フィードで自動検証しません）。")
            if path:
                reasons.append("特権と機密情報への到達経路が台帳に登録されています。")
            if critical and v["cvss"] is not None and v["cvss"] < 7:
                reasons.append("CVSSが7未満でも、公開範囲と到達経路の組み合わせを優先します。")
            result.append(finding("AS-001", p, "公開機器の修正を優先" if exposed else "未適用パッチの確認", reasons, ["asset:" + aid], asset_id=aid, kind="exposure", cvss=v["cvss"], reference=v["reference"]))
        unknown = any(a[k] is None for k in ("internet_exposed", "privileged_path", "sensitive_path")) or a["patch_state"] == "unknown"
        stale = parse_time(snapshot["as_of"]) - parse_time(a["observed_at"]) > timedelta(hours=24)
        if unknown or stale:
            result.append(finding("AS-005", "P2", "資産情報の不足・古さを確認", ["未確認の項目や24時間を超える古い資産情報を、安全と扱いません。"], ["asset:" + aid], kind="coverage", asset_id=aid))

    logins = defaultdict(list)
    for e in events:
        if e["type"] != "login" or not e["success"]:
            continue
        logins[(e["actor"], e["session"])].append(e)
        if e["privileged"] is True and (e["device_trusted"] is False or e["approved"] is False):
            result.append(finding("AS-002", "P2", "特権ログインの条件を確認", ["特権ログインに、未承認作業または非管理端末の条件が重なっています。", "不正利用と断定せず、作業申請と端末状態を確認してください。"], [e["id"]], kind="identity", actor=e["actor"], gateway_id=e["gateway_id"], at=e["at"]))

    groups = defaultdict(list)
    for e in events:
        if e["type"] == "file_access":
            groups[(e["actor"], e["session"], e["asset_id"])].append(e)
    for (actor, session, target), reads in groups.items():
        reads.sort(key=lambda e: (e["at"], e["id"]))
        window, files, best, peak = deque(), Counter(), [], 0
        for e in reads:
            t = parse_time(e["at"])
            while window and (t - parse_time(window[0]["at"])).total_seconds() > WINDOW_SECONDS:
                old = window.popleft()
                files[old["file_id"]] -= 1
                if not files[old["file_id"]]:
                    del files[old["file_id"]]
            window.append(e)
            files[e["file_id"]] += 1
            if len(files) > peak:
                peak, best = len(files), list(window)
        if peak < DISTINCT_FILE_THRESHOLD:
            continue
        sensitive = len({e["file_id"] for e in best if e["sensitive"] is True})
        evidence = [e["id"] for e in best]
        result.append(finding("AS-003", "P2", "短時間の大量ファイル参照", [f"300秒以内に{peak}個の異なるファイルへの参照を記録しました。", f"このうち機密ラベル付きは{sensitive}個です。", "参照ログだけでは外部への送信・漏えいを証明できません。"], evidence, kind="bulk", actor=actor, asset_id=target, distinct_files=peak, sensitive_files=sensitive, at=best[-1]["at"]))
        # Match the latest successful login before the window; never mix sessions/users.
        eligible = [e for e in logins[(actor, session)] if 0 <= (parse_time(best[0]["at"]) - parse_time(e["at"])).total_seconds() <= LOGIN_LOOKBACK_SECONDS]
        if not eligible:
            continue
        login = max(eligible, key=lambda e: e["at"])
        if not (login["privileged"] is True and (login["device_trusted"] is False or login["approved"] is False)):
            continue
        if login["gateway_id"] not in exposed_pending or sensitive < 1:
            continue
        result.append(finding("AS-004", "P1", "保守アカウントの侵害を疑う相関候補", ["公開・未修正の接続機器、条件に問題がある特権ログイン、機密ファイルの大量参照が関連しています。", "同一ユーザー・同一セッションと30分以内の時系列で関連付けました。", "接続機器の脆弱性が実際に悪用されたこと、外部漏えいが起きたことは未確認です。"], ["asset:" + login["gateway_id"], login["id"], *evidence], kind="correlation", actor=actor, gateway_id=login["gateway_id"], asset_id=target, distinct_files=peak, sensitive_files=sensitive, at=best[-1]["at"], hypothesis=True))
    return sorted(result, key=lambda f: (f["priority"], 0 if f["kind"] == "correlation" else 1, f["id"]))


def coverage(snapshot: dict) -> dict:
    events = snapshot["events"]
    missing = [name for name, present in (("資産台帳", bool(snapshot["assets"])), ("認証ログ", any(e["type"] == "login" for e in events)), ("ファイル参照ログ", any(e["type"] == "file_access" for e in events))) if not present]
    return {"live_connectors": 0, "expected_connectors": 3, "snapshot_only": True, "missing_sources": missing,
            "unknown_asset_fields": sum(a[k] is None for a in snapshot["assets"] for k in ("internet_exposed", "privileged_path", "sensitive_path")),
            "unknown_login_fields": sum(e[k] is None for e in events if e["type"] == "login" for k in ("privileged", "device_trusted", "approved")),
            "unknown_classifications": sum(e["type"] == "file_access" and e["sensitive"] is None for e in events)}
