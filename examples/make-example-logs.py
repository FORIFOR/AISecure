#!/usr/bin/env python3
"""Render a synthetic scenario into the raw log shapes the built-in profiles expect.

Development helper. It exists so `aisecure import` can be exercised end to end
without anyone's real logs. The output is synthetic; see docs/SOURCES.md.

    python3 examples/make-example-logs.py
"""
from __future__ import annotations
import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aisecure.baseline import scenario  # noqa: E402
from aisecure.schema import parse_time  # noqa: E402

JST = timezone(timedelta(hours=9))
OUT = Path(__file__).resolve().parent / "logs"
KIND = {"vpn": "vpn", "server": "fileserver", "saas": "saas", "endpoint": "pc", "unknown": "unknown"}
PATCH = {"pending": "未適用", "applied": "適用済", "not_applicable": "対象外", "unknown": ""}


def local(value: str) -> str:
    return parse_time(value).astimezone(JST).strftime("%Y-%m-%dT%H:%M:%S")


def flag(value, yes="yes", no="no") -> str:
    return "" if value is None else (yes if value else no)


def main() -> None:
    data = scenario("example-import", seed=4, days=1, users=6, attack=True)
    snapshot = data["snapshot"]
    OUT.mkdir(exist_ok=True)

    with (OUT / "assets.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["asset_id", "type", "exposed", "admin_path", "sensitive_path", "patch", "observed_at", "advisory", "cvss", "kev"])
        for asset in snapshot["assets"]:
            vulnerability = asset["vulnerability"] or {}
            writer.writerow([asset["id"], KIND[asset["kind"]], flag(asset["internet_exposed"]),
                             flag(asset["privileged_path"], "あり", "なし"), flag(asset["sensitive_path"], "あり", "なし"),
                             PATCH[asset["patch_state"]], local(asset["observed_at"]),
                             vulnerability.get("reference", ""), vulnerability.get("cvss", ""),
                             flag(vulnerability.get("known_exploited"))])

    logins = [e for e in snapshot["events"] if e["type"] == "login"]
    with (OUT / "auth.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "event_id", "user", "session_id", "gateway", "result", "account_type", "device_state", "change_ticket"])
        for index, event in enumerate(logins):
            writer.writerow([local(event["at"]), event["id"], event["actor"], event["session"], event["gateway_id"],
                             "success" if event["success"] else "failure",
                             "" if event["privileged"] is None else ("maintenance" if event["privileged"] else "user"),
                             "" if event["device_trusted"] is None else ("managed" if event["device_trusted"] else "unmanaged"),
                             "" if event["approved"] is None else (f"CHG-{index:04}" if event["approved"] else "none")])

    label = {True: "confidential", False: "internal", None: ""}
    with (OUT / "file-access.jsonl").open("w", encoding="utf-8") as handle:
        for event in snapshot["events"]:
            if event["type"] != "file_access":
                continue
            row = {"ts": int(parse_time(event["at"]).timestamp() * 1000),
                   "user": {"id": event["actor"]}, "session": event["session"], "host": event["asset_id"],
                   "path": "/share/" + event["file_id"], "label": label[event["sensitive"]]}
            if event["bytes_read"] is not None:
                row["bytes"] = event["bytes_read"]
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    labels = {"malicious_event_ids": data["labels"]["malicious_event_ids"],
              "malicious_asset_ids": data["labels"]["malicious_asset_ids"],
              "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "note": "合成ログです。実組織のログではありません。インポート結果の確認にのみ使用してください。"}
    (OUT / "labels.json").write_text(json.dumps(labels, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"assets={len(snapshot['assets'])} logins={len(logins)} "
          f"file_access={len(snapshot['events']) - len(logins)} -> {OUT}")


if __name__ == "__main__":
    main()
