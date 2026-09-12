"""Strict, metadata-only snapshot boundary. No file contents are accepted."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import math
import re
from typing import Any

MAX_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 5000
MAX_ASSETS = 200
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")


class ValidationError(ValueError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValidationError("日時はタイムゾーン付きISO 8601文字列が必要です。")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("日時の形式が不正です。") from exc
    if result.tzinfo is None:
        raise ValidationError("日時のタイムゾーンを省略できません。")
    return result.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def object_keys(value: Any, required: set[str], optional: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        raise ValidationError("JSONオブジェクトが必要です。")
    keys = set(value)
    if not required <= keys or keys - required - (optional or set()):
        raise ValidationError("必須フィールドの欠落、または未定義フィールドがあります。")
    return value


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValidationError("識別子は80文字以内の英数字と _ . : - に限定してください。")
    return value


def nullable_bool(value: Any) -> bool | None:
    if value is not None and type(value) is not bool:
        raise ValidationError("真偽値またはnullが必要です。")
    return value


def pseudonym(value: Any, key: bytes, namespace: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 32 for c in value):
        raise ValidationError("ユーザー・セッション・ファイル識別子の形式が不正です。")
    # Keyed, domain-separated hashes prevent dictionary matching without the key.
    # These are pseudonymous identifiers, NOT anonymous/non-personal information.
    digest = hmac.new(key, (namespace + "\0" + value).encode(), hashlib.sha256).hexdigest()[:24]
    return f"{namespace}-{digest}"


def number(value: Any, low: float, high: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValidationError("数値の範囲が不正です。")
    return float(value)


def read_json(raw: bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise ValidationError("JSONは2 MiB以下にしてください。")
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValidationError("JSONキーの重複は許可しません。")
            out[k] = v
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("非有限数は許可しません。")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError("JSONを読み込めません。重複キー・形式・容量を確認してください。") from exc


def normalize(raw: Any, key: bytes, *, source_mode: str, now: datetime | None = None) -> dict:
    """The server sets source_mode; callers cannot claim imported events are verified."""
    now = now or utcnow()
    object_keys(raw, {"schema_version", "as_of", "assets", "events"})
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValidationError("schema_versionは1が必要です。")
    as_of = parse_time(raw["as_of"])
    if as_of > now + timedelta(minutes=5):
        raise ValidationError("スナップショット時刻が未来すぎます。")
    if source_mode not in {"demo", "imported"}:
        raise ValidationError("入力モードが不正です。")
    if not isinstance(raw["assets"], list) or not 1 <= len(raw["assets"]) <= MAX_ASSETS:
        raise ValidationError("資産数は1〜200件にしてください。")
    if not isinstance(raw["events"], list) or len(raw["events"]) > MAX_EVENTS:
        raise ValidationError("イベント数は5,000件以下にしてください。")

    assets, seen_assets = [], set()
    for item in raw["assets"]:
        object_keys(item, {"id", "kind", "internet_exposed", "privileged_path", "sensitive_path", "patch_state", "observed_at", "vulnerability"})
        aid = identifier(item["id"])
        if aid in seen_assets:
            raise ValidationError("資産IDが重複しています。")
        seen_assets.add(aid)
        if not isinstance(item["kind"], str) or item["kind"] not in {"vpn", "server", "saas", "endpoint"} or not isinstance(item["patch_state"], str) or item["patch_state"] not in {"pending", "applied", "unknown", "not_applicable"}:
            raise ValidationError("資産種別またはパッチ状態が不正です。")
        observed = parse_time(item["observed_at"])
        if observed > as_of + timedelta(minutes=5):
            raise ValidationError("資産の観測時刻がスナップショットより未来です。")
        vuln = item["vulnerability"]
        if vuln is not None:
            object_keys(vuln, {"reference", "cvss", "known_exploited"})
            vuln = {"reference": identifier(vuln["reference"]), "cvss": None if vuln["cvss"] is None else number(vuln["cvss"], 0, 10), "known_exploited": nullable_bool(vuln["known_exploited"])}
        if item["patch_state"] == "pending" and vuln is None:
            raise ValidationError("パッチ待ちの資産には脆弱性参照が必要です。")
        assets.append({"id": aid, "kind": item["kind"], "patch_state": item["patch_state"], "observed_at": iso(observed), "vulnerability": vuln,
                       **{k: nullable_bool(item[k]) for k in ("internet_exposed", "privileged_path", "sensitive_path")}})

    events, seen = [], {}
    common = {"id", "type", "at", "actor", "session"}
    for item in raw["events"]:
        if not isinstance(item, dict):
            raise ValidationError("イベントはJSONオブジェクトが必要です。")
        kind = item.get("type")
        if kind == "login":
            object_keys(item, common | {"gateway_id", "success", "privileged", "device_trusted", "approved"})
            identifier(item["gateway_id"])
            if item["gateway_id"] not in seen_assets:
                raise ValidationError("ログインの接続元機器が資産台帳にありません。")
            if type(item["success"]) is not bool:
                raise ValidationError("successには真偽値が必要です。")
            fields = {"gateway_id": item["gateway_id"], "success": item["success"], **{k: nullable_bool(item[k]) for k in ("privileged", "device_trusted", "approved")}}
        elif kind == "file_access":
            object_keys(item, common | {"asset_id", "file_id", "sensitive", "bytes_read"})
            identifier(item["asset_id"])
            if item["asset_id"] not in seen_assets:
                raise ValidationError("ファイルの保存先が資産台帳にありません。")
            if type(item["bytes_read"]) is not int:
                raise ValidationError("bytes_readには整数が必要です。")
            number(item["bytes_read"], 0, 10**12)
            fields = {"asset_id": item["asset_id"], "file_id": pseudonym(item["file_id"], key, "file"), "sensitive": nullable_bool(item["sensitive"]), "bytes_read": item["bytes_read"]}
        else:
            raise ValidationError("未対応のイベント種別です。")
        at = parse_time(item["at"])
        if at > as_of + timedelta(minutes=5):
            raise ValidationError("イベント時刻がスナップショットより未来です。")
        event = {"id": identifier(item["id"]), "type": kind, "at": iso(at), "actor": pseudonym(item["actor"], key, "actor"), "session": pseudonym(item["session"], key, "session"), **fields}
        if event["id"] in seen:
            if seen[event["id"]] != event:
                raise ValidationError("同じイベントIDに異なる内容が指定されています。")
            continue
        seen[event["id"]] = event
        events.append(event)
    return {"schema_version": 1, "as_of": iso(as_of), "source_mode": source_mode, "assets": sorted(assets, key=lambda a: a["id"]), "events": sorted(events, key=lambda e: (e["at"], e["id"]))}
