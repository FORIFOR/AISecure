"""Declarative, read-only mapping from a real log file to snapshot metadata.

A profile can only name targets on the allowlist below. Any other column in the
source is dropped and never reaches the snapshot, the database, or an LLM, so a
profile cannot be written that imports file contents, credentials, or free text.

Unknown and unparseable values become null. They are never mapped to a value
that would make an asset or a login look safe.
"""
from __future__ import annotations
import re
from ..schema import ValidationError

PROFILE_VERSION = 1
FORMATS = {"csv", "jsonl"}
TIME_FORMATS = {"iso8601", "epoch_seconds", "epoch_millis"}
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:/-]{0,79}$")

# target -> (kind, required)
TARGETS: dict[str, dict[str, tuple[str, bool]]] = {
    "login": {
        "id": ("id", False),  # derived from content when the source has no event id
        "at": ("time", True),
        "actor": ("opaque", True),
        "session": ("opaque", True),
        "gateway_id": ("id", True),
        "success": ("bool", True),
        "privileged": ("bool", False),
        "device_trusted": ("bool", False),
        "approved": ("bool", False),
    },
    "file_access": {
        "id": ("id", False),
        "at": ("time", True),
        "actor": ("opaque", True),
        "session": ("opaque", True),
        "asset_id": ("id", True),
        "file_id": ("opaque", True),
        "sensitive": ("bool", False),
        "bytes_read": ("int", False),
    },
    "asset": {
        "id": ("id", True),
        "kind": ("enum", True),
        "observed_at": ("time", True),
        "patch_state": ("enum", True),
        "internet_exposed": ("bool", False),
        "privileged_path": ("bool", False),
        "sensitive_path": ("bool", False),
        "vulnerability_reference": ("id", False),
        "vulnerability_cvss": ("number", False),
        "vulnerability_known_exploited": ("bool", False),
    },
}
ENUMS = {"kind": {"vpn", "server", "saas", "endpoint", "unknown"}, "patch_state": {"pending", "applied", "unknown", "not_applicable"}}
SPEC_KEYS = {"field", "const", "derive", "true", "false", "true_contains", "false_contains", "map", "default", "time", "timezone"}
MAX_LIST = 64


def _strings(value, label: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_LIST:
        raise ValidationError(f"{label}は1〜{MAX_LIST}件の文字列リストが必要です。")
    out = []
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 200:
            raise ValidationError(f"{label}の要素は200文字以内の文字列が必要です。")
        out.append(item)
    return out


def _spec(target: str, kind: str, raw) -> dict:
    if not isinstance(raw, dict) or set(raw) - SPEC_KEYS or not raw:
        raise ValidationError(f"{target}のマッピング定義に未対応の項目があります。")
    if ("field" in raw) + ("const" in raw) + ("derive" in raw) != 1:
        raise ValidationError(f"{target}にはfield、const、deriveのいずれか1つを指定してください。")
    spec: dict = {"target": target, "kind": kind}
    if "field" in raw:
        if not isinstance(raw["field"], str) or not 1 <= len(raw["field"]) <= 120:
            raise ValidationError(f"{target}のfield名が不正です。")
        spec["field"] = raw["field"]
    if "const" in raw:
        spec["const"] = raw["const"]
    if "derive" in raw:
        if target != "id" or raw["derive"] != "content":
            raise ValidationError("deriveはidに対する\"content\"のみ対応しています。")
        spec["derive"] = "content"
    for key in ("true", "false", "true_contains", "false_contains"):
        if key in raw:
            if kind != "bool":
                raise ValidationError(f"{target}は真偽値の項目ではありません。")
            spec[key] = _strings(raw[key], key)
    if "map" in raw:
        if not isinstance(raw["map"], dict) or not raw["map"] or len(raw["map"]) > MAX_LIST:
            raise ValidationError(f"{target}のmapが不正です。")
        for source_value, mapped in raw["map"].items():
            if not isinstance(source_value, str) or not isinstance(mapped, str):
                raise ValidationError(f"{target}のmapは文字列の対応表が必要です。")
            if kind == "enum" and mapped not in ENUMS[target]:
                raise ValidationError(f"{target}のmap先は{sorted(ENUMS[target])}のいずれかにしてください。")
        spec["map"] = dict(raw["map"])
    if "default" in raw:
        spec["default"] = raw["default"]
    if kind == "time":
        fmt = raw.get("time", "iso8601")
        if not isinstance(fmt, str) or not 1 <= len(fmt) <= 60:
            raise ValidationError(f"{target}のtime指定が不正です。")
        if fmt not in TIME_FORMATS and "%" not in fmt:
            raise ValidationError(f"{target}のtimeはiso8601、epoch_seconds、epoch_millis、またはstrptime書式を指定してください。")
        spec["time"] = fmt
        zone = raw.get("timezone")
        if zone is not None and (not isinstance(zone, str) or not 1 <= len(zone) <= 10):
            raise ValidationError(f"{target}のtimezone指定が不正です。")
        spec["timezone"] = zone
    elif "time" in raw or "timezone" in raw:
        raise ValidationError(f"{target}は日時の項目ではありません。")
    if kind == "enum" and "map" not in spec and "const" not in spec and "default" not in spec:
        raise ValidationError(f"{target}にはmap、const、defaultのいずれかが必要です。")
    return spec


def load(raw) -> dict:
    """Validate a mapping profile. Unknown keys are rejected, never ignored."""
    if not isinstance(raw, dict):
        raise ValidationError("プロファイルはJSONオブジェクトが必要です。")
    allowed = {"profile_version", "name", "description", "format", "record", "map", "delimiter", "encoding", "skip_rows"}
    if set(raw) - allowed or not {"profile_version", "name", "format", "record", "map"} <= set(raw):
        raise ValidationError("プロファイルの必須項目の欠落、または未定義項目があります。")
    if raw["profile_version"] != PROFILE_VERSION or type(raw["profile_version"]) is not int:
        raise ValidationError(f"profile_versionは{PROFILE_VERSION}が必要です。")
    if not isinstance(raw["name"], str) or not NAME.fullmatch(raw["name"]):
        raise ValidationError("プロファイル名は80文字以内の英数字・空白・_.:/- にしてください。")
    if raw["format"] not in FORMATS or raw["record"] not in TARGETS:
        raise ValidationError("formatはcsv/jsonl、recordはlogin/file_access/assetを指定してください。")
    description = raw.get("description", "")
    if not isinstance(description, str) or len(description) > 500:
        raise ValidationError("descriptionは500文字以内にしてください。")
    delimiter = raw.get("delimiter", ",")
    if raw["format"] == "csv" and (not isinstance(delimiter, str) or len(delimiter) != 1 or delimiter in "\r\n"):
        raise ValidationError("delimiterは1文字にしてください。")
    encoding = raw.get("encoding", "utf-8")
    if encoding not in {"utf-8", "utf-8-sig", "cp932", "shift_jis", "euc_jp", "latin-1"}:
        raise ValidationError("encodingは utf-8, utf-8-sig, cp932, shift_jis, euc_jp, latin-1 から選んでください。")
    skip_rows = raw.get("skip_rows", 0)
    if type(skip_rows) is not int or type(skip_rows) is bool or not 0 <= skip_rows <= 100:
        raise ValidationError("skip_rowsは0〜100の整数にしてください。")

    targets = TARGETS[raw["record"]]
    if not isinstance(raw["map"], dict) or set(raw["map"]) - set(targets):
        raise ValidationError(f"{raw['record']}で指定できる項目は {', '.join(sorted(targets))} です。")
    missing = [name for name, (_, required) in targets.items() if required and name not in raw["map"]]
    if missing:
        raise ValidationError(f"必須マッピングが不足しています: {', '.join(missing)}")
    mapping = {name: _spec(name, targets[name][0], spec) for name, spec in raw["map"].items()}
    if "id" not in mapping:
        mapping["id"] = {"target": "id", "kind": "id", "derive": "content"}
    return {"profile_version": PROFILE_VERSION, "name": raw["name"], "description": description, "format": raw["format"],
            "record": raw["record"], "delimiter": delimiter, "encoding": encoding, "skip_rows": skip_rows, "map": mapping}
