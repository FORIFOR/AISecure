"""Read-only import of real log files into a metadata snapshot.

Sources are opened read-only, hashed for provenance, and never written back.
Only the targets a profile maps are carried forward; every other column is
dropped at this boundary. Rows that cannot be parsed are skipped and counted —
they are never guessed at, and an unreadable field never becomes a safe value.

This is an offline importer. It does not connect to a SIEM, an IdP, or a file
server, and it does not verify that the logs it reads are authentic or complete.
"""
from __future__ import annotations
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterator

from ..schema import ValidationError, canonical, iso, parse_time, utcnow, ID
from . import profile as profiles

CONNECTOR_VERSION = 1
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_ROWS = 2_000_000
MAX_COLUMNS = 200
MAX_FIELD_BYTES = 8192
MAX_LINE_BYTES = 256 * 1024
# ":" is deliberately excluded from what a raw name may keep, so it can mark a
# generated identifier. A value containing ":" can therefore never pass through
# unchanged, which keeps generated identifiers disjoint from raw ones.
SLUG_KEEP = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
SLUG_MARK = ":"
ASSET_TARGETS = ("internet_exposed", "privileged_path", "sensitive_path")


class ImportError_(ValidationError):
    """Raised when a source cannot be read at all; row-level problems are counted, not raised."""


def slug(value: str) -> str:
    """Map a free-form device or share name onto the identifier rules.

    A name that already satisfies the rules is kept as it is. Anything else gets
    a hash of the original after a ":" marker. Because ":" never survives
    cleaning, a generated identifier can never be produced by a raw name, so an
    attacker cannot pick a device name that collides with the normalized form of
    somebody else's device.
    """
    cleaned = "".join(c if c in SLUG_KEEP else "-" for c in value).strip("-")
    if cleaned and ID.fullmatch(cleaned) and cleaned == value:
        return value
    digest = hashlib.sha256(value.encode()).hexdigest()[:16]
    head = (cleaned[:60].strip("-") or "asset")
    if not head[0].isalnum():
        head = "x" + head
    return f"{head}{SLUG_MARK}{digest}"


def _dotted(record: dict, field: str) -> Any:
    value: Any = record
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value) if isinstance(value, float) else str(value)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _boolean(spec: dict, raw: Any) -> bool | None:
    if isinstance(raw, bool):
        return raw
    text = _text(raw)
    if text is None:
        return None
    lowered = text.lower()
    if lowered in {v.lower() for v in spec.get("true", [])}:
        return True
    if lowered in {v.lower() for v in spec.get("false", [])}:
        return False
    if any(needle.lower() in lowered for needle in spec.get("true_contains", [])):
        return True
    if any(needle.lower() in lowered for needle in spec.get("false_contains", [])):
        return False
    if not any(key in spec for key in ("true", "false", "true_contains", "false_contains")):
        if lowered in {"true", "yes", "y", "1", "success", "ok"}:
            return True
        if lowered in {"false", "no", "n", "0", "failure", "failed", "denied"}:
            return False
    return None


def _timestamp(spec: dict, raw: Any) -> datetime | None:
    text = _text(raw)
    if text is None:
        return None
    fmt = spec.get("time", "iso8601")
    try:
        if fmt in {"epoch_seconds", "epoch_millis"}:
            seconds = float(text) / (1000 if fmt == "epoch_millis" else 1)
            if not -62135596800 <= seconds <= 253402300799:
                return None
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        moment = datetime.fromisoformat(text.replace("Z", "+00:00")) if fmt == "iso8601" else datetime.strptime(text, fmt)
    except (ValueError, OverflowError, OSError):
        return None
    if moment.tzinfo is None:
        zone = spec.get("timezone")
        if zone is None:
            return None  # Never guess a timezone: an hour of drift breaks correlation.
        try:
            offset = timezone.utc if zone.upper() in {"Z", "UTC"} else datetime.fromisoformat("2000-01-01T00:00:00" + zone).tzinfo
        except ValueError:
            return None
        moment = moment.replace(tzinfo=offset)
    return moment.astimezone(timezone.utc)


def _finite(text: str | None) -> float | None:
    """inf / nan / 1e400 are not measurements; they must not abort an import."""
    if text is None:
        return None
    try:
        value = float(text)
    except (ValueError, OverflowError):
        return None
    return value if math.isfinite(value) else None


def _value(spec: dict, record: dict, dotted: bool) -> Any:
    if "const" in spec:
        return spec["const"]
    if "derive" in spec:
        return None
    raw = _dotted(record, spec["field"]) if dotted else record.get(spec["field"])
    kind = spec["kind"]
    if kind == "bool":
        result = _boolean(spec, raw)
    elif kind == "time":
        result = _timestamp(spec, raw)
    elif kind in {"id", "opaque", "enum"}:
        text = _text(raw)
        if text is not None and "map" in spec:
            text = spec["map"].get(text)
        result = text
    elif kind == "int":
        result = _finite(_text(raw))
        result = None if result is None else int(result)
        if result is not None and not 0 <= result <= 10**12:
            result = None
    else:  # number
        result = _finite(_text(raw))
        if result is not None and not 0 <= result <= 10:
            result = None
    return spec.get("default") if result is None and "default" in spec else result


def _rows(path: Path, spec: dict, quality: dict) -> Iterator[dict]:
    limit = csv.field_size_limit()
    try:
        if spec["format"] == "csv":
            csv.field_size_limit(MAX_FIELD_BYTES)
            with path.open("r", encoding=spec["encoding"], errors="replace", newline="") as handle:
                for _ in range(spec["skip_rows"]):
                    handle.readline()
                reader = csv.DictReader(handle, delimiter=spec["delimiter"])
                if not reader.fieldnames or len(reader.fieldnames) > MAX_COLUMNS:
                    raise ImportError_("CSVのヘッダー行がないか、列数が上限を超えています。")
                for row in reader:
                    yield {k: v for k, v in row.items() if isinstance(k, str)}
        else:
            with path.open("r", encoding=spec["encoding"], errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index < spec["skip_rows"]:
                        continue
                    if len(line) > MAX_LINE_BYTES:
                        quality["skip_reasons"]["行が長すぎます"] += 1
                        yield {}
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except (ValueError, RecursionError):
                        # Deeply nested input raises RecursionError on some Python
                        # versions and ValueError on others. One line, one skip.
                        quality["skip_reasons"]["JSONとして読み取れません"] += 1
                        yield {}
                        continue
                    if not isinstance(record, dict):
                        quality["skip_reasons"]["JSONオブジェクトではありません"] += 1
                        yield {}
                        continue
                    yield record
    except (UnicodeError, csv.Error) as exc:
        raise ImportError_(f"ソースを読み取れません: {type(exc).__name__}") from exc
    finally:
        csv.field_size_limit(limit)


def _digest(path: Path) -> tuple[str, int]:
    sha, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            sha.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), size


def _check(path: Path, max_bytes: int) -> None:
    if path.is_symlink():
        raise ImportError_(f"シンボリックリンクは読み込みません: {path.name}")
    if not path.is_file():
        raise ImportError_(f"通常ファイルではありません: {path.name}")
    if path.stat().st_size > max_bytes:
        raise ImportError_(f"ソースは{max_bytes // (1024 * 1024)} MiB以下にしてください: {path.name}")


def read_source(path: Path, spec: dict, *, max_rows: int = MAX_ROWS, max_bytes: int = MAX_SOURCE_BYTES,
                identifiers: dict[str, str] | None = None) -> tuple[list[dict], dict]:
    """Read one file into partially-mapped records plus a quality report."""
    path = Path(path)
    _check(path, max_bytes)
    sha, size = _digest(path)
    quality = {"label": path.name, "sha256": sha, "bytes": size, "profile": spec["name"], "record": spec["record"],
               "rows_read": 0, "rows_imported": 0, "rows_skipped": 0,
               "skip_reasons": Counter(), "unknown_values": Counter(), "normalized_identifiers": 0}
    dotted = spec["format"] == "jsonl"
    targets = profiles.TARGETS[spec["record"]]
    out: list[dict] = []
    for row in _rows(path, spec, quality):
        quality["rows_read"] += 1
        if quality["rows_read"] > max_rows:
            raise ImportError_(f"行数が{max_rows:,}行の上限を超えました。期間を絞って読み込んでください。")
        if not row:
            quality["rows_skipped"] += 1
            continue
        record, skip = {}, None
        for name, field_spec in spec["map"].items():
            value = _value(field_spec, row, dotted)
            if value is None:
                if targets.get(name, ("", False))[1]:
                    skip = f"{name}を読み取れません"
                    break
                if name != "id":
                    quality["unknown_values"][name] += 1
                record[name] = None
                continue
            if field_spec["kind"] == "id":
                text = str(value)
                mapped = slug(text)
                if mapped != text:
                    quality["normalized_identifiers"] += 1
                if identifiers is not None:
                    original = identifiers.setdefault(mapped, text)
                    if original != text:
                        # Two different real names would become one asset. Merging
                        # them would hide one asset's exposure behind the other's.
                        raise ImportError_(f"識別子が衝突しました: {original!r} と {text!r} が同じIDになります。"
                                           "元の名称を確認してください。")
                value = mapped
            elif field_spec["kind"] == "time":
                value = iso(value)
            elif field_spec["kind"] == "opaque":
                # Match what normalize() accepts, so one bad row cannot make the
                # whole snapshot unusable later.
                text = str(value)
                if not 1 <= len(text) <= 256:
                    skip = f"{name}の長さが不正です"
                    break
                if any(ord(c) < 32 for c in text):
                    skip = f"{name}に制御文字が含まれます"
                    break
            elif field_spec["kind"] == "enum" and value not in profiles.ENUMS[name]:
                skip = f"{name}の値が未対応です"
                break
            record[name] = value
        if skip:
            quality["rows_skipped"] += 1
            quality["skip_reasons"][skip] += 1
            continue
        if record.get("id") is None:
            prefix = {"login": "lg", "file_access": "fa", "asset": "as"}[spec["record"]]
            record["id"] = f"{prefix}-" + hashlib.sha256(canonical({k: v for k, v in record.items() if k != "id"}).encode()).hexdigest()[:24]
        quality["rows_imported"] += 1
        # Targets the profile does not map stay present and explicitly unknown.
        out.append({name: record.get(name) for name in targets} | {"id": record["id"]})
    quality["skip_reasons"] = dict(quality["skip_reasons"])
    quality["unknown_values"] = dict(quality["unknown_values"])
    return out, quality


def _asset(record: dict) -> dict:
    reference = record.get("vulnerability_reference")
    vulnerability = None
    if reference is not None:
        vulnerability = {"reference": reference, "cvss": record.get("vulnerability_cvss"),
                         "known_exploited": record.get("vulnerability_known_exploited")}
    return {"id": record["id"], "kind": record["kind"], "patch_state": record["patch_state"],
            "observed_at": record["observed_at"], "vulnerability": vulnerability,
            **{k: record.get(k) for k in ASSET_TARGETS}}


def build_snapshot(sources: list[tuple[Path, dict]], *, as_of: datetime | None = None,
                   unknown_assets: str = "record", max_rows: int = MAX_ROWS,
                   max_bytes: int = MAX_SOURCE_BYTES) -> tuple[dict, dict]:
    """Combine an asset inventory and log sources into one snapshot plus a quality report."""
    if unknown_assets not in {"record", "skip"}:
        raise ImportError_("unknown_assetsはrecordまたはskipを指定してください。")
    if not sources:
        raise ImportError_("読み込むソースを1つ以上指定してください。")
    assets: dict[str, dict] = {}
    events: list[dict] = []
    reports: list[dict] = []
    seen_events: dict[str, str] = {}
    identifiers: dict[str, str] = {}
    for path, spec in sources:
        records, quality = read_source(path, spec, max_rows=max_rows, max_bytes=max_bytes, identifiers=identifiers)
        reports.append(quality)
        for record in records:
            if spec["record"] == "asset":
                asset = _asset(record)
                previous = assets.get(asset["id"])
                # Keep the most recently observed row; older inventory rows do not
                # overwrite a newer one just because they were read later.
                if previous is None or asset["observed_at"] >= previous["observed_at"]:
                    assets[asset["id"]] = asset
                continue
            event = {"type": spec["record"], **record}
            body = canonical(event)
            previous_body = seen_events.get(event["id"])
            if previous_body is None:
                seen_events[event["id"]] = body
                events.append(event)
            elif previous_body == body:
                # A re-sent identical row is a duplicate, not new evidence.
                quality["rows_imported"] -= 1
                quality["rows_skipped"] += 1
                quality["skip_reasons"]["同じ行の重複"] = quality["skip_reasons"].get("同じ行の重複", 0) + 1
            else:
                # The same ID carrying different content is a collector problem.
                # Neither record is dropped: one of them may be the evidence that
                # matters, and a planted row must not be able to evict a real one.
                event["id"] = f"{event['id'][:40]}{SLUG_MARK}" + hashlib.sha256(body.encode()).hexdigest()[:16]
                if event["id"] in seen_events:
                    quality["rows_imported"] -= 1
                    quality["rows_skipped"] += 1
                    quality["skip_reasons"]["重複した再付与ID"] = quality["skip_reasons"].get("重複した再付与ID", 0) + 1
                else:
                    seen_events[event["id"]] = canonical(event)
                    events.append(event)
                    quality["skip_reasons"]["同じイベントIDのため別IDを付与"] = quality["skip_reasons"].get("同じイベントIDのため別IDを付与", 0) + 1

    referenced = {e["gateway_id"] if e["type"] == "login" else e["asset_id"] for e in events}
    shadow = sorted(referenced - set(assets))
    latest = max((e["at"] for e in events), default=None)
    # The snapshot is as recent as the newest thing it contains — an inventory row
    # may well be newer than the last log line.
    newest = max([t for t in [latest, *(a["observed_at"] for a in assets.values())] if t], default=None)
    stamp = as_of or (parse_time(newest) if newest else utcnow())
    for aid in shadow:
        if unknown_assets == "record":
            # An asset that appears only in traffic is a coverage gap, not a safe asset.
            assets[aid] = {"id": aid, "kind": "unknown", "patch_state": "unknown", "observed_at": iso(stamp),
                           "vulnerability": None, **{k: None for k in ASSET_TARGETS}}
    if unknown_assets == "skip":
        events = [e for e in events if (e["gateway_id"] if e["type"] == "login" else e["asset_id"]) in assets]
    if not assets:
        raise ImportError_("資産が1件も読み込めませんでした。資産台帳のプロファイルと入力を確認してください。")

    snapshot = {"schema_version": 1, "as_of": iso(stamp), "assets": sorted(assets.values(), key=lambda a: a["id"]),
                "events": sorted(events, key=lambda e: (e["at"], e["id"])),
                "provenance": [{"label": r["label"], "sha256": r["sha256"], "rows_read": r["rows_read"],
                                "rows_imported": r["rows_imported"], "connector": "file-import"} for r in reports]}
    totals = {key: sum(r[key] for r in reports) for key in ("rows_read", "rows_imported", "rows_skipped", "normalized_identifiers")}
    unknown: Counter = Counter()
    reasons: Counter = Counter()
    for report in reports:
        unknown.update(report["unknown_values"])
        reasons.update(report["skip_reasons"])
    quality = {"connector_version": CONNECTOR_VERSION, "generated_at": iso(utcnow()), "sources": reports,
               "totals": {**totals, "assets": len(assets), "events": len(snapshot["events"]),
                          "unknown_values": dict(unknown), "skip_reasons": dict(reasons)},
               "shadow_assets": shadow, "unknown_assets_policy": unknown_assets,
               "time_range": {"first": snapshot["events"][0]["at"] if snapshot["events"] else None, "last": latest},
               "warnings": _warnings(reports, shadow, snapshot, stamp)}
    return snapshot, quality


def _warnings(reports: list[dict], shadow: list[str], snapshot: dict, stamp: datetime) -> list[str]:
    out = []
    kinds = {r["record"] for r in reports}
    for name, label in (("asset", "資産台帳"), ("login", "認証ログ"), ("file_access", "ファイル参照ログ")):
        if name not in kinds:
            out.append(f"{label}を読み込んでいません。相関の材料が欠けています。")
    if shadow:
        out.append(f"台帳にない資産を{len(shadow)}件、ログから検出しました。公開状況・パッチ状態は不明のまま扱います。")
    skipped = sum(r["rows_skipped"] for r in reports)
    read = sum(r["rows_read"] for r in reports) or 1
    conflicts = sum(r["skip_reasons"].get("同じイベントIDのため別IDを付与", 0) for r in reports)
    if conflicts:
        out.append(f"同じイベントIDで内容が異なる行が{conflicts}行ありました。証跡を失わないよう別IDを付与しています。"
                   "収集元のID付与を確認してください。")
    if skipped / read > 0.05:
        out.append(f"読み飛ばした行が{skipped}行（{skipped / read:.1%}）あります。マッピングと時刻書式を確認してください。")
    if snapshot["events"]:
        span = parse_time(snapshot["events"][-1]["at"]) - parse_time(snapshot["events"][0]["at"])
        if span < timedelta(hours=1):
            out.append("イベントの時間幅が1時間未満です。誤検知評価には不十分な期間です。")
        if stamp - parse_time(snapshot["events"][-1]["at"]) > timedelta(days=1):
            out.append("最新イベントがスナップショット時刻より1日以上前です。取得漏れの可能性があります。")
    out.append("このインポートはログの真正性・網羅性を検証していません。収集側の設定と保持期間を別途確認してください。")
    return out
