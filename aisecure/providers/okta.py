"""Minimal Okta management adapter for verified session containment.

The adapter deliberately accepts an Okta user ID, not AISecure's pseudonymous
actor or a login address. It clears all active Okta sessions for that user and
only reports success after a matching ``user.session.clear`` event is visible
in the System Log. The token is held only by this process and is never logged,
stored in the local database, or sent to the analysis store.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..responder import ResponderError
from ..schema import canonical, iso, parse_time, ValidationError, ID, utcnow
from ..connectors import MAX_ROWS, MAX_SOURCE_BYTES, build_snapshot
from ..connectors.importer import _warnings

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_LOG_PAGES = 20
OKTA_USER_ID = re.compile(r"^00u[A-Za-z0-9]{7,77}$")


class OktaError(ResponderError):
    """An Okta request or post-action verification failed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise OktaError("Okta APIのリダイレクトは許可しません。")


@dataclass(frozen=True)
class OktaConfig:
    """Connection settings; ``token`` must come from a secret manager/env var."""

    base_url: str
    token: str
    auth_scheme: str = "Bearer"
    timeout: float = 5.0
    verification_timeout: float = 5.0
    allow_insecure_localhost: bool = False

    def __post_init__(self):
        try:
            parts = urlsplit(self.base_url)
            hostname = parts.hostname
        except ValueError as exc:
            raise ValidationError("OktaドメインのURL形式が不正です。") from exc
        local = hostname in {"127.0.0.1", "::1", "localhost"}
        if parts.scheme != "https" and not (self.allow_insecure_localhost and parts.scheme == "http" and local):
            raise ValidationError("Okta APIはHTTPSが必要です。HTTPは明示的なローカルテストだけ許可します。")
        if not hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in {"", "/"}:
            raise ValidationError("Oktaドメインにはホストだけを指定してください。")
        if self.auth_scheme not in {"Bearer", "SSWS"}:
            raise ValidationError("Okta認証方式はBearerまたはSSWSを指定してください。")
        if not isinstance(self.token, str) or not 20 <= len(self.token) <= 4096 or any(ord(c) < 33 for c in self.token):
            raise ValidationError("Oktaトークンの形式または長さが不正です。")
        if not 0.5 <= self.timeout <= 30:
            raise ValidationError("Okta APIのタイムアウトは0.5〜30秒にしてください。")
        if not 0.5 <= self.verification_timeout <= 30:
            raise ValidationError("Oktaの検証待ちは0.5〜30秒にしてください。")


class OktaClient:
    """Small, redirect-free stdlib client for the Okta Management API."""

    adapter_name = "okta-session-revoker"

    def __init__(self, config: OktaConfig):
        self.config = config
        parts = urlsplit(config.base_url)
        self._origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def _url(self, path: str, query: dict[str, str] | None = None) -> str:
        if not path.startswith("/api/v1/") or ".." in path.split("/"):
            raise OktaError("Okta APIパスが許可範囲外です。")
        return self._origin + path + (("?" + urlencode(query)) if query else "")

    def _check_url(self, url: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError as exc:
            raise OktaError("Okta APIのリンク形式が不正です。") from exc
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        if origin != self._origin or parts.scheme not in {"https", "http"} or parts.username or parts.password or parts.fragment:
            raise OktaError("Okta APIのリンク先が許可された同一ドメインではありません。")

    def _request(self, method: str, url: str) -> tuple[int, bytes, Any]:
        self._check_url(url)
        request = Request(url, headers={
            "Accept": "application/json",
            "Authorization": f"{self.config.auth_scheme} {self.config.token}",
            "User-Agent": "AISecure-okta/1",
        }, method=method)
        try:
            with build_opener(_NoRedirect).open(request, timeout=self.config.timeout) as response:
                status = response.status
                length = response.headers.get("Content-Length")
                if length and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
                    raise OktaError("Okta APIの応答が大きすぎます。")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise OktaError("Okta APIの応答が大きすぎます。")
                return status, body, response.headers
        except HTTPError as exc:
            raise OktaError(f"Okta APIがHTTP {exc.code}を返しました。") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OktaError("Okta APIへ接続できませんでした。") from exc

    @staticmethod
    def _json(body: bytes) -> Any:
        if not body:
            return None
        try:
            return json.loads(body)
        except (ValueError, UnicodeError) as exc:
            raise OktaError("Okta APIの応答がJSONではありません。") from exc

    @staticmethod
    def _next_link(headers: Any) -> str | None:
        values = headers.get_all("Link", []) if hasattr(headers, "get_all") else []
        for value in values:
            for part in value.split(","):
                match = re.fullmatch(r"\s*<([^>]+)>\s*;\s*rel=\"next\"\s*", part)
                if match:
                    return match.group(1)
        return None

    def system_log(self, *, since: datetime, until: datetime | None = None,
                   filter_expression: str | None = None, limit: int = 100) -> list[dict]:
        """Read bounded System Log pages and follow only Okta's next links."""
        if since.tzinfo is None or (until is not None and until.tzinfo is None):
            raise ValidationError("Okta System Logの時刻にはタイムゾーンが必要です。")
        if until is not None and until <= since:
            raise ValidationError("Okta System Logの終了時刻は開始時刻より後にしてください。")
        if not 1 <= limit <= 1000:
            raise ValidationError("Okta System Logのlimitは1〜1000です。")
        query = {"since": iso(since.astimezone(timezone.utc)), "sortOrder": "ASCENDING", "limit": str(limit)}
        if until is not None:
            query["until"] = iso(until.astimezone(timezone.utc))
        if filter_expression:
            if (not isinstance(filter_expression, str) or len(filter_expression) > 500
                    or any(ord(c) < 32 for c in filter_expression)):
                raise ValidationError("Oktaのfilterが不正です。")
            query["filter"] = filter_expression
        url = self._url("/api/v1/logs", query)
        events: list[dict] = []
        for _ in range(MAX_LOG_PAGES):
            status, body, headers = self._request("GET", url)
            if not 200 <= status < 300:
                raise OktaError(f"Okta System LogがHTTP {status}を返しました。")
            data = self._json(body)
            if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
                raise OktaError("Okta System Logの応答形式が不正です。")
            events.extend(data)
            next_url = self._next_link(headers)
            if not next_url:
                return events
            self._check_url(next_url)
            url = next_url
        raise OktaError("Okta System Logのページ数が上限を超えました。")

    def clear_user_sessions(self, user_id: str) -> datetime:
        if not isinstance(user_id, str) or not OKTA_USER_ID.fullmatch(user_id):
            raise ValidationError("実操作の対象は検証済みOktaユーザーID（00uで始まる値）に限定します。")
        requested_at = datetime.now(timezone.utc)
        url = self._url(f"/api/v1/users/{user_id}/sessions", {"oauthTokens": "false"})
        status, _, _ = self._request("DELETE", url)
        if status not in {200, 202, 204}:
            raise OktaError(f"Oktaセッション失効がHTTP {status}で拒否されました。")
        return requested_at - timedelta(seconds=2)

    @staticmethod
    def _targets_user(event: dict, user_id: str) -> bool:
        targets = event.get("target", [])
        if isinstance(targets, dict):
            targets = [targets]
        return isinstance(targets, list) and any(isinstance(target, dict) and target.get("id") == user_id for target in targets)

    def verify_session_clear(self, user_id: str, since: datetime) -> bool:
        deadline = time.monotonic() + self.config.verification_timeout
        expression = f'eventType eq "user.session.clear" and target.id eq "{user_id}"'
        while True:
            now = datetime.now(timezone.utc)
            events = self.system_log(since=since, until=now, filter_expression=expression)
            if any(event.get("eventType") == "user.session.clear" and self._targets_user(event, user_id) for event in events):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.5, remaining))


class OktaSessionResponder:
    """Store-compatible real adapter for the narrow ``revoke_session`` action."""

    adapter_name = OktaClient.adapter_name

    def __init__(self, config: OktaConfig):
        self.client = OktaClient(config)

    def execute(self, plan: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if plan.get("execution_mode") != "real" or plan.get("automatic_execution") is not False:
            raise OktaError("実操作モードかつ自動実行無効の計画だけをOktaへ送信できます。")
        if plan.get("action") != "revoke_session":
            raise OktaError("Oktaアダプターが許可する操作はrevoke_sessionだけです。")
        user_id = context.get("provider_target")
        since = self.client.clear_user_sessions(user_id)
        if not self.client.verify_session_clear(user_id, since):
            return {"status": "failed", "executed": False, "adapter": self.adapter_name,
                    "provider": "okta", "verification": "user.session.clear not observed"}
        return {"status": "verified", "executed": True, "adapter": self.adapter_name,
                "provider": "okta", "verification": "user.session.clear"}


class OktaSystemLogCollector:
    """Fetch a bounded, overlapping Okta login window into an AISecure snapshot.

    The overlap avoids cursor loss during a restart and makes duplicate rows
    harmless. The provider response is held in memory only; the normalized
    snapshot is what enters the local store. Asset and file-access sources are
    still read through the existing read-only importer.
    """

    def __init__(self, client: OktaClient, asset_source: tuple[Path, dict],
                 additional_sources: list[tuple[Path, dict]] | None = None, *,
                 lookback_seconds: int = 1800, max_rows: int = MAX_ROWS,
                 unknown_assets: str = "record"):
        if asset_source[1].get("record") != "asset":
            raise ValidationError("Oktaの直接監視にはassetプロファイルが必要です。")
        if not 60 <= lookback_seconds <= 7 * 24 * 60 * 60:
            raise ValidationError("Oktaの監視ルックバックは60秒〜7日です。")
        if not 1 <= max_rows <= MAX_ROWS:
            raise ValidationError("Oktaの行数上限が不正です。")
        if unknown_assets not in {"record", "skip"}:
            raise ValidationError("unknown_assetsはrecordまたはskipを指定してください。")
        self.client = client
        self.asset_source = asset_source
        self.additional_sources = additional_sources or []
        self.lookback_seconds = lookback_seconds
        self.max_rows = max_rows
        self.unknown_assets = unknown_assets

    @staticmethod
    def _opaque(value: Any) -> bool:
        return isinstance(value, str) and 1 <= len(value) <= 256 and not any(ord(c) < 32 for c in value)

    def _map_login(self, raw: dict) -> dict | None:
        if raw.get("eventType") != "user.session.start":
            return None
        try:
            at = parse_time(raw.get("published"))
        except ValidationError:
            return None
        actor_object = raw.get("actor")
        auth_context = raw.get("authenticationContext")
        outcome = raw.get("outcome")
        actor = actor_object.get("alternateId") if isinstance(actor_object, dict) else None
        session = auth_context.get("externalSessionId") if isinstance(auth_context, dict) else None
        result = outcome.get("result") if isinstance(outcome, dict) else None
        if not self._opaque(actor) or not self._opaque(session) or result not in {"SUCCESS", "FAILURE"}:
            return None
        event_id = raw.get("uuid")
        if not isinstance(event_id, str) or not ID.fullmatch(event_id):
            event_id = "okta-" + hashlib.sha256(canonical(raw).encode("utf-8")).hexdigest()[:24]
        return {"id": event_id, "type": "login", "at": iso(at), "actor": actor,
                "session": session, "gateway_id": "okta-idp", "success": result == "SUCCESS",
                "privileged": None, "device_trusted": None, "approved": None}

    def collect(self, now: datetime | None = None) -> tuple[dict, dict]:
        now = now or utcnow()
        since = now - timedelta(seconds=self.lookback_seconds)
        sources = [self.asset_source, *self.additional_sources]
        snapshot, quality = build_snapshot(sources, unknown_assets=self.unknown_assets,
                                            max_rows=self.max_rows, max_bytes=MAX_SOURCE_BYTES, now=now)
        raw_events = self.client.system_log(
            since=since, until=now,
            filter_expression='eventType eq "user.session.start"', limit=1000,
        )
        if len(raw_events) > self.max_rows:
            raise OktaError(f"Okta System Logの取得件数が{self.max_rows:,}行の上限を超えました。")
        raw_json = canonical(raw_events).encode("utf-8")
        api_report = {"label": "okta-system-log-api", "sha256": hashlib.sha256(raw_json).hexdigest(),
                      "bytes": len(raw_json), "profile": "okta-system-log-api",
                      "record": "login", "rows_read": len(raw_events), "rows_imported": 0,
                      "rows_skipped": 0, "skip_reasons": {}, "unknown_values": {}, "normalized_identifiers": 0}
        existing = {event["id"]: canonical(event) for event in snapshot["events"]}
        imported, skipped = 0, 0
        for raw in raw_events:
            event = self._map_login(raw)
            if event is None:
                skipped += 1
                continue
            if parse_time(event["at"]) > now + timedelta(minutes=5):
                skipped += 1
                continue
            event_body = canonical(event)
            previous = existing.get(event["id"])
            if previous == event_body:
                skipped += 1
                continue
            if previous is not None:
                event["id"] = f"{event['id'][:40]}:" + hashlib.sha256(event_body.encode("utf-8")).hexdigest()[:16]
            if event["id"] in existing:
                skipped += 1
                continue
            existing[event["id"]] = canonical(event)
            snapshot["events"].append(event)
            imported += 1
        api_report["rows_imported"] = imported
        api_report["rows_skipped"] = skipped
        api_report["skip_reasons"] = {"形式または必須項目が不正": skipped} if skipped else {}
        snapshot["events"].sort(key=lambda event: (event["at"], event["id"]))

        referenced = {event["gateway_id"] if event["type"] == "login" else event["asset_id"] for event in snapshot["events"]}
        assets = {asset["id"]: asset for asset in snapshot["assets"]}
        latest = max((event["at"] for event in snapshot["events"]), default=None)
        stamp = max(parse_time(snapshot["as_of"]), *(parse_time(event["at"]) for event in snapshot["events"]))
        for asset_id in sorted(referenced - set(assets)):
            if self.unknown_assets == "record":
                assets[asset_id] = {"id": asset_id, "kind": "unknown", "patch_state": "unknown",
                                    "observed_at": iso(stamp), "vulnerability": None,
                                    "internet_exposed": None, "privileged_path": None, "sensitive_path": None}
        if self.unknown_assets == "skip":
            snapshot["events"] = [event for event in snapshot["events"]
                                  if (event["gateway_id"] if event["type"] == "login" else event["asset_id"]) in assets]
        snapshot["assets"] = sorted(assets.values(), key=lambda asset: asset["id"])
        snapshot["as_of"] = iso(stamp)
        snapshot["provenance"].append({"label": api_report["label"], "sha256": api_report["sha256"],
                                       "rows_read": api_report["rows_read"], "rows_imported": api_report["rows_imported"],
                                       "connector": "okta-system-log-api"})
        quality["sources"].append(api_report)
        quality["totals"]["rows_read"] += api_report["rows_read"]
        quality["totals"]["rows_imported"] += api_report["rows_imported"]
        quality["totals"]["rows_skipped"] += api_report["rows_skipped"]
        quality["totals"]["assets"] = len(snapshot["assets"])
        quality["totals"]["events"] = len(snapshot["events"])
        quality["shadow_assets"] = sorted(referenced - {asset["id"] for asset in snapshot["assets"]})
        quality["unknown_assets_policy"] = self.unknown_assets
        quality["time_range"] = {"first": snapshot["events"][0]["at"] if snapshot["events"] else None, "last": latest}
        quality["warnings"] = _warnings(quality["sources"], quality["shadow_assets"], snapshot, stamp)
        return snapshot, quality
