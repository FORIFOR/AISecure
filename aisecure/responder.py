"""Explicit, signed response delivery for real containment adapters.

The analysis process never receives provider credentials and never executes
shell commands.  A separately operated responder (SOAR, IdP, firewall, or a
small sidecar) receives a minimal, signed action request and is responsible
for provider-specific authentication and post-action verification.

The default remains simulation-only.  Real delivery is opt-in, restricted to
an HTTPS endpoint (or a loopback HTTP endpoint for local integration tests),
and only accepts an explicitly allowlisted action.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .schema import canonical, identifier, ValidationError
from .safety import EmergencyStop, EmergencyStopError


class ResponderError(RuntimeError):
    """A response could not be delivered or verified."""


class _NoRedirect(HTTPRedirectHandler):
    """Never leak an action payload to a URL chosen by a redirect."""

    def redirect_request(self, *_args, **_kwargs):
        raise ResponderError("実行先のリダイレクトは許可しません。")


@dataclass(frozen=True)
class ResponderConfig:
    url: str
    secret: bytes
    timeout: float = 5.0
    allowed_actions: frozenset[str] = frozenset()
    emergency_stop_file: str | None = None

    def __post_init__(self):
        try:
            parts = urlsplit(self.url)
            hostname = parts.hostname
        except ValueError as exc:
            raise ValidationError("実行先URLの形式が不正です。") from exc
        if parts.scheme != "https":
            if not (parts.scheme == "http" and hostname in {"127.0.0.1", "::1", "localhost"}):
                raise ValidationError("実行先はHTTPSが必要です。HTTPはループバックのテスト先だけ許可します。")
        if not hostname or parts.username or parts.password or parts.fragment or parts.query:
            raise ValidationError("実行先URLにホスト以外の認証情報・クエリ・フラグメントは指定できません。")
        if not 0.5 <= self.timeout <= 30:
            raise ValidationError("Webhookのタイムアウトは0.5〜30秒にしてください。")
        if len(self.secret) < 32:
            raise ValidationError("Webhook署名鍵は32バイト以上が必要です。")
        if not self.allowed_actions or not self.allowed_actions <= {"revoke_session", "restrict_remote_access", "review_evidence"}:
            raise ValidationError("許可する対応操作を明示してください。")


def _request_payload(plan: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Build a provider-neutral payload without raw logs or operator secrets."""
    required = {"action", "target", "finding_id"}
    if not required <= plan.keys():
        raise ValidationError("対応計画の必須項目が不足しています。")
    action = plan["action"]
    identifier(plan["finding_id"])
    identifier(context["snapshot_id"])
    identifier(context["proposal_id"])
    # The analysis store intentionally keeps only a pseudonymous target. A real
    # provider target must be supplied by the approving operator at execution
    # time, after they have verified it in the provider's own console.
    target = context.get("provider_target")
    if not isinstance(target, str) or not 1 <= len(target) <= 160:
        raise ValidationError("実操作には、防御側で確認した対象IDの明示指定が必要です。")
    if any(ord(c) < 32 for c in target):
        raise ValidationError("防御側の対象IDに制御文字は指定できません。")
    evidence_ids = context.get("evidence_ids", [])
    if not isinstance(evidence_ids, list) or len(evidence_ids) > 500:
        raise ValidationError("根拠IDの数が上限を超えています。")
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or not 1 <= len(evidence_id) <= 160:
            raise ValidationError("根拠IDの形式が不正です。")
    return {
        "schema_version": 1,
        "request_id": secrets.token_hex(16),
        "proposal_id": context["proposal_id"],
        "snapshot_id": context["snapshot_id"],
        "finding_id": plan["finding_id"],
        "action": action,
        "target": target,
        "evidence_ids": sorted(set(evidence_ids)),
        "requested_at": int(time.time()),
    }


class SignedWebhookResponder:
    """Deliver an approved action to a separately authenticated responder."""

    adapter_name = "signed-webhook"

    def __init__(self, config: ResponderConfig):
        self.config = config
        self.emergency_stop = EmergencyStop(config.emergency_stop_file)

    def execute(self, plan: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        try:
            self.emergency_stop.assert_clear()
        except EmergencyStopError as exc:
            raise ResponderError(str(exc)) from exc
        if plan.get("execution_mode") != "real":
            raise ResponderError("実操作モードではない対応計画は実行できません。")
        if plan.get("automatic_execution") is not False:
            raise ResponderError("自動実行を無効にした対応計画だけ実行できます。")
        if plan.get("action") not in self.config.allowed_actions:
            raise ResponderError("この対応操作はWebhookの許可リストにありません。")
        payload = _request_payload(plan, context)
        raw = canonical(payload).encode("utf-8")
        timestamp = str(payload["requested_at"])
        signature = hmac.new(self.config.secret, timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AISecure-responder/1",
            "X-AISecure-Timestamp": timestamp,
            "X-AISecure-Request": payload["request_id"],
            "X-AISecure-Signature": "sha256=" + signature,
            "X-AISecure-Idempotency-Key": context["proposal_id"],
        }
        request = Request(self.config.url, data=raw, headers=headers, method="POST")
        try:
            self.emergency_stop.assert_clear()
            with build_opener(_NoRedirect).open(request, timeout=self.config.timeout) as response:
                status = response.status
                body = response.read(64 * 1024)
        except EmergencyStopError as exc:
            raise ResponderError(str(exc)) from exc
        except HTTPError as exc:
            raise ResponderError(f"実行先がHTTP {exc.code}を返しました。") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ResponderError("実行先へ接続できませんでした。") from exc
        if not 200 <= status < 300:
            raise ResponderError(f"実行先がHTTP {status}を返しました。")
        try:
            result = json.loads(body)
        except (ValueError, UnicodeError) as exc:
            raise ResponderError("実行先の応答がJSONではありません。") from exc
        if not isinstance(result, dict) or result.get("status") not in {"verified", "failed"}:
            raise ResponderError("実行先はstatus=verifiedまたはfailedを返す必要があります。")
        if result.get("request_id") != payload["request_id"] or result.get("proposal_id") != context["proposal_id"]:
            raise ResponderError("実行先の応答がこの要求に対応していません。")
        if result["status"] == "failed":
            return {"status": "failed", "executed": False, "adapter": self.adapter_name, "provider": result.get("provider", "unknown")}
        return {"status": "verified", "executed": True, "adapter": self.adapter_name, "provider": result.get("provider", "unknown")}
