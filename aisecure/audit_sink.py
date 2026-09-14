"""HTTPS publisher for independently retained audit checkpoints.

The sink is intentionally a separate trust boundary.  It receives only a
sequence count and audit-chain tip, signed with a dedicated secret, and must
echo both values in a JSON acknowledgement before publication is reported as
successful.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .schema import canonical, ValidationError


MAX_RESPONSE_BYTES = 64 * 1024
TIP = re.compile(r"^[0-9a-f]{64}$")


class AuditSinkError(RuntimeError):
    """The independent checkpoint could not be accepted and verified."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise AuditSinkError("監査チェックポイント送信先のリダイレクトは許可しません。")


@dataclass(frozen=True)
class AuditSinkConfig:
    url: str
    secret: bytes
    timeout: float = 5.0
    allow_insecure_localhost: bool = False

    def __post_init__(self):
        try:
            parts = urlsplit(self.url)
            hostname = parts.hostname
        except ValueError as exc:
            raise ValidationError("監査チェックポイント送信先URLの形式が不正です。") from exc
        local = hostname in {"127.0.0.1", "::1", "localhost"}
        if parts.scheme != "https" and not (self.allow_insecure_localhost and parts.scheme == "http" and local):
            raise ValidationError("監査チェックポイント送信先はHTTPSが必要です。HTTPは明示的なローカルテストだけ許可します。")
        if not hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValidationError("監査チェックポイント送信先URLに認証情報・クエリ・フラグメントは指定できません。")
        if not 0.5 <= self.timeout <= 30:
            raise ValidationError("監査チェックポイント送信のタイムアウトは0.5〜30秒にしてください。")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValidationError("監査チェックポイント署名鍵は32バイト以上が必要です。")


class ExternalAuditSink:
    """Publish a checkpoint and require an exact remote acknowledgement."""

    adapter_name = "external-audit-checkpoint"

    def __init__(self, config: AuditSinkConfig):
        self.config = config

    @staticmethod
    def _payload(checkpoint: dict) -> dict:
        if not isinstance(checkpoint, dict):
            raise ValidationError("監査チェックポイントの形式が不正です。")
        count, tip = checkpoint.get("count"), checkpoint.get("tip")
        if type(count) is not int or count < 0 or not isinstance(tip, str) or not TIP.fullmatch(tip):
            raise ValidationError("監査チェックポイントのcountまたはtipが不正です。")
        return {"schema_version": 1, "count": count, "tip": tip, "published_at": int(time.time())}

    def publish(self, checkpoint: dict) -> dict:
        payload = self._payload(checkpoint)
        raw = canonical(payload).encode("utf-8")
        signature = hmac.new(self.config.secret, raw, hashlib.sha256).hexdigest()
        request = Request(self.config.url, data=raw, headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AISecure-audit-sink/1",
            "X-AISecure-Checkpoint-Signature": "sha256=" + signature,
            "X-AISecure-Checkpoint-Tip": payload["tip"],
        }, method="POST")
        try:
            with build_opener(_NoRedirect).open(request, timeout=self.config.timeout) as response:
                status = response.status
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise AuditSinkError(f"監査チェックポイント送信先がHTTP {exc.code}を返しました。") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise AuditSinkError("監査チェックポイント送信先へ接続できませんでした。") from exc
        if len(body) > MAX_RESPONSE_BYTES:
            raise AuditSinkError("監査チェックポイント送信先の応答が大きすぎます。")
        if not 200 <= status < 300:
            raise AuditSinkError(f"監査チェックポイント送信先がHTTP {status}を返しました。")
        try:
            result = json.loads(body)
        except (ValueError, UnicodeError) as exc:
            raise AuditSinkError("監査チェックポイント送信先の応答がJSONではありません。") from exc
        if not isinstance(result, dict) or result.get("status") not in {"accepted", "verified"}:
            raise AuditSinkError("監査チェックポイント送信先はstatus=acceptedまたはverifiedを返す必要があります。")
        if result.get("count") != payload["count"] or result.get("tip") != payload["tip"]:
            raise AuditSinkError("監査チェックポイント送信先の応答がこのチェックポイントに対応していません。")
        return {"status": result["status"], "count": payload["count"], "tip": payload["tip"],
                "adapter": self.adapter_name}
