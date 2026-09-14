"""Verification boundary for approvals issued by an external identity service.

AISecure does not implement an identity provider.  A deployment can instead
configure an SSO/RBAC gateway to issue two Ed25519-signed approval documents;
this module verifies their binding to the exact proposal, snapshot and action
before the local store records the approval.
"""
from __future__ import annotations

import base64
import binascii
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from .schema import canonical, identifier, object_keys, parse_time, read_json, utcnow, ValidationError


MAX_APPROVAL_BYTES = 32 * 1024
MAX_KEYS_BYTES = 32 * 1024
ROLES = {"primary", "secondary"}
DECISION = "approve"


def _b64url(value: str, expected_length: int) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValidationError("承認証明の署名形式が不正です。")
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValidationError("承認証明の署名形式が不正です。")
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValidationError("承認証明の署名形式が不正です。") from exc
    if len(raw) != expected_length:
        raise ValidationError("承認証明の署名長が不正です。")
    return raw


def load_public_keys(path: str | Path) -> dict[str, bytes]:
    """Load an operator-id to raw Ed25519 public-key registry."""
    try:
        raw = read_json(Path(path).read_bytes(), MAX_KEYS_BYTES)
    except (OSError, ValueError, RecursionError) as exc:
        raise ValidationError("承認者公開鍵レジストリを読み込めません。") from exc
    if not isinstance(raw, dict) or not raw or len(raw) > 1000:
        raise ValidationError("承認者公開鍵レジストリの形式が不正です。")
    keys: dict[str, bytes] = {}
    for operator, encoded in raw.items():
        if not isinstance(operator, str) or not 1 <= len(operator) <= 120 or any(ord(c) < 32 for c in operator):
            raise ValidationError("承認者公開鍵レジストリの識別子が不正です。")
        keys[operator] = _b64url(encoded, 32)
    return keys


def _validate_claim(payload: Any, expected_proposal: str, expected_snapshot: str) -> dict:
    if not isinstance(payload, dict):
        raise ValidationError("承認証明のpayloadが不正です。")
    object_keys(payload, {"schema_version", "proposal_id", "snapshot_id", "action", "approver", "role", "decision", "issued_at", "expires_at", "nonce"})
    if payload["schema_version"] != 1 or payload["decision"] != DECISION or payload["role"] not in ROLES:
        raise ValidationError("承認証明の決定または役割が不正です。")
    if payload["proposal_id"] != expected_proposal or payload["snapshot_id"] != expected_snapshot:
        raise ValidationError("承認証明が現在の計画または入力に対応していません。")
    try:
        identifier(payload["proposal_id"])
        identifier(payload["snapshot_id"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("承認証明の計画IDまたは入力IDが不正です。") from exc
    if not isinstance(payload["action"], str) or payload["action"] not in {"revoke_session", "restrict_remote_access", "review_evidence"}:
        raise ValidationError("承認証明の操作が許可範囲外です。")
    if not isinstance(payload["approver"], str) or not 1 <= len(payload["approver"]) <= 120 or any(ord(c) < 32 for c in payload["approver"]):
        raise ValidationError("承認証明の承認者IDが不正です。")
    if not isinstance(payload["nonce"], str) or not 16 <= len(payload["nonce"]) <= 256 or any(ord(c) < 32 for c in payload["nonce"]):
        raise ValidationError("承認証明のnonceが不正です。")
    try:
        issued = parse_time(payload["issued_at"])
        expires = parse_time(payload["expires_at"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("承認証明の時刻が不正です。") from exc
    now = utcnow()
    if issued < now - timedelta(minutes=5) or issued > now + timedelta(minutes=2) or expires <= now or expires > issued + timedelta(minutes=15):
        raise ValidationError("承認証明の有効期限が切れているか、時刻が不正です。")
    return payload


def verify_approval(path: str | Path, public_keys: dict[str, bytes], expected_proposal: str,
                    expected_snapshot: str, expected_role: str) -> dict:
    """Verify one signed approval and return only its validated payload."""
    if expected_role not in ROLES:
        raise ValidationError("承認証明の役割が不正です。")
    try:
        document = read_json(Path(path).read_bytes(), MAX_APPROVAL_BYTES)
    except (OSError, ValueError, RecursionError) as exc:
        raise ValidationError("承認証明を読み込めません。") from exc
    if not isinstance(document, dict):
        raise ValidationError("承認証明の形式が不正です。")
    object_keys(document, {"payload", "signature"})
    claim = _validate_claim(document["payload"], expected_proposal, expected_snapshot)
    if claim["role"] != expected_role or claim["approver"] not in public_keys:
        raise ValidationError("承認証明の役割または承認者が許可されていません。")
    signature = _b64url(document["signature"], 64)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised by install docs
        raise ValidationError(
            "署名付き承認の検証にはcryptographyが必要です。pip install '.[production]' を実行してください。"
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(public_keys[claim["approver"]]).verify(
            signature, canonical(claim).encode("utf-8")
        )
    except InvalidSignature as exc:
        raise ValidationError("承認証明の署名検証に失敗しました。") from exc
    return claim


def verify_pair(primary_path: str | Path, secondary_path: str | Path, keys_path: str | Path,
                expected_proposal: str, expected_snapshot: str) -> list[dict]:
    keys = load_public_keys(keys_path)
    primary = verify_approval(primary_path, keys, expected_proposal, expected_snapshot, "primary")
    secondary = verify_approval(secondary_path, keys, expected_proposal, expected_snapshot, "secondary")
    if primary["approver"] == secondary["approver"]:
        raise ValidationError("承認証明には異なる2名の承認者が必要です。")
    if primary["action"] != secondary["action"]:
        raise ValidationError("2件の承認証明の操作が一致しません。")
    return [primary, secondary]
