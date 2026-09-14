"""Authenticated encryption for sensitive local-store fields.

The default local prototype keeps its existing file-key mode for zero-install
use.  Production deployments can provide a 32-byte key from a secret manager
and use this envelope for snapshot bodies and audit payloads.  The key is
never written by this module; the caller owns its lifecycle.
"""
from __future__ import annotations

import base64
import binascii
import os

from .schema import ValidationError


PREFIX = "aesgcm:v1:"
NONCE_BYTES = 12
KEY_BYTES = 32


class StorageCipherError(RuntimeError):
    """The encrypted storage envelope cannot be opened or is malformed."""


class StorageCipher:
    """Small AES-GCM envelope with explicit associated-data binding."""

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != KEY_BYTES:
            raise ValidationError("保管時暗号化の鍵は32バイトで指定してください。")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:  # pragma: no cover - exercised by install docs
            raise ValidationError(
                "保管時暗号化にはcryptographyが必要です。pip install '.[production]' を実行してください。"
            ) from exc
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: str, associated_data: str) -> str:
        if not isinstance(plaintext, str) or not isinstance(associated_data, str):
            raise StorageCipherError("暗号化対象の形式が不正です。")
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = self._aes.encrypt(nonce, plaintext.encode("utf-8"), associated_data.encode("utf-8"))
        return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, envelope: str, associated_data: str) -> str:
        if not isinstance(envelope, str) or not envelope.startswith(PREFIX):
            raise StorageCipherError("暗号化された保管データの形式が不正です。")
        try:
            packed = base64.urlsafe_b64decode(envelope[len(PREFIX):].encode("ascii"))
            if len(packed) <= NONCE_BYTES:
                raise ValueError
            plaintext = self._aes.decrypt(
                packed[:NONCE_BYTES], packed[NONCE_BYTES:], associated_data.encode("utf-8")
            )
            return plaintext.decode("utf-8")
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise StorageCipherError("保管データの復号または完全性検証に失敗しました。") from exc
        except Exception as exc:
            # cryptography raises InvalidTag for an incorrect key or modified
            # ciphertext. Keep the optional dependency's exception type out of
            # the storage boundary and fail closed for all crypto failures.
            raise StorageCipherError("保管データの復号または完全性検証に失敗しました。") from exc
