"""Shared, bounded contracts. Error messages never interpolate input content."""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import time

class ControlError(ValueError):
    pass

ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z')
CLASSES = frozenset({'public', 'internal', 'confidential', 'restricted', 'unknown'})

def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')

def decode(raw: bytes, limit: int = 1024 * 1024):
    if type(raw) is not bytes or len(raw) > limit:
        raise ControlError('入力サイズが上限を超えています。')
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result: raise ControlError('重複するJSON項目は使用できません。')
            result[k] = v
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ControlError('数値が不正です。')))
    except (ValueError, UnicodeError, RecursionError):
        raise ControlError('入力形式が不正です。') from None

def ident(value):
    if type(value) is not str or not ID.fullmatch(value):
        raise ControlError('識別子の形式が不正です。')
    return value

def integer(value, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise ControlError('数値が許可範囲外です。')
    return value

def timestamp(value, *, now=None, age=30 * 86400):
    now = int(time.time()) if now is None else now
    return integer(value, now-age, now+60)

def opaque(key: bytes, kind: str, value: bytes | str) -> str:
    if type(key) is not bytes or len(key) != 32: raise ControlError('外部管理鍵が必要です。')
    value = value.encode() if isinstance(value, str) else value
    return hmac.new(key, kind.encode() + b'\0' + value, hashlib.sha256).hexdigest()
