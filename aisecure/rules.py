"""Tunable detection thresholds.

Changing a threshold changes what is detected and what is missed, so the active
configuration is validated, hashed, shown in the UI, and recorded in the audit
chain. Defaults are the v0.1 values; they are starting points for tuning against
an organization's own normal traffic, not validated production settings.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib
from .schema import canonical, ValidationError

# name -> (low, high, type, description)
BOUNDS: dict[str, tuple[float, float, type, str]] = {
    "window_seconds": (10, 86400, int, "大量参照を数える時間窓（秒）"),
    "distinct_file_threshold": (2, 1_000_000, int, "窓内で検知に必要な異なるファイル数"),
    "login_lookback_seconds": (0, 604800, int, "大量参照の直前ログインを関連付ける上限（秒）"),
    "sensitive_file_minimum": (0, 1_000_000, int, "相関に必要な機密ラベル付きファイル数"),
    "stale_asset_hours": (1, 8760, int, "資産情報を古いと判定する経過時間"),
    "cvss_priority_threshold": (0.0, 10.0, float, "公開状況が不明な資産をP2に上げるCVSS下限"),
}
# name -> (choices, description)
CHOICES: dict[str, tuple[set[str], str]] = {
    "identity_conditions": ({"any", "both"}, "特権ログインを要確認とする条件。any=非管理端末または未承認、both=両方"),
}


@dataclass(frozen=True)
class RuleConfig:
    window_seconds: int = 300
    distinct_file_threshold: int = 100
    login_lookback_seconds: int = 1800
    sensitive_file_minimum: int = 1
    stale_asset_hours: int = 24
    cvss_priority_threshold: float = 7.0
    identity_conditions: str = "any"

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical(self.as_dict()).encode()).hexdigest()[:16]

    def replace(self, **changes) -> "RuleConfig":
        return from_mapping({**self.as_dict(), **changes})


DEFAULT = RuleConfig()


def from_mapping(raw) -> RuleConfig:
    """Strict validation: unknown keys and out-of-range values are rejected, never clamped."""
    if not isinstance(raw, dict):
        raise ValidationError("検知設定はJSONオブジェクトが必要です。")
    unknown = set(raw) - set(BOUNDS) - set(CHOICES)
    if unknown:
        raise ValidationError(f"未定義の検知設定項目です: {', '.join(sorted(unknown))}")
    values = DEFAULT.as_dict()
    for name, value in raw.items():
        if name in CHOICES:
            if value not in CHOICES[name][0]:
                raise ValidationError(f"{name}は{sorted(CHOICES[name][0])}のいずれかを指定してください。")
            values[name] = value
            continue
        low, high, kind, _ = BOUNDS[name]
        if type(value) is bool or type(value) not in ((int, float) if kind is float else (int,)):
            raise ValidationError(f"{name}には{'数値' if kind is float else '整数'}が必要です。")
        if not low <= value <= high:
            raise ValidationError(f"{name}は{low}〜{high}の範囲で指定してください。")
        values[name] = kind(value)
    config = RuleConfig(**values)
    if config.sensitive_file_minimum > config.distinct_file_threshold:
        raise ValidationError("sensitive_file_minimumはdistinct_file_threshold以下にしてください。")
    return config


def describe(config: RuleConfig) -> list[dict]:
    values = config.as_dict()
    return ([{"name": name, "value": values[name], "description": BOUNDS[name][3]} for name in BOUNDS]
            + [{"name": name, "value": values[name], "description": CHOICES[name][1]} for name in CHOICES])
