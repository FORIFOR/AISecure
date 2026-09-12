"""Read-only log connectors.

`aisecure import` is the only entry point that reads files outside the snapshot
JSON boundary. It writes nothing back to the sources and carries forward only
the metadata a validated mapping profile names.
"""
from __future__ import annotations
from pathlib import Path

from ..schema import read_json, ValidationError
from . import profile as profile_module
from .importer import ImportError_, build_snapshot, read_source, slug, CONNECTOR_VERSION, MAX_ROWS, MAX_SOURCE_BYTES

BUILTIN_DIR = Path(__file__).resolve().parent / "profiles"

__all__ = ["ImportError_", "build_snapshot", "read_source", "slug", "load_profile", "builtin_profiles",
           "CONNECTOR_VERSION", "MAX_ROWS", "MAX_SOURCE_BYTES"]


def builtin_profiles() -> dict[str, Path]:
    return {path.stem: path for path in sorted(BUILTIN_DIR.glob("*.json"))}


def load_profile(name_or_path: str) -> dict:
    """Resolve a built-in profile name, or a path to an operator-authored profile."""
    builtin = builtin_profiles()
    path = builtin.get(name_or_path) or Path(name_or_path).expanduser()
    if not path.is_file():
        raise ValidationError(f"プロファイルが見つかりません: {name_or_path}（組み込み: {', '.join(builtin)}）")
    if path.stat().st_size > 256 * 1024:
        raise ValidationError("プロファイルは256 KiB以下にしてください。")
    return profile_module.load(read_json(path.read_bytes()))
