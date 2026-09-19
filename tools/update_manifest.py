"""Keep SHA256SUMS.txt covering every tracked file; --check fails on drift.

The manifest is the tree's integrity record, so a file that is missing from it
is as much a defect as one whose hash no longer matches.
"""
from pathlib import Path
import argparse
import hashlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SHA256SUMS.txt"


def tracked() -> list[str]:
    out = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"])
    return sorted(p for p in out.decode().split("\0") if p and p != MANIFEST.name)


def render() -> str:
    return "".join(
        hashlib.sha256((ROOT / path).read_bytes()).hexdigest() + "  " + path + "\n"
        for path in tracked()
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="SHA256SUMS.txt を再生成、または差分を検査します。")
    parser.add_argument("--check", action="store_true", help="書き換えずに差分だけ報告する")
    args = parser.parse_args()
    expected = render()
    current = MANIFEST.read_text() if MANIFEST.exists() else ""
    if expected == current:
        print(f"SHA256SUMS.txt は {len(tracked())} ファイルと一致しています。")
        return 0
    if not args.check:
        MANIFEST.write_text(expected)
        print(f"SHA256SUMS.txt を {len(tracked())} ファイルで更新しました。")
        return 0
    have = {line.split("  ", 1)[1] for line in current.splitlines() if "  " in line}
    want = {line.split("  ", 1)[1] for line in expected.splitlines()}
    for path in sorted(want - have):
        print("未登録: " + path, file=sys.stderr)
    for path in sorted(have - want):
        print("削除済み: " + path, file=sys.stderr)
    stale = [
        line.split("  ", 1)[1]
        for line in sorted(set(expected.splitlines()) - set(current.splitlines()))
        if line.split("  ", 1)[1] in have
    ]
    for path in stale:
        print("ハッシュ不一致: " + path, file=sys.stderr)
    print("SHA256SUMS.txt が実際のファイルと一致しません。tools/update_manifest.py を実行してください。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
