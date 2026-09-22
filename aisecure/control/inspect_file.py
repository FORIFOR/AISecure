"""Offline file inspection CLI. JSON stdout or exclusive-create output file."""
import argparse
import json
import os
import tempfile
from pathlib import Path
import sys
from .common import ControlError
from .documents import MAX_FILE
from .inspection import inspect_document


def save_report(destination: Path, body: str) -> None:
    """Publish complete private output without replacing an existing path.

    Hard-link publication is atomic and no-clobber on the same filesystem.
    Unsupported filesystems fail with OSError; no unsafe overwrite fallback.
    """
    descriptor, temporary = tempfile.mkstemp(prefix='.aisecure-report-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description='外部送信せずに資料を検査し、JSONレポートを保存します。')
    parser.add_argument('file', type=Path)
    parser.add_argument('--output', type=Path, help='新規JSON保存先（既存ファイルは上書きしません）')
    args = parser.parse_args(argv)
    try:
        with args.file.open('rb') as stream:
            data = stream.read(MAX_FILE + 1)
        report = inspect_document(data, args.file.suffix.lower().removeprefix('.'))
        body = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
        if args.output:
            save_report(args.output, body)
        else:
            sys.stdout.write(body)
    except (OSError, ControlError):
        print('入力形式・サイズ・読取権限と、新規の保存先を確認してください。既存ファイルは上書きしません。', file=sys.stderr)
        return 2
    return {'no_findings': 0, 'review': 3, 'block': 4}[report['verdict']]


if __name__ == '__main__':
    raise SystemExit(main())
