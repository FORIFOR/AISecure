"""Run from repository root: python -m examples.control.inspect_document FILE.

Local evaluation only; no provider credentials, upload or authorization.
"""
import json
import sys
from pathlib import Path
from aisecure.control.documents import MAX_FILE
from aisecure.control.inspection import inspect_document


def main():
    source = Path(sys.argv[1])
    with source.open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
    report = inspect_document(data, source.suffix.lower().removeprefix('.'))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    # A caller must explicitly handle every verdict. None permits external sending.
    return {'no_findings': 0, 'review': 3, 'block': 4}[report['verdict']]


if __name__ == '__main__':
    raise SystemExit(main())
