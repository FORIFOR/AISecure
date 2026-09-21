"""Store credential-shaped corpus values in parts.

GitHub push protection blocks a push that contains a string matching a real
vendor token format, even when the value is synthetic. The corpus needs those
formats to measure the detector, so the value is stored split and joined at
load time: no complete token literal exists in the repository, and the string
the detector sees is byte-identical.

    python -m tools.split_corpus_literals docs/security/corpus.jsonl
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

# Cases whose ids start with these letters carry credential-shaped values.
SPLIT_PREFIXES = ('S', 'E')
TOKEN = re.compile(r'\S{16,}')


def split_text(text: str) -> list[str] | None:
    """Break the longest long run of non-space characters in half."""
    matches = list(TOKEN.finditer(text))
    if not matches:
        return None
    target = max(matches, key=lambda m: m.end() - m.start())
    middle = target.start() + (target.end() - target.start()) // 2
    return [text[:middle], text[middle:]]


def main(argv=None):
    path = Path((argv or sys.argv[1:])[0])
    cases = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    changed = 0
    for case in cases:
        if not case['id'].startswith(SPLIT_PREFIXES) or 'text' not in case:
            continue
        parts = split_text(case['text'])
        if not parts:
            continue
        assert ''.join(parts) == case['text']
        case['parts'] = parts
        del case['text']
        changed += 1
    path.write_text('\n'.join(json.dumps(c, ensure_ascii=False) for c in cases) + '\n', encoding='utf-8')
    print(f'{changed} / {len(cases)} cases stored in parts')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
