"""Measure shipped text patterns against a labelled, frozen corpus.

    python -m tools.measure_detection [--corpus PATH] [--out NEW_REPORT.json]

Measurement only: exit 0 means the measurement ran, never that detection passed.
Custom input classification is unverified. Use synthetic or explicitly authorized
customer-owned low-risk input locally; this command grants no data permission.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import unicodedata

from aisecure.preflight import SECRET, PERSONAL
from tools.check_control import provenance, save_report

CORPUS = Path(__file__).resolve().parents[1] / 'docs' / 'security' / 'corpus.jsonl'
MAX_CORPUS_BYTES = 8 * 1024 * 1024
MAX_CASES = 10000
MAX_TEXT_CHARS = 65536
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z')


def detect(text: str) -> list[str]:
    normalized = unicodedata.normalize('NFKC', text)
    rules = []
    if SECRET.search(normalized):
        rules.append('SECRET')
    if PERSONAL.search(normalized):
        rules.append('PII')
    return rules


def validate_cases(cases):
    """Reject ambiguous labels and duplicated samples before any scoring."""
    if type(cases) is not list or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError('Corpus must contain 1 to 10000 cases.')
    validated, seen = [], set()
    for index, case in enumerate(cases, 1):
        error = f'Invalid corpus case {index}; check the documented schema.'
        if type(case) is not dict or not {'id', 'category', 'expect'} <= set(case):
            raise ValueError(error)
        if set(case) - {'id', 'category', 'expect', 'text', 'parts', 'note'}:
            raise ValueError(error)
        if any(type(case[k]) is not str or not IDENTIFIER.fullmatch(case[k])
               for k in ('id', 'category')):
            raise ValueError(error)
        if case['id'] in seen or case['expect'] not in ('detect', 'clean'):
            raise ValueError(error)
        if 'note' in case and type(case['note']) is not str:
            raise ValueError(error)
        if ('text' in case) == ('parts' in case):
            raise ValueError(error)
        if 'text' in case:
            text = case['text']
        else:
            parts = case['parts']
            if (type(parts) is not list or not 1 <= len(parts) <= 64
                    or any(type(part) is not str for part in parts)):
                raise ValueError(error)
            if sum(map(len, parts)) > MAX_TEXT_CHARS:
                raise ValueError(error)
            text = ''.join(parts)
        if type(text) is not str or not 1 <= len(text) <= MAX_TEXT_CHARS:
            raise ValueError(error)
        seen.add(case['id'])
        validated.append({'id': case['id'], 'category': case['category'],
                          'expect': case['expect'], 'text': text})
    return validated


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field in corpus.')
        result[key] = value
    return result


def load_corpus(path):
    with path.open('rb') as stream:
        raw = stream.read(MAX_CORPUS_BYTES + 1)
    if len(raw) > MAX_CORPUS_BYTES:
        raise ValueError('Corpus exceeds 8 MiB.')
    try:
        lines = raw.decode('utf-8').split('\n')
        cases = []
        for line in lines:
            if line.strip(' \t\r'):
                if len(cases) >= MAX_CASES:
                    raise ValueError('Corpus exceeds 10000 cases.')
                cases.append(json.loads(line, object_pairs_hook=_unique_object))
        return validate_cases(cases), hashlib.sha256(raw).hexdigest()
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('Corpus must be valid UTF-8 JSON Lines.') from None


def measure(cases):
    cases = validate_cases(cases)
    per_category = defaultdict(lambda: {'total': 0, 'detected': 0,
                                       'positives': 0, 'negatives': 0,
                                       'true_positives': 0, 'false_positives': 0})
    positives = negatives = true_positive = false_positive = 0
    misses, false_alarms = [], []
    for case in cases:
        rules = detect(case['text'])
        hit = bool(rules)
        bucket = per_category[case['category']]
        bucket['total'] += 1
        bucket['detected'] += hit
        if case['expect'] == 'detect':
            positives += 1
            true_positive += hit
            bucket['positives'] += 1
            bucket['true_positives'] += hit
            if not hit:
                misses.append(case['id'])
        else:
            negatives += 1
            false_positive += hit
            bucket['negatives'] += 1
            bucket['false_positives'] += hit
            if hit:
                false_alarms.append({'id': case['id'], 'rules': rules})
    recall = true_positive / positives if positives else None
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else None
    return {
        'cases': len(cases), 'positives': positives, 'negatives': negatives,
        'detected': true_positive, 'missed': positives - true_positive,
        'false_positives': false_positive,
        'recall': round(recall, 4) if recall is not None else None,
        'precision': round(precision, 4) if precision is not None else None,
        'false_positive_rate': round(false_positive / negatives, 4) if negatives else None,
        'per_category': {k: v for k, v in sorted(per_category.items())},
        'missed_ids': misses, 'false_positive_cases': false_alarms,
        'corpus': 'unverified', 'is_real_world_measurement': False,
        'classification_verified': False, 'production_certified': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, help='Custom JSONL; classification remains unverified')
    parser.add_argument('--out', type=Path, help='New private report; existing files are never replaced')
    args = parser.parse_args(argv)
    if args.out and (args.out.exists() or args.out.is_symlink()):
        parser.exit(2, 'Use a new output file; existing evidence is not replaced.\n')
    try:
        cases, digest = load_corpus(CORPUS if args.corpus is None else args.corpus)
        report = measure(cases)
    except (OSError, ValueError) as error:
        # Do not echo paths, source text, labels or parser snippets into logs.
        message = str(error) if isinstance(error, ValueError) else 'Corpus could not be read.'
        parser.exit(2, message + '\n')
    report.update({'schema': 'aisecure.detection-measurement.v2',
                   'corpus': 'bundled_synthetic' if args.corpus is None else 'custom_unverified',
                   'corpus_sha256': digest,
                   'measured_at': datetime.now(timezone.utc).isoformat(),
                   **provenance(),
                   'measurement_scope': 'supplied_text_patterns_only',
                   'acceptance_passed': None})
    if args.out:
        try:
            save_report(args.out, json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        except OSError:
            parser.exit(2, 'Report publication failed; existing evidence is not replaced.\n')
    for category, counts in report['per_category'].items():
        print(f"{category:22s} {counts['detected']:>3}/{counts['total']:<3}")
    print(f"\n再現率 {report['recall']}  適合率 {report['precision']}  誤検知率 {report['false_positive_rate']}")
    print(f"陽性 {report['positives']} 件中 {report['missed']} 件を見逃し。入力は {report['corpus']}。実運用の測定・合格判定ではありません。")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
