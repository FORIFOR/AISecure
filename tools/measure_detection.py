"""Measure the shipped detection patterns against a labelled corpus.

    python -m tools.measure_detection [--corpus PATH] [--out report.json]

The corpus is synthetic. This measures the detector, not real-world exposure:
a recall number here is an upper bound on a corpus we wrote ourselves, and says
nothing about the distribution of real documents. Exit code is 0 as long as the
measurement ran; it is a measurement, not a gate.
"""
from __future__ import annotations
import argparse
import json
from collections import defaultdict
from pathlib import Path
import unicodedata

from aisecure.preflight import SECRET, PERSONAL

CORPUS = Path(__file__).resolve().parents[1] / 'docs' / 'security' / 'corpus.jsonl'


def detect(text: str) -> list[str]:
    normalized = unicodedata.normalize('NFKC', text)
    rules = []
    if SECRET.search(normalized):
        rules.append('SECRET')
    if PERSONAL.search(normalized):
        rules.append('PII')
    return rules


def measure(cases):
    per_category = defaultdict(lambda: {'total': 0, 'detected': 0})
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
            if not hit:
                misses.append(case['id'])
        else:
            negatives += 1
            false_positive += hit
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
        'corpus': 'synthetic', 'is_real_world_measurement': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=CORPUS)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    cases = [json.loads(line) for line in args.corpus.read_text(encoding='utf-8').splitlines() if line.strip()]
    # Credential-shaped values are stored split so the repository never holds a
    # complete vendor-format token; the joined string is what the detector sees.
    for case in cases:
        case.setdefault('text', ''.join(case.get('parts', ())))
    report = measure(cases)
    for category, counts in report['per_category'].items():
        print(f"{category:22s} {counts['detected']:>3}/{counts['total']:<3}")
    print(f"\n再現率 {report['recall']}  適合率 {report['precision']}  誤検知率 {report['false_positive_rate']}")
    print(f"陽性 {report['positives']} 件中 {report['missed']} 件を見逃し。合成コーパスであり実運用の測定ではない。")
    if args.out:
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
