"""Structured test evidence: skipped or empty security suites never pass."""
from pathlib import Path
import argparse
import json
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SCHEMA = 'aisecure.test-result.v1'


def run_suite(suite, *, stream=None):
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2, stream=stream).run(suite)
    status = ('FAIL' if not result.wasSuccessful() else
              'BLOCKED' if result.skipped or result.expectedFailures or result.testsRun == 0 else 'PASS')
    return {'schema': SCHEMA, 'status': status, 'tests_run': result.testsRun,
            'failures': len(result.failures), 'errors': len(result.errors),
            'skipped': len(result.skipped),
            'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses),
            'duration_seconds': round(time.monotonic() - started, 2),
            'scope': 'automated_synthetic_tests_not_live_enterprise_validation'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=Path('/tmp/aisecure-tests.json'))
    parser.add_argument('--suite', choices=('full', 'control'), default='full')
    args = parser.parse_args(argv)
    start = ROOT / ('tests/control' if args.suite == 'control' else 'tests')
    suite = unittest.TestLoader().discover(str(start), top_level_dir=str(ROOT) if args.suite == 'control' else None)
    report = {**run_suite(suite), 'suite': args.suite}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
