#!/usr/bin/env python3
"""Fixed synthetic control checks. Never enables live delivery or installs tools.

This runner strips inherited provider credentials; it is not an OS network
sandbox. It executes the reviewed repository's synthetic/local test code only.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def test_environment():
    allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP'}
    return {**{k: v for k, v in os.environ.items() if k in allowed},
            'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


def control_status(returncode, report):
    """A successful subprocess exit alone cannot establish executed coverage."""
    if type(report) is not dict or report.get('schema') != 'aisecure.test-result.v1' or report.get('suite') != 'control':
        return 'BLOCKED'
    for name in ('tests_run', 'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'):
        if type(report.get(name)) is not int or report[name] < 0:
            return 'BLOCKED'
    if report['failures'] or report['errors'] or report['unexpected_successes']:
        return 'FAIL'
    if (returncode != 0 or report['tests_run'] == 0 or report['skipped']
            or report['expected_failures'] or report.get('status') != 'PASS'):
        return 'BLOCKED'
    return 'PASS'


def browser_evidence(returncode, output):
    counts = {key: int(value) for key, value in re.findall(
        r'^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\s*$', output, re.MULTILINE)}
    if set(counts) != {'tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'}:
        return 'BLOCKED', None
    status = ('FAIL' if counts['fail'] else
              'BLOCKED' if returncode != 0 or not counts['tests'] or counts['cancelled']
              or counts['skipped'] or counts['todo'] or counts['pass'] != counts['tests'] else 'PASS')
    return status, {'schema': 'node.tap-summary', **counts}


def provenance():
    try:
        options = {'cwd': ROOT, 'env': test_environment(), 'text': True,
                   'stderr': subprocess.DEVNULL, 'timeout': 10}
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], **options).strip()
        dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], **options))
        return {'source_commit': commit, 'source_dirty': dirty}
    except (OSError, subprocess.SubprocessError):
        return {'source_commit': None, 'source_dirty': None}


def save_report(destination, body):
    """Private, complete, atomic no-clobber publication on one filesystem."""
    descriptor, temporary = tempfile.mkstemp(prefix='.aisecure-check-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        os.unlink(temporary)


def run_checks():
    results = []
    with tempfile.TemporaryDirectory(prefix='aisecure-control-check-') as temporary:
        report_path = Path(temporary) / 'control-tests.json'
        commands = [
            ('control', [sys.executable, str(ROOT / 'tools/run_full_tests.py'),
                         '--suite', 'control', '--report', str(report_path)]),
            ('browser_protocol', ['node', '--test', '--test-reporter=tap', 'browser/aisecure/protocol.test.js'])]
        for name, command in commands:
            try:
                run = subprocess.run(command, cwd=ROOT, env=test_environment(),
                                     capture_output=True, text=True, timeout=240)
                evidence = None
                if name == 'control':
                    try:
                        evidence = json.loads(report_path.read_text())
                    except (OSError, ValueError):
                        pass
                    status = control_status(run.returncode, evidence)
                else:
                    status, evidence = browser_evidence(run.returncode, run.stdout)
                results.append({'stage': name, 'returncode': run.returncode, 'status': status,
                                'test_evidence': evidence, 'output': run.stdout + run.stderr})
            except (OSError, subprocess.SubprocessError):
                results.append({'stage': name, 'returncode': None, 'status': 'BLOCKED',
                                'test_evidence': None, 'output': 'Execution could not be completed.'})
    status = ('FAIL' if any(r['status'] == 'FAIL' for r in results) else
              'BLOCKED' if any(r['status'] != 'PASS' for r in results) else 'PASS')
    return {'schema': 'aisecure.local-checks.v1', 'status': status,
            'local_checks': results, 'local_checks_passed': status == 'PASS',
            **provenance(), 'input_scope': 'bundled_synthetic_tests_only',
            'provider_credentials_inherited': False, 'live_delivery_enabled': False,
            'network_isolation_verified': False, 'production_certified': False,
            'real_browser_enforcement_tested': False, 'vpn_containment_tested': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New report only; existing evidence is never overwritten')
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.exit(2, 'Use a new output file; existing evidence is not replaced.\n')
    result = run_checks()
    try:
        save_report(args.output, json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    except OSError:
        parser.exit(2, 'Report publication failed; existing evidence is not replaced.\n')
    return 0 if result['local_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
