"""Dependency-free regressions: missing evidence cannot become pilot readiness."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import check_control, release_gate, run_full_tests


def test_report(**changes):
    return {'schema': 'aisecure.test-result.v1', 'suite': 'control', 'status': 'PASS',
            'tests_run': 3, 'failures': 0, 'errors': 0, 'skipped': 0,
            'expected_failures': 0, 'unexpected_successes': 0, **changes}


def tap(**changes):
    counts = {'tests': 7, 'pass': 7, 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0, **changes}
    return '\n'.join(f'# {name} {count}' for name, count in counts.items()) + '\n'


class StructuredSuiteTests(unittest.TestCase):
    def run_case(self, method):
        case = type('SyntheticCheck', (unittest.TestCase,), {'runTest': method})
        return run_full_tests.run_suite(unittest.TestSuite([case()]), stream=io.StringIO())

    def test_pass_requires_executed_checks(self):
        result = self.run_case(lambda _: None)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['tests_run'], 1)
        self.assertEqual(run_full_tests.run_suite(unittest.TestSuite(), stream=io.StringIO())['status'], 'BLOCKED')

    def test_skipped_suite_is_blocked_even_when_unittest_succeeds(self):
        def skipped(case): case.skipTest('synthetic missing dependency')
        result = self.run_case(skipped)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['skipped'], 1)

    def test_failed_assertion_and_error_are_failures(self):
        def failed(case): case.fail('synthetic failure')
        def error(_): raise ValueError('synthetic failure')
        for method in (failed, error):
            self.assertEqual(self.run_case(method)['status'], 'FAIL')

    def test_expected_failure_and_unexpected_success_never_pass(self):
        @unittest.expectedFailure
        def known_failure(case): case.fail('documented unresolved case')
        @unittest.expectedFailure
        def unexpected_success(_): pass
        blocked = self.run_case(known_failure)
        self.assertEqual(blocked['status'], 'BLOCKED')
        self.assertEqual(blocked['expected_failures'], 1)
        failed = self.run_case(unexpected_success)
        self.assertEqual(failed['status'], 'FAIL')
        self.assertEqual(failed['unexpected_successes'], 1)
        self.assertEqual(check_control.control_status(0, {**failed, 'suite': 'control'}), 'FAIL')
        self.assertEqual(check_control.control_status(0, {**blocked, 'suite': 'control'}), 'BLOCKED')

    def test_control_evidence_is_strict_and_not_exit_code_only(self):
        self.assertEqual(check_control.control_status(0, test_report()), 'PASS')
        for report in (None, {}, test_report(schema='unknown'), test_report(suite='full'),
                       test_report(tests_run=0), test_report(skipped=1), test_report(tests_run=True),
                       test_report(failures=-1), test_report(status='BLOCKED')):
            self.assertEqual(check_control.control_status(0, report), 'BLOCKED')
        self.assertEqual(check_control.control_status(1, test_report()), 'BLOCKED')
        self.assertEqual(check_control.control_status(1, test_report(errors=1)), 'FAIL')

    def test_browser_skips_empty_todo_missing_and_cancelled_are_not_pass(self):
        self.assertEqual(check_control.browser_evidence(0, tap())[0], 'PASS')
        for output in ('', 'process succeeded', tap(tests=0, **{'pass': 0}), tap(skipped=7, **{'pass': 0}),
                       tap(todo=1), tap(cancelled=1), tap(**{'pass': 6})):
            self.assertEqual(check_control.browser_evidence(0, output)[0], 'BLOCKED')
        self.assertEqual(check_control.browser_evidence(1, tap(fail=1, **{'pass': 6}))[0], 'FAIL')


class PilotRunnerTests(unittest.TestCase):
    def run_with(self, report=None, *, fail=False):
        def run(command, **kwargs):
            self.assertEqual(kwargs['cwd'], check_control.ROOT)
            self.assertNotIn('OPENAI_API_KEY', kwargs['env'])
            self.assertNotIn('OKTA_ACCESS_TOKEN', kwargs['env'])
            self.assertNotIn('AISECURE_GATEWAY_KEY', kwargs['env'])
            self.assertNotIn('PYTHONPATH', kwargs['env'])
            self.assertNotIn('NODE_OPTIONS', kwargs['env'])
            if fail: raise subprocess.TimeoutExpired(command, 240)
            if '--report' in command:
                if report is not None:
                    Path(command[command.index('--report') + 1]).write_text(json.dumps(report))
                return subprocess.CompletedProcess(command, 0, '', '')
            return subprocess.CompletedProcess(command, 0, tap(), '')
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'synthetic-secret', 'OKTA_ACCESS_TOKEN': 'synthetic-token',
                                     'AISECURE_GATEWAY_KEY': 'synthetic-key', 'PYTHONPATH': 'untrusted', 'NODE_OPTIONS': '--inspect'}), \
             patch('tools.check_control.subprocess.run', side_effect=run) as execute, \
             patch('tools.check_control.provenance', return_value={'source_commit': 'a'*40, 'source_dirty': False}):
            result = check_control.run_checks()
        self.assertEqual(execute.call_count, 2)
        self.assertNotIn('synthetic-secret', json.dumps(result))
        self.assertFalse(result['live_delivery_enabled'])
        self.assertFalse(result['production_certified'])
        self.assertFalse(result['network_isolation_verified'])
        return result

    def test_missing_report_is_blocked(self):
        self.assertEqual(self.run_with()['status'], 'BLOCKED')

    def test_skip_and_timeout_are_blocked(self):
        self.assertFalse(self.run_with(test_report(skipped=1))['local_checks_passed'])
        self.assertEqual(self.run_with(fail=True)['status'], 'BLOCKED')

    def test_real_structured_success_passes_only_local_checks(self):
        self.assertTrue(self.run_with(test_report())['local_checks_passed'])

    def test_provenance_uses_repository_root_not_callers_directory(self):
        with patch('tools.check_control.subprocess.check_output', side_effect=['a'*40+'\n', '']) as call:
            self.assertEqual(check_control.provenance(), {'source_commit': 'a'*40, 'source_dirty': False})
            for entry in call.call_args_list:
                self.assertEqual(entry.kwargs['cwd'], check_control.ROOT)

    def test_no_live_option_or_existing_output_can_start_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'prior.json'
            output.write_text('original evidence')
            with patch('tools.check_control.run_checks') as run:
                with self.assertRaises(SystemExit) as raised:
                    check_control.main(['--output', str(output)])
                self.assertEqual(raised.exception.code, 2)
                run.assert_not_called()
                with self.assertRaises(SystemExit):
                    check_control.main(['--output', str(output), '--live'])
                run.assert_not_called()
            self.assertEqual(output.read_text(), 'original evidence')

    def test_report_is_private_atomic_and_never_replaces_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'result.json'
            check_control.save_report(output, '{"complete":true}')
            if os.name == 'posix': self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            link = root / 'linked.json'
            link.symlink_to(output)
            with self.assertRaises(FileExistsError): check_control.save_report(link, 'replacement')
            self.assertEqual(output.read_text(), '{"complete":true}')
            failed = root / 'failed.json'
            with patch('tools.check_control.os.fsync', side_effect=OSError('synthetic disk failure')):
                with self.assertRaises(OSError): check_control.save_report(failed, 'partial')
            self.assertFalse(failed.exists())
            self.assertEqual(list(root.glob('.aisecure-check-*')), [])

    def test_concurrent_report_publication_has_one_winner(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'result.json'
            def attempt(body):
                try: check_control.save_report(output, body); return True
                except FileExistsError: return False
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(attempt, ['first', 'second'])), 1)
            self.assertIn(output.read_text(), {'first', 'second'})


class LiveEvidenceGateTests(unittest.TestCase):
    def manifest(self, scope, environment):
        at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        return {'scope': scope, 'evidence': [
            {'gate': gate, 'status': 'pass', 'environment': environment, 'reviewer': 'named-reviewer',
             'sha256': 'a'*64, 'executed_at': at} for gate in release_gate.REQUIRED[scope]]}

    def test_invalid_environment_types_and_blank_values_cannot_pass(self):
        for scope in release_gate.REQUIRED:
            for environment in (None, False, True, 123, 1.5, [], {}, '', '   ', 'site\nsecret'):
                with self.subTest(scope=scope, environment=environment), self.assertRaises(ValueError):
                    release_gate.missing(self.manifest(scope, environment))

    def test_placeholder_environment_is_case_and_space_insensitive(self):
        for scope in release_gate.REQUIRED:
            for environment in ('demo', ' DEMO ', 'Synthetic', ' MOCK ', 'unknown', 'UNKNOWN', 'ＤＥＭＯ', 'Ｓｙｎｔｈｅｔｉｃ'):
                self.assertEqual(set(release_gate.missing(self.manifest(scope, environment))), release_gate.REQUIRED[scope])

    def test_named_environment_is_completeness_only(self):
        for scope in release_gate.REQUIRED:
            self.assertEqual(release_gate.missing(self.manifest(scope, 'approved-lab-01')), [])

    def test_malformed_scope_unknown_gate_and_nonpass_remain_incomplete(self):
        for report in (None, [], {'scope': []}, {'scope': 'unrecognized'}):
            with self.assertRaises(ValueError): release_gate.missing(report)
        report = self.manifest('managed_pilot', 'approved-lab-01')
        report['evidence'][0]['gate'] = 'not_a_gate'
        with self.assertRaises(ValueError): release_gate.missing(report)
        report = self.manifest('managed_pilot', 'approved-lab-01')
        report['evidence'][0]['status'] = 'not_run'
        self.assertTrue(release_gate.missing(report))

    def test_cli_rejects_invalid_and_marks_synthetic_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest.json'
            for environment, expected in ((None, 3), (' DEMO ', 2), ('approved-lab-01', 0)):
                path.write_text(json.dumps(self.manifest('managed_pilot', environment)))
                run = subprocess.run([sys.executable, str(check_control.ROOT / 'tools/release_gate.py'), str(path)],
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, expected)
                if expected != 3:
                    self.assertFalse(json.loads(run.stdout)['evidence_authenticity_independently_verified'])


if __name__ == '__main__':
    unittest.main()
