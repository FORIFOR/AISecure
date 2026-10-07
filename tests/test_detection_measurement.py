"""Regression contracts for customer-local evaluation evidence, all synthetic."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools import measure_detection as m


def sample(**changes):
    return {'id': 'case-1', 'category': 'credential_example', 'expect': 'detect',
            'text': 'password = synthetic-value', **changes}


class CorpusContractTests(unittest.TestCase):
    def test_typo_label_never_becomes_negative(self):
        for label in ('detcet', 'Clean', '', None, True, 1, [], {}):
            with self.subTest(label=label), self.assertRaises(ValueError):
                m.measure([sample(expect=label)])

    def test_empty_or_non_list_corpus_rejected(self):
        for cases in ([], None, {}, (sample(),)):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                m.measure(cases)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            m.measure([sample(), sample(category='different')])

    def test_ambiguous_or_missing_text_rejected(self):
        for changes in ({'parts': ['ignored']}, {'text': None}, {'text': ''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                m.measure([sample(**changes)])
        case = sample()
        del case['text']
        with self.assertRaises(ValueError):
            m.measure([case])

    def test_split_tokens_match_without_mutating_input(self):
        case = sample()
        del case['text']
        case['parts'] = ['password = ', 'synthetic-value']
        original = copy.deepcopy(case)
        self.assertEqual(m.measure([case])['detected'], 1)
        self.assertEqual(case, original)

    def test_malformed_parts_rejected(self):
        for parts in ('password', [], [1], ['x'] * 65):
            case = sample()
            del case['text']
            case['parts'] = parts
            with self.subTest(parts=parts), self.assertRaises(ValueError):
                m.measure([case])

    def test_strict_fields_and_safe_identifiers(self):
        for changes in ({'extra': 'unintended'}, {'id': ''}, {'id': 'line\nbreak'},
                        {'category': '\x1b[31m'}, {'category': 'a' * 81},
                        {'note': []}, {'text': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                m.measure([sample(**changes)])
        for field in ('id', 'category', 'expect'):
            case = sample()
            del case[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.measure([case])

    def test_text_and_case_limits(self):
        with mock.patch.object(m, 'MAX_CASES', 1), self.assertRaises(ValueError):
            m.measure([sample(), sample(id='case-2')])
        with self.assertRaises(ValueError):
            m.measure([sample(text='x' * (m.MAX_TEXT_CHARS + 1))])
        case = sample()
        del case['text']
        case['parts'] = ['x' * m.MAX_TEXT_CHARS, 'x']
        with self.assertRaises(ValueError):
            m.measure([case])

    def test_mixed_category_has_unambiguous_denominators(self):
        report = m.measure([sample(), sample(id='miss', text='ordinary text'),
                            sample(id='fp', expect='clean'),
                            sample(id='tn', expect='clean', text='ordinary text')])
        self.assertEqual(report['per_category']['credential_example'],
                         {'total': 4, 'detected': 2, 'positives': 2, 'negatives': 2,
                          'true_positives': 1, 'false_positives': 1})
        self.assertEqual((report['recall'], report['precision'], report['false_positive_rate']),
                         (0.5, 0.5, 0.5))

    def test_absent_denominators_remain_unknown(self):
        positive = m.measure([sample(text='ordinary text')])
        self.assertIsNone(positive['false_positive_rate'])
        self.assertIsNone(positive['precision'])
        self.assertIsNone(m.measure([sample(expect='clean')])['recall'])

    def test_measure_never_asserts_input_classification_or_acceptance(self):
        report = m.measure([sample()])
        self.assertEqual(report['corpus'], 'unverified')
        self.assertFalse(report['classification_verified'])
        self.assertFalse(report['is_real_world_measurement'])
        self.assertFalse(report['production_certified'])

    def test_historical_corpus_metrics_unchanged(self):
        cases, digest = m.load_corpus(m.CORPUS)
        report = m.measure(cases)
        historical = json.loads((m.CORPUS.parent / 'detection-measurement.json').read_text())
        for key in ('cases', 'positives', 'negatives', 'detected', 'missed',
                    'false_positives', 'recall', 'precision', 'false_positive_rate',
                    'missed_ids', 'false_positive_cases'):
            self.assertEqual(report[key], historical[key], key)
        self.assertEqual(digest, hashlib.sha256(m.CORPUS.read_bytes()).hexdigest())


class MeasurementCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.corpus = self.root / 'input.jsonl'
        self.out = self.root / 'report.json'
        self.corpus.write_text(json.dumps(sample()) + '\n', encoding='utf-8')

    def run_cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return m.main(list(args))

    def test_custom_input_provenance_and_no_source_text(self):
        self.assertEqual(self.run_cli('--corpus', str(self.corpus), '--out', str(self.out)), 0)
        report = json.loads(self.out.read_text())
        self.assertEqual(report['corpus'], 'custom_unverified')
        self.assertEqual(report['corpus_sha256'], hashlib.sha256(self.corpus.read_bytes()).hexdigest())
        self.assertEqual(report['schema'], 'aisecure.detection-measurement.v2')
        self.assertIn('source_commit', report)
        self.assertIn('source_dirty', report)
        self.assertIn('measured_at', report)
        self.assertIsNone(report['acceptance_passed'])
        self.assertNotIn('synthetic-value', self.out.read_text())
        self.assertNotIn(str(self.corpus), self.out.read_text())
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)

    def test_default_bundled_scope_is_limited(self):
        self.assertEqual(self.run_cli('--out', str(self.out)), 0)
        report = json.loads(self.out.read_text())
        self.assertEqual(report['corpus'], 'bundled_synthetic')
        self.assertEqual(report['measurement_scope'], 'supplied_text_patterns_only')
        self.assertFalse(report['classification_verified'])
        self.assertFalse(report['production_certified'])

    def test_existing_output_preserved(self):
        self.out.write_text('prior evidence')
        with self.assertRaises(SystemExit) as caught:
            self.run_cli('--out', str(self.out))
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.out.read_text(), 'prior evidence')

    def test_symlink_output_preserved(self):
        target = self.root / 'target'
        target.write_text('prior evidence')
        self.out.symlink_to(target)
        with self.assertRaises(SystemExit):
            self.run_cli('--out', str(self.out))
        self.assertTrue(self.out.is_symlink())
        self.assertEqual(target.read_text(), 'prior evidence')

    def test_dangling_symlink_not_replaced(self):
        self.out.symlink_to(self.root / 'missing')
        with self.assertRaises(SystemExit):
            self.run_cli('--out', str(self.out))
        self.assertTrue(self.out.is_symlink())

    def test_publication_failure_does_not_leave_partial_report(self):
        with mock.patch('tools.check_control.os.link', side_effect=OSError('failure')):
            with self.assertRaises(SystemExit) as caught:
                self.run_cli('--out', str(self.out))
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.root.glob('.aisecure-check-*')), [])

    def test_publication_race_cannot_overwrite_evidence(self):
        real_link = os.link
        def race(source, destination):
            destination.write_text('winning evidence')
            return real_link(source, destination)
        with mock.patch('tools.check_control.os.link', side_effect=race):
            with self.assertRaises(SystemExit):
                self.run_cli('--out', str(self.out))
        self.assertEqual(self.out.read_text(), 'winning evidence')
        self.assertEqual(list(self.root.glob('.aisecure-check-*')), [])

    def test_invalid_corpus_never_publishes_and_does_not_echo_payload(self):
        self.corpus.write_text('{"private-payload-that-must-not-appear":', encoding='utf-8')
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as caught:
            m.main(['--corpus', str(self.corpus), '--out', str(self.out)])
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.out.exists())
        self.assertNotIn('private-payload', error.getvalue())
        self.assertNotIn(str(self.corpus), error.getvalue())

    def test_duplicate_json_keys_rejected(self):
        self.corpus.write_text('{"id":"one","id":"two"}\n')
        with self.assertRaises(ValueError):
            m.load_corpus(self.corpus)

    def test_unicode_line_separators_inside_text_are_valid_jsonl(self):
        for separator in ('\u2028', '\u2029', '\u0085'):
            with self.subTest(separator=repr(separator)):
                text = 'before' + separator + 'after'
                self.corpus.write_text(json.dumps(sample(text=text), ensure_ascii=False) + '\r\n')
                self.assertEqual(m.load_corpus(self.corpus)[0][0]['text'], text)

    def test_deeply_nested_json_is_safe_invalid_input(self):
        self.corpus.write_text('[' * 10000 + '0' + ']' * 10000)
        with self.assertRaises(SystemExit) as caught:
            self.run_cli('--corpus', str(self.corpus), '--out', str(self.out))
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(self.out.exists())

    def test_non_json_unicode_whitespace_is_not_a_blank_record(self):
        self.corpus.write_text(json.dumps(sample()) + '\n\u0085\n')
        with self.assertRaises(ValueError):
            m.load_corpus(self.corpus)

    def test_invalid_utf8_rejected(self):
        self.corpus.write_bytes(b'\xff')
        with self.assertRaises(ValueError):
            m.load_corpus(self.corpus)

    def test_oversized_input_rejected_before_parsing(self):
        with mock.patch.object(m, 'MAX_CORPUS_BYTES', 1), self.assertRaises(ValueError):
            m.load_corpus(self.corpus)

    def test_too_many_json_lines_rejected(self):
        self.corpus.write_text((json.dumps(sample()) + '\n') * 2)
        with mock.patch.object(m, 'MAX_CASES', 1), self.assertRaises(ValueError):
            m.load_corpus(self.corpus)

    def test_blank_lines_allowed_but_empty_corpus_rejected(self):
        self.corpus.write_text('\n' + json.dumps(sample()) + '\n\n')
        self.assertEqual(len(m.load_corpus(self.corpus)[0]), 1)
        self.corpus.write_text('\n \n')
        with self.assertRaises(ValueError):
            m.load_corpus(self.corpus)

    def test_unreadable_corpus_has_safe_error(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as caught:
            m.main(['--corpus', str(self.root / 'customer-name-missing.jsonl')])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn('customer-name', error.getvalue())


if __name__ == '__main__':
    unittest.main()
