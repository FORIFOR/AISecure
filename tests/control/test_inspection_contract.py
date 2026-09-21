"""Public contract checks using real worker, CLI, HTTP and metadata artifacts."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from aisecure.control.common import ControlError
from aisecure.control.example_document import sample_file
from aisecure.control.inspection import inspect_document
from aisecure.control.bundles import redacted_text_preview
from .helpers import office, files


class InspectionContractTests(unittest.TestCase):
    def test_editable_sample_is_deterministic_and_inspected(self):
        sample = sample_file('社外秘：架空の検討メモ')
        self.assertEqual(sample, sample_file('社外秘：架空の検討メモ'))
        raw = base64.b64decode(sample['base64'])
        report = inspect_document(raw, 'xlsx')
        self.assertEqual(report['report_schema'], 'aisecure.document-report.v1')
        self.assertEqual(report['input_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(report['verdict'], 'review')
        self.assertEqual(report['units'], 1)
        self.assertFalse(report['release_authorized'])
        self.assertNotIn('検討メモ', json.dumps(report, ensure_ascii=False))

    def test_block_and_unreadable_do_not_pass(self):
        report = inspect_document(base64.b64decode(sample_file('api_key=synthetic-secret-value')['base64']), 'xlsx')
        self.assertEqual(report['verdict'], 'block')
        broken = inspect_document(b'not a pdf', 'pdf')
        self.assertEqual(broken['coverage'], 'unreadable')
        self.assertNotEqual(broken['verdict'], 'no_findings')

    def test_invalid_input_has_documented_error(self):
        for data, fmt in [(b'', 'pdf'), ('bad', 'xlsx'), (b'x', 'doc')]:
            with self.assertRaises(ControlError): inspect_document(data, fmt)
        for value in ['', '\x00', 'x'*8193]:
            with self.assertRaises(ControlError): sample_file(value)

    def test_split_secret_and_pii_are_not_exposed_by_preview(self):
        for first, last in [('api_', 'key=synthetic-secret-value'), ('private@', 'example.invalid')]:
            xml = f'<worksheet><c><is><r><t>{first}</t></r><r><t>{last}</t></r></is></c></worksheet>'
            result = redacted_text_preview(files(office(extra={'xl/worksheets/sheet2.xml':xml})))
            self.assertTrue(result['preview_withheld'])
            self.assertNotIn(last, result['text'])
            self.assertFalse(result['release_authorized'])

    def test_cli_artifact_and_non_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.xlsx'; output = Path(directory)/'result.json'
            raw = base64.b64decode(sample_file('社外秘：CLIサンプル')['base64']); path.write_bytes(raw)
            command = [sys.executable, '-m', 'aisecure.control.inspect_file', str(path), '--output', str(output)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 3, run.stderr)
            self.assertEqual(json.loads(output.read_text()), inspect_document(raw, 'xlsx'))
            saved = output.read_bytes()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
            self.assertEqual(output.read_bytes(), saved)
            path.write_bytes(base64.b64decode(sample_file('api_key=synthetic-secret-value')['base64']))
            blocked = subprocess.run(command[:4], capture_output=True, text=True)
            self.assertEqual(blocked.returncode, 4)
            self.assertEqual(json.loads(blocked.stdout)['verdict'], 'block')
