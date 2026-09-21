"""Machine contracts validated with the standard Draft 2020-12 validator."""
import base64
import copy
import json
from pathlib import Path
import secrets
import unittest
try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError as exc:
    raise unittest.SkipTest("jsonschema is required: install .[test]") from exc
from aisecure.control.inspection import inspect_document, report_schema
from aisecure.control.example_document import sample_file
from aisecure.control.bundles import BundleGateway, sign_bundle
from aisecure.gateway import DemoTransport
from .helpers import Store, keypair


class SchemaTests(unittest.TestCase):
    def test_document_outcomes_and_invalid_contracts(self):
        schema = report_schema(); Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for value in ['Public synthetic sample', '社外秘：架空', 'api_key=synthetic-secret-value']:
            report = inspect_document(base64.b64decode(sample_file(value)['base64']), 'xlsx')
            validator.validate(report)
            for field, bad in [('report_schema', 'future-version'), ('release_authorized', True), ('input_sha256','bad')]:
                modified = {**report, field: bad}
                with self.assertRaises(ValidationError): validator.validate(modified)
            with self.assertRaises(ValidationError): validator.validate({**report, 'text':value})
        validator.validate(inspect_document(b'bad pdf','pdf'))
        changed = {**report, 'verdict':'no_findings'}
        with self.assertRaises(ValidationError): validator.validate(changed)

    def test_bundle_and_prior_working_tree_fixture(self):
        schema = report_schema('bundle'); Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        old = Path(__file__).resolve().parents[2]/'docs/quality/evidence/2026-09-19/report-390.json'
        validator.validate(json.loads(old.read_text()))
        with Store() as store:
            private, public = keypair()
            gateway = BundleGateway(store.audit, public, 'demo', DemoTransport(), 'org')
            for value in ['Public synthetic sample', '社外秘：架空', 'api_key=synthetic-secret-value']:
                files = [sample_file(value)]; request_id = secrets.token_hex(16)
                for label in [None, sign_bundle(private,'q',files,'demo',request_id,'org')]:
                    report = gateway.check('q',files,request_id,label)
                    validator.validate(report)
                    with self.assertRaises(ValidationError): validator.validate({**report, 'question':'raw'})
                    modified = copy.deepcopy(report); modified['documents'][0]['release_authorized'] = True
                    with self.assertRaises(ValidationError): validator.validate(modified)
                    if report['decision'] != 'allow' and report['documents'][0]['verdict'] != 'no_findings':
                        unsafe = {**report, 'decision':'allow', 'classification':'public', 'release_authorized':True}
                        with self.assertRaises(ValidationError): validator.validate(unsafe)
