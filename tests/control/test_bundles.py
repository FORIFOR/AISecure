import json,secrets,unittest
from aisecure.control.bundles import BundleGateway,sign_bundle,wire,redacted_text_preview
from aisecure.control.common import ControlError
from .helpers import Store,keypair,files,office

class Transport:
    def __init__(self,fail=False):self.calls=[];self.fail=fail
    def send(self,body):
        self.calls.append(body)
        if self.fail:raise OSError('SENSITIVE-SERVER-RESPONSE')
        return 'OUTPUT-NOT-FOR-AUDIT'

class BundleTests(unittest.TestCase):
    def setUp(self):
        self.store=Store().__enter__();self.private,self.public=keypair();self.transport=Transport()
        self.gateway=BundleGateway(self.store.audit,self.public,'demo-model',self.transport,'org')
        self.id=secrets.token_hex(16);self.files=files();self.question='Summarize the public report.'
    def tearDown(self):self.store.__exit__()
    def proof(self,**kw):return sign_bundle(self.private,kw.get('question',self.question),kw.get('files',self.files),kw.get('model','demo-model'),self.id,'org')
    def send(self,**kw):return self.gateway.send(kw.get('question',self.question),kw.get('files',self.files),self.id,kw.get('label',self.proof()),consent=kw.get('consent',True))
    def test_unknown_never_sent(self):
        r=self.gateway.send(self.question,self.files,self.id,consent=True);self.assertEqual(r['execution_state'],'prevented_in_gateway');self.assertFalse(self.transport.calls)
    def test_exact_approved_bundle_sent(self):
        r=self.send();self.assertEqual(r['execution_state'],'demo_received');self.assertEqual(self.transport.calls[0],wire(self.question,self.files,'demo-model'))
    def test_question_swap_denied(self):
        with self.assertRaises(ControlError):self.send(question='different',label=self.proof())
        self.assertFalse(self.transport.calls)
    def test_file_swap_denied(self):
        with self.assertRaises(ControlError):self.send(files=files(office(text='different')),label=self.proof())
        self.assertFalse(self.transport.calls)
    def test_signature_does_not_override_secret(self):
        self.files=files(office(text='api_key=synthetic-secret-bundle'))
        r=self.send();self.assertEqual(r['execution_state'],'prevented_in_gateway');self.assertFalse(self.transport.calls)
    def test_signature_does_not_override_partial(self):
        self.files=files(office(extra={'xl/media/test.png':b'fake'}));self.assertEqual(self.send()['execution_state'],'prevented_in_gateway')
    def test_consent_required(self):
        with self.assertRaises(ControlError):self.send(consent=False)
    def test_single_dispatch_on_repeat(self):
        self.send();r=self.send();self.assertTrue(r['replayed']);self.assertEqual(len(self.transport.calls),1)
    def test_receipt_deletion_does_not_repeat_dispatch(self):
        self.send();self.store.evidence.db.execute('DELETE FROM receipts')
        with self.assertRaises(ValueError):self.send()
        self.assertEqual(len(self.transport.calls),1)
    def test_delivery_unknown_not_resent(self):
        self.transport.fail=True;r=self.send();self.assertEqual(r['execution_state'],'delivery_unknown')
        self.send();self.assertEqual(len(self.transport.calls),1)
    def test_logs_no_file_text_or_output(self):
        self.send();raw=self.store.audit.export(100)
        for secret in (b'Public information',b'OUTPUT-NOT-FOR-AUDIT',self.files[0]['base64'].encode(),b'Summarize'):
            self.assertNotIn(secret,raw)
        db=open(self.store.temp.name+'/gateway.sqlite3','rb').read();self.assertNotIn(b'Public information',db)
    def test_no_hidden_context_or_tools(self):
        payload=json.loads(wire(self.question,self.files,'demo-model'));self.assertEqual(payload['tools'],[])
        self.assertNotIn('previous_response_id',payload);self.assertNotIn('file_id',str(payload))
    def test_live_requires_network_isolation(self):
        with self.assertRaises(ControlError):BundleGateway(self.store.audit,self.public,'model',self.transport,'org',live=True)
    def test_preview_not_automatic_authorization(self):
        result=redacted_text_preview(files(office(text='email private@example.invalid api_key=synthetic-secret-value')))
        self.assertNotIn('private@example.invalid',result['text']);self.assertNotIn('synthetic-secret-value',result['text'])
        self.assertFalse(result['release_authorized']);self.assertFalse(result['original_modified'])
    def test_metadata_bounded(self):
        self.send()
        for r in self.store.evidence.history():self.assertLess(len(json.dumps(r).encode()),2200)
    def test_stop_switch(self):
        from pathlib import Path
        from aisecure.safety import EmergencyStop
        stop=Path(self.store.temp.name)/'STOP';stop.touch();self.gateway.stop=EmergencyStop(stop)
        with self.assertRaises(Exception):self.send()
        self.assertFalse(self.transport.calls)

    def test_managed_inspection_mode_never_sends(self):
        self.gateway.delivery_enabled=False
        self.assertEqual(self.send()['execution_state'],'prevented_in_gateway')
        self.assertFalse(self.transport.calls)
