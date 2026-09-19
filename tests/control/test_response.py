import unittest,hashlib,json,secrets,copy
from unittest.mock import patch
from aisecure.control.response import ResponseController,plan,sign,verify_pair
from aisecure.control.vpn import FortiOSPolicyAdapter,PolicyTarget,assess_vpn
from aisecure.control.common import ControlError,canonical
from .helpers import Store,keypair
NOW=2000000000
class Adapter:
    target_id='registered-vpn';deployment_verified=True
    def __init__(self):self.state='enable';self.version=1;self.calls=0;self.fail=False;self.fail_verify=False
    def read_state(self):
        if self.fail_verify and self.calls:raise OSError('provider raw secret')
        return {'target':self.target_id,'status':self.state,'state_hash':hashlib.sha256(canonical([self.state,self.version])).hexdigest()}
    def expected(self,operation):return 'disable' if operation=='disable_registered_rule' else 'enable'
    def apply(self,operation):
        self.calls+=1
        if self.fail:raise OSError('provider raw secret')
        self.state=self.expected(operation);self.version+=1

class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.store=Store().__enter__();self.a=Adapter();self.k1,self.p1=keypair();self.k2,self.p2=keypair()
        self.keys={'primary-person':self.p1,'secondary-person':self.p2}
        self.plan=plan(self.a,'disable_registered_rule',now=NOW)
        self.proofs=[sign(self.k1,self.plan,'primary-person','primary',now=NOW),sign(self.k2,self.plan,'secondary-person','secondary',now=NOW)]
        from pathlib import Path
        self.stop=Path(self.store.temp.name)/'STOP'
        self.controller=ResponseController(self.store.audit,{self.a.target_id:self.a},self.keys,self.stop)
    def tearDown(self):self.store.__exit__()
    def execute(self,**kwargs):return self.controller.execute(kwargs.get('proposal',self.plan),kwargs.get('proofs',self.proofs),consent=kwargs.get('consent',True),now=kwargs.get('now',NOW))
    def test_dual_approval_executes_and_verifies_config(self):
        r=self.execute();self.assertEqual(self.a.calls,1);self.assertEqual(r['execution_state'],'verified');self.assertFalse(r['containment_verified'])
    def test_single_approver_denied(self):
        with self.assertRaises(ControlError):self.execute(proofs=self.proofs[:1])
        self.assertEqual(self.a.calls,0)
    def test_same_key_under_two_names_denied(self):
        self.controller.keys['secondary-person']=self.p1
        same=[self.proofs[0],sign(self.k1,self.plan,'secondary-person','secondary',now=NOW)]
        with self.assertRaises(ControlError):self.execute(proofs=same)
    def test_target_swap_denied(self):
        with self.assertRaises(ControlError):self.execute(proposal={**self.plan,'target':'other-vpn'})
    def test_operation_swap_denied(self):
        with self.assertRaises(ControlError):self.execute(proposal={**self.plan,'operation':'restore_registered_rule'})
    def test_state_swap_denied(self):
        self.a.version+=1;r=self.execute();self.assertEqual(r['execution_state'],'precondition_failed');self.assertEqual(self.a.calls,0)
    def test_expired_denied(self):
        with self.assertRaises(ControlError):self.execute(now=NOW+301)
    def test_no_auto_retry(self):
        self.a.fail=True;r=self.execute();self.assertEqual(r['execution_state'],'delivery_unknown')
        self.execute();self.assertEqual(self.a.calls,1)
    def test_readback_failure_not_verified(self):
        self.a.fail_verify=True;self.assertEqual(self.execute()['execution_state'],'delivery_unknown')
    def test_replay_once(self):self.execute();self.execute();self.assertEqual(self.a.calls,1)
    def test_stop_switch(self):
        self.stop.touch()
        with self.assertRaises(Exception):self.execute()
        self.assertEqual(self.a.calls,0)
    def test_no_operator_acceptance_denied(self):
        self.a.deployment_verified=False
        with self.assertRaises(ControlError):self.execute()
    def test_no_consent_denied(self):
        with self.assertRaises(ControlError):self.execute(consent=False)
    def test_restore_needs_new_approvals(self):
        self.execute();restore=plan(self.a,'restore_registered_rule',now=NOW)
        with self.assertRaises(ControlError):self.execute(proposal=restore)
        proofs=[sign(self.k1,restore,'primary-person','primary',now=NOW),sign(self.k2,restore,'secondary-person','secondary',now=NOW)]
        self.execute(proposal=restore,proofs=proofs);self.assertEqual(self.a.state,'enable')
    def test_bad_signature_denied(self):
        bad=copy.deepcopy(self.proofs);bad[0]['signature']='A'*88
        with self.assertRaises(ControlError):self.execute(proofs=bad)
    def test_opaque_audit(self):
        self.execute();raw=self.store.audit.export(100)
        self.assertNotIn(b'registered-vpn',raw);self.assertNotIn(b'primary-person',raw)
    def test_receipt_removal_detected(self):
        self.execute();self.store.evidence.db.execute('DELETE FROM receipts')
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.a.calls,1)

class VPNAdapterTests(unittest.TestCase):
    def target(self):return PolicyTarget('vpn','vpn.example.invalid',42,expected_uuid='12345678-1234-1234-1234-123456789012')
    def response(self,**kw):return {'status':'success','http_method':'GET','vdom':'root','revision':'abc',
        'results':[{'policyid':42,'uuid':self.target().expected_uuid,'status':'enable','action':'accept',**kw}]}
    def test_registered_rule_only(self):
        a=FortiOSPolicyAdapter(self.target(),'x'*32)
        with patch.object(a,'_request',return_value=self.response()):self.assertEqual(a.read_state()['status'],'enable')
    def test_deny_rule_never_disabled(self):
        a=FortiOSPolicyAdapter(self.target(),'x'*32)
        with patch.object(a,'_request',return_value=self.response(action='deny')):
            with self.assertRaises(ControlError):a.read_state()
    def test_wrong_rule_denied(self):
        a=FortiOSPolicyAdapter(self.target(),'x'*32)
        with patch.object(a,'_request',return_value=self.response(policyid=43)):
            with self.assertRaises(ControlError):a.read_state()
    def test_live_adapter_default_no_write(self):
        a=FortiOSPolicyAdapter(self.target(),'x'*32)
        with self.assertRaises(ControlError):a.apply('disable_registered_rule')
    def test_only_status_field_written(self):
        a=FortiOSPolicyAdapter(self.target(),'x'*32,deployment_verified=True)
        with patch.object(a,'_request') as request:
            a.apply('disable_registered_rule');request.assert_called_once_with('PUT',{'status':'disable'})
    def test_arbitrary_operation_denied(self):
        a=FortiOSPolicyAdapter(self.target(),'x'*32,deployment_verified=True)
        with self.assertRaises(ControlError):a.apply('shell')
    def test_port_bool_rejected(self):
        with self.assertRaises(ControlError):PolicyTarget('vpn','vpn.example.invalid',True,expected_uuid=self.target().expected_uuid)
    def test_unregistered_uuid_rejected(self):
        with self.assertRaises(ControlError):PolicyTarget('vpn','vpn.example.invalid',42)
    def test_unknown_not_safe(self):
        from datetime import datetime,timezone
        date=datetime.fromtimestamp(NOW,timezone.utc);iso=date.isoformat()
        r=assess_vpn({'observed_at':iso,'assets':[{'id':'vpn','vendor':'Example','product':'LabVPN','version':'1.0',
                     'internet_exposed':None,'privileged_path':None,'sensitive_path':None}]},
                    {'observed_at':iso,'advisories':[]},{'dateReleased':iso,'vulnerabilities':[]},now=date)
        self.assertEqual(r['posture']['findings'][0]['status'],'unknown');self.assertFalse(r['containment_verified'])
