import unittest,json
from aisecure.control.analytics import normalize,analyze,Baseline
from aisecure.control.common import ControlError
from aisecure.control.events import EventStore
from .helpers import Store
NOW=2000000000

def event(i,kind='egress',at=None,actor='user',session='session',org='org',**kwargs):
    return normalize({'id':str(i),'at':at or NOW-60,'kind':kind,'actor':actor,'session':session,'asset':'vpn',
        'result':'success',**kwargs},key=b'k'*32,organization=org,source='source',now=NOW)
def rules(events,**kw):return {x['rule'] for x in analyze(events,now=NOW,**kw)['cases']}

class AnalysisTests(unittest.TestCase):
    def test_single_sensitive_transfer_detected(self):self.assertIn('AN-SENSITIVE-EGRESS',rules([event(1,data_class='confidential',target_type='personal')]))
    def test_blocked_transfer_not_leak(self):self.assertFalse(rules([event(1,data_class='confidential',target_type='personal',result='blocked')]))
    def test_low_slow(self):
        data=[event(i,at=NOW-1500+i*600,data_class='internal',target_type='personal') for i in range(3)]
        self.assertIn('AN-LOW-SLOW',rules(data))
    def test_cross_actor_not_combined(self):
        data=[event(i,at=NOW-1500+i*600,actor='user'+str(i),data_class='internal',target_type='personal') for i in range(3)]
        self.assertNotIn('AN-LOW-SLOW',rules(data))
    def chain(self,**kw):
        login=event(1,'vpn_login',at=NOW-900,privileged=True,mfa=False,device_trusted=False)
        read=event(2,'file_read',at=kw.pop('at',NOW-700),data_class='confidential',**kw)
        return [login,read],[(login['organization'],login['asset'])]
    def test_vpn_path(self):
        data,assets=self.chain();self.assertIn('AN-VPN-PRIVILEGE-DATA-PATH',rules(data,risky_assets=assets))
    def test_other_session_not_joined(self):
        data,assets=self.chain(session='other');self.assertNotIn('AN-VPN-PRIVILEGE-DATA-PATH',rules(data,risky_assets=assets))
    def test_other_tenant_not_joined(self):
        data,assets=self.chain(org='other');self.assertNotIn('AN-VPN-PRIVILEGE-DATA-PATH',rules(data,risky_assets=assets))
    def test_file_before_login_not_joined(self):
        data,assets=self.chain(at=NOW-1000);self.assertNotIn('AN-VPN-PRIVILEGE-DATA-PATH',rules(data,risky_assets=assets))
    def test_unknown_controls_not_unsafe_fact(self):
        data,assets=self.chain();data[0]['mfa']=None;data[0]['device_trusted']=None
        self.assertNotIn('AN-VPN-PRIVILEGE-DATA-PATH',rules(data,risky_assets=assets))
    def test_evidence_not_causality(self):
        data,assets=self.chain()
        for c in analyze(data,now=NOW,risky_assets=assets)['cases']:
            self.assertFalse(c['leak_confirmed']);self.assertFalse(c['intrusion_confirmed']);self.assertFalse(c['automatic_action'])
    def test_duplicate_observations_not_counted_twice(self):
        e=event(1);self.assertEqual(analyze([e,e],now=NOW)['events'],1)
    def test_conflicting_duplicate_rejected(self):
        e=event(1)
        with self.assertRaises(ControlError):analyze([e,{**e,'bytes':999}],now=NOW)
    def test_sensitive_values_pseudonymized(self):
        e=event(1,actor='private@example.invalid');self.assertNotIn('private@example.invalid',json.dumps(e))
    def test_secret_field_rejected(self):
        with self.assertRaises(ControlError):event(1,password='sensitive')
    def test_future_rejected(self):
        with self.assertRaises(ControlError):event(1,at=NOW+61)
    def test_boolean_counts_rejected(self):
        with self.assertRaises(ControlError):event(1,bytes=True)
    def test_baseline_needs_enough_days(self):
        with self.assertRaises(ControlError):Baseline('a','o',NOW-200000,(1,)*2)
    def test_robust_baseline_deviation(self):
        e=event(1,bytes=50_000_000);b=Baseline(e['actor'],e['organization'],NOW-200000,(1024,)*20)
        self.assertIn('AN-BASELINE-DEVIATION',rules([e],baselines=[b]))
    def test_baseline_cannot_overlap_evaluation(self):
        e=event(1);b=Baseline(e['actor'],e['organization'],NOW-10,(1024,)*20)
        with self.assertRaises(ControlError):analyze([e],now=NOW,baselines=[b])
    def test_cold_start_explicit(self):self.assertEqual(analyze([],now=NOW)['baseline_status'],'not_configured')
    def test_stale_source(self):self.assertEqual(analyze([],now=NOW,expected_sources=['source'])['missing_or_stale_sources'],['source'])
    def test_repeated_failures_success(self):
        items=[event(i,'vpn_login',at=NOW-600+i*30,result='failure') for i in range(5)]+[event(10,'vpn_login')]
        self.assertIn('AN-LOGIN-AFTER-FAILURES',rules(items))
    def test_persisted_events_encrypted_deduplicated(self):
        with Store() as s:
            store=EventStore(s.audit);value={'id':'a','at':NOW,'kind':'egress','actor':'SENSITIVE-USER','result':'success'}
            store.ingest(value,organization='o',source='s',now=NOW)
            self.assertTrue(store.ingest(value,organization='o',source='s',now=NOW)['duplicate'])
            self.assertEqual(len(store.read()),1)
            self.assertNotIn(b'SENSITIVE-USER',open(s.temp.name+'/gateway.sqlite3','rb').read())
    def test_deleting_index_cannot_hide_events_or_repeat(self):
        with Store() as s:
            store=EventStore(s.audit);value={'id':'a','at':NOW,'kind':'egress','actor':'user','result':'success'}
            store.ingest(value,organization='o',source='s',now=NOW);s.evidence.db.execute('DELETE FROM control_events')
            self.assertEqual(len(store.read()),1);self.assertTrue(store.ingest(value,organization='o',source='s',now=NOW)['duplicate'])
    def test_capacity_is_not_silent_drop(self):
        with Store() as s:
            store=EventStore(s.audit,limit=1)
            value={'id':'a','at':NOW,'kind':'egress','actor':'user','result':'success'}
            store.ingest(value,organization='o',source='s',now=NOW)
            with self.assertRaises(ControlError):store.ingest({**value,'id':'b'},organization='o',source='s',now=NOW)
