from __future__ import annotations
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from aisecure.server import LocalServer
from aisecure.store import Store


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = Store(cls.temp.name)
        cls.server = LocalServer(cls.store, 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = cls.server.origin

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
        cls.store.close(); cls.temp.cleanup()

    def request(self,path,body=None,auth=True,headers=None):
        h={'Authorization':'Bearer '+self.server.token} if auth else {}
        if body is not None: h['Content-Type']='application/json'
        h.update(headers or {})
        data=json.dumps(body).encode() if body is not None else None
        req=urllib.request.Request(self.base+path,data=data,headers=h)
        try:
            with urllib.request.urlopen(req,timeout=3) as r: return r.status,r.read(),r.headers
        except urllib.error.HTTPError as e: return e.code,e.read(),e.headers

    def test_state_exposes_the_active_detection_config(self):
        status,body,_=self.request('/api/state')
        config=json.loads(body)['rule_config']
        self.assertEqual(status,200)
        self.assertEqual(config['values'],self.store.config.as_dict())
        self.assertTrue(all(p['description'] for p in config['parameters']))

    def test_state_reports_unknown_read_sizes(self):
        self.request('/api/demo',{'confirm':'LOAD SYNTHETIC DATA'})
        coverage=json.loads(self.request('/api/state')[1])['coverage']
        self.assertIn('unknown_read_sizes',coverage)
        self.assertEqual(coverage['provenance'],[])

    def test_api_requires_auth(self):
        self.assertEqual(self.request('/api/state',auth=False)[0],401)

    def test_wrong_token(self):
        self.assertEqual(self.request('/api/state',headers={'Authorization':'Bearer wrong'})[0],401)

    def test_unicode_token_rejected_without_server_crash(self):
        self.assertEqual(self.request('/api/state',headers={'Authorization':'Bearer \xe9'})[0],401)

    def test_wrong_host(self):
        self.assertEqual(self.request('/api/state',headers={'Host':'evil.example'})[0],403)

    def test_wrong_origin(self):
        self.assertEqual(self.request('/api/state',headers={'Origin':'https://evil.example'})[0],403)

    def test_cross_site_fetch(self):
        self.assertEqual(self.request('/api/state',headers={'Sec-Fetch-Site':'cross-site'})[0],403)

    def test_content_type_enforced(self):
        self.assertEqual(self.request('/api/demo',{'confirm':'LOAD SYNTHETIC DATA'},headers={'Content-Type':'text/plain'})[0],415)

    def test_demo_confirmation_required(self):
        self.assertEqual(self.request('/api/demo',{'confirm':'yes'})[0],400)

    def test_ui_assets_served(self):
        for path, ctype in [('/','text/html'),('/style.css','text/css'),('/app.js','text/javascript'),('/i18n.js','text/javascript')]:
            status,body,headers=self.request(path,auth=False)
            self.assertEqual(status,200,path)
            self.assertIn(ctype,headers['Content-Type'],path)
        self.assertIn(b'nav.overview',self.request('/i18n.js',auth=False)[1])

    def test_path_traversal_not_served(self):
        self.assertEqual(self.request('/../aisecure/store.py')[0],404)

    def test_secret_file_not_served(self):
        self.assertEqual(self.request('/master.key')[0],404)

    def test_query_tokens_rejected(self):
        self.assertEqual(self.request('/api/state?token=anything')[0],400)

    def test_security_headers_and_no_cors(self):
        status,_,headers=self.request('/')
        self.assertEqual(status,200)
        self.assertEqual(headers['X-Frame-Options'],'DENY')
        self.assertIn("script-src 'self'",headers['Content-Security-Policy'])
        self.assertIsNone(headers.get('Access-Control-Allow-Origin'))

    def test_full_simulated_workflow(self):
        status,_,_=self.request('/api/demo',{'confirm':'LOAD SYNTHETIC DATA'})
        self.assertEqual(status,200)
        _,body,_=self.request('/api/state');s=json.loads(body)
        self.assertEqual(s['snapshot']['event_counts']['total'],148)
        self.assertNotIn('events',s['snapshot'])
        fid=s['findings'][0]['id'];sid=s['snapshot_id']
        status,body,_=self.request('/api/plan',{'snapshot_id':sid,'finding_id':fid})
        self.assertEqual(status,200);p=json.loads(body)
        status,body,_=self.request('/api/approve',{'proposal_id':p['proposal_id'],'snapshot_id':sid,'confirmation':'SIMULATE ONLY','reason':'対象の根拠と業務への影響を確認しました。'})
        self.assertEqual(status,200);self.assertFalse(json.loads(body)['executed'])
        _,body,_=self.request('/api/state');self.assertTrue(json.loads(body)['audit']['valid'])

    def test_state_omits_the_event_list(self):
        self.request('/api/demo',{'confirm':'LOAD SYNTHETIC DATA'})
        snapshot=json.loads(self.request('/api/state')[1])['snapshot']
        self.assertFalse(snapshot['events_included'])
        self.assertNotIn('events',snapshot)
        self.assertEqual(snapshot['event_counts']['login'],2)

    def test_export_includes_the_event_list(self):
        self.request('/api/demo',{'confirm':'LOAD SYNTHETIC DATA'})
        snapshot=json.loads(self.request('/api/export')[1])['snapshot']
        self.assertTrue(snapshot['events_included'])
        self.assertEqual(len(snapshot['events']),148)

    def test_submitted_provenance_is_never_marked_verified(self):
        snapshot={'schema_version':1,'as_of':'2026-09-01T12:00:00Z',
                  'provenance':[{'label':'corp-audit.csv','sha256':'0'*64,'rows_read':120000,
                                 'rows_imported':120000,'connector':'file-import'}],
                  'assets':[{'id':'edge-vpn-01','kind':'vpn','internet_exposed':True,'privileged_path':True,
                             'sensitive_path':True,'patch_state':'applied',
                             'observed_at':'2026-09-01T09:00:00Z','vulnerability':None}],'events':[]}
        self.assertEqual(self.request('/api/ingest',snapshot)[0],200)
        sources=json.loads(self.request('/api/state')[1])['snapshot']['provenance']
        self.assertEqual(len(sources),1)
        self.assertFalse(sources[0]['verified'])

    def test_export_retains_simulation_label(self):
        status,body,_=self.request('/api/export')
        self.assertEqual(status,200)
        self.assertFalse(json.loads(body)['real_actions_enabled'])


if __name__=='__main__': unittest.main()
