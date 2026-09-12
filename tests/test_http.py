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
        self.assertEqual(len(s['snapshot']['events']),148)
        fid=s['findings'][0]['id'];sid=s['snapshot_id']
        status,body,_=self.request('/api/plan',{'snapshot_id':sid,'finding_id':fid})
        self.assertEqual(status,200);p=json.loads(body)
        status,body,_=self.request('/api/approve',{'proposal_id':p['proposal_id'],'snapshot_id':sid,'confirmation':'SIMULATE ONLY','reason':'対象の根拠と業務への影響を確認しました。'})
        self.assertEqual(status,200);self.assertFalse(json.loads(body)['executed'])
        _,body,_=self.request('/api/state');self.assertTrue(json.loads(body)['audit']['valid'])

    def test_export_retains_simulation_label(self):
        status,body,_=self.request('/api/export')
        self.assertEqual(status,200)
        self.assertFalse(json.loads(body)['real_actions_enabled'])


if __name__=='__main__': unittest.main()
