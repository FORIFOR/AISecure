import asyncio,io,json,struct,secrets,unittest

try:
    import httpx
except ImportError as exc:  # pragma: no cover - httpx ships in the test extra only
    raise unittest.SkipTest("httpx が未インストールです: pip install '.[test]'") from exc

from aisecure.control.service import App
from aisecure.control.bundles import BundleGateway,sign_bundle
from aisecure.control.native import handle,read_message,write_message
from aisecure.control.common import ControlError
from aisecure.gateway import DemoTransport
from .helpers import Store,keypair,files,office

class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store=Store().__enter__();self.private,self.public=keypair();self.token='a'*40;self.collector='b'*40
        self.g=BundleGateway(self.store.audit,self.public,'demo',DemoTransport(),'org')
        self.app=App(self.g,self.token,8878,collector_token=self.collector,organization='org',demo=True)
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url='http://127.0.0.1:8878')
    async def asyncTearDown(self):await self.client.aclose();self.store.__exit__()
    def auth(self,collector=False):return {'Authorization':'Bearer '+(self.collector if collector else self.token)}
    async def test_no_auth(self):self.assertEqual((await self.client.get('/api/state')).status_code,401)
    async def test_other_origin_denied(self):
        r=await self.client.get('/api/state',headers={**self.auth(),'Origin':'https://evil.invalid'});self.assertEqual(r.status_code,403)
    async def test_wrong_host_denied(self):
        r=await self.client.get('/api/state',headers={**self.auth(),'Host':'localhost:8878'});self.assertEqual(r.status_code,403)
    async def test_duplicate_authorization_denied(self):
        r=await self.client.get('/api/state',headers=[('Authorization','Bearer '+self.token),('Authorization','Bearer '+self.token)]);self.assertEqual(r.status_code,400)
    async def test_query_token_rejected(self):
        r=await self.client.get('/api/state?token='+self.token,headers=self.auth());self.assertEqual(r.status_code,403)
    async def test_user_cannot_ingest(self):
        r=await self.client.post('/api/events',headers=self.auth(),json={});self.assertEqual(r.status_code,401)
    async def test_collector_cannot_send(self):
        r=await self.client.post('/api/send',headers=self.auth(True),json={});self.assertEqual(r.status_code,401)
    async def test_arbitrary_fields_rejected(self):
        r=await self.client.post('/api/check',headers=self.auth(),json={'question':'q','files':files(),'request_id':'a'*32,'file_url':'https://evil.invalid'});self.assertEqual(r.status_code,400)
    async def test_unknown_classified_file_not_sent(self):
        r=await self.client.post('/api/send',headers=self.auth(),json={'question':'q','files':files(),'request_id':'a'*32,'consent':True})
        self.assertEqual(r.status_code,200);self.assertEqual(r.json()['execution_state'],'prevented_in_gateway')
    async def test_synthetic_vpn_and_analysis(self):
        r=await self.client.post('/api/demo',headers=self.auth(),json={});self.assertEqual(r.status_code,200)
        r=await self.client.get('/api/state',headers=self.auth());self.assertEqual(r.status_code,200)
        self.assertGreaterEqual(len(r.json()['analysis']['cases']),3);self.assertFalse(r.json()['coverage']['vpn_containment_verified'])
    async def test_explanation_not_authoritative(self):
        r=await self.client.post('/api/approve',headers=self.auth(),json={});self.assertEqual(r.status_code,404)
    async def test_audit_download_no_raw_text(self):
        await self.client.post('/api/check',headers=self.auth(),json={'question':'PRIVATEQUESTION','files':files(office(text='private@example.invalid')),'request_id':'a'*32})
        r=await self.client.get('/api/audit',headers=self.auth());self.assertNotIn('private@example.invalid',r.text);self.assertNotIn('PRIVATEQUESTION',r.text)
    async def test_rate_limit(self):
        for _ in range(60):await self.client.get('/api/nope',headers=self.auth())
        self.assertEqual((await self.client.get('/api/state',headers=self.auth())).status_code,429)
    async def test_security_headers(self):
        r=await self.client.get('/');self.assertEqual(r.headers['cache-control'],'no-store');self.assertEqual(r.headers['x-frame-options'],'DENY')
    async def test_native_key_separation(self):
        with self.assertRaises(ControlError):App(self.g,self.token,8878,collector_token=self.token)

class NativeTests(unittest.TestCase):
    def test_round_trip(self):
        stream=io.BytesIO();write_message(stream,{'action':'check'});stream.seek(0);self.assertEqual(read_message(stream),{'action':'check'})
    def test_bad_length_denied(self):
        with self.assertRaises(ControlError):read_message(io.BytesIO(struct.pack('<I',30*1024*1024)))
    def test_incomplete_input_denied(self):
        with self.assertRaises(ControlError):read_message(io.BytesIO(struct.pack('<I',3)+b'{'))
    def test_arbitrary_path_denied(self):
        with Store() as s:
            with self.assertRaises(ControlError):handle({'action':'inspect_files','files':[{'path':'/etc/passwd'}],'request_id':'a'*32},s.audit)
    def test_no_false_enforcement_claim(self):
        with Store() as s:
            r=handle({'action':'inspect_files','files':files(),'request_id':'a'*32},s.audit)
            self.assertFalse(r['browser_enforcement']);self.assertFalse(r['release_authorized'])
    def test_no_native_approval_authority(self):
        with Store() as s:
            with self.assertRaises(ControlError):handle({'action':'approve','text':'ok','request_id':'a'*32},s.audit)
