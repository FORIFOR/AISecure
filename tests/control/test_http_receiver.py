"""Actual local HTTP receiver checks. This is not a real provider/device trial."""
import http.client,secrets,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from aisecure.control.bundles import BundleGateway,sign_bundle
from .helpers import Store,keypair,files,office

class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.received=[];received=self.received
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(200);self.end_headers();self.wfile.write(b'local-lab-received')
            def log_message(self,*args):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        port=self.server.server_address[1]
        class LabTransport:
            def send(self,body):
                c=http.client.HTTPConnection('127.0.0.1',port,timeout=2)
                try:
                    c.request('POST','/sink',body=body);r=c.getresponse();return r.read().decode()
                finally:c.close()
        self.store=Store().__enter__();self.private,pub=keypair()
        self.g=BundleGateway(self.store.audit,pub,'lab',LabTransport(),'org')
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3);self.store.__exit__()
    def send(self,data):
        rid=secrets.token_hex(16);fs=files(data);proof=sign_bundle(self.private,'Question',fs,'lab',rid,'org')
        return self.g.send('Question',fs,rid,proof,consent=True)
    def test_approved_public_file_reaches_local_receiver_once(self):
        self.assertEqual(self.send(office())['execution_state'],'demo_received');self.assertEqual(len(self.received),1)
    def test_secret_file_never_reaches_local_receiver(self):
        self.assertEqual(self.send(office(text='api_key=synthetic-http-test'))['execution_state'],'prevented_in_gateway')
        self.assertEqual(self.received,[])
    def test_unknown_visual_content_never_reaches_receiver(self):
        self.assertEqual(self.send(office(extra={'xl/media/a.png':b'synthetic'}))['execution_state'],'prevented_in_gateway')
        self.assertEqual(self.received,[])
