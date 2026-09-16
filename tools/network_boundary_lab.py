"""Synthetic, isolated Docker acceptance fixture. Never a production server.

Run via deployment/check-egress.sh; do not expose its unauthenticated HTTP lab
endpoints outside the disposable networks. No real credentials/data/provider.
"""
from __future__ import annotations
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import uuid


def request(host,path,body=None):
    c=http.client.HTTPConnection(host,8080,timeout=3)
    try:
        c.request('POST' if body is not None else 'GET',path,json.dumps(body).encode() if body is not None else None,
                  {'Content-Type':'application/json'})
        r=c.getresponse();data=r.read(100000)
        if r.status!=200:raise RuntimeError('lab HTTP error')
        return json.loads(data)
    finally:c.close()


if sys.argv[1]=='client':
    # Prove direct TCP reachability to the independent receiver is blocked.
    try:
        s=socket.create_connection((os.environ['SINK_IP'],8080),timeout=2);s.close()
    except OSError:pass
    else:raise SystemExit('FAIL: app can bypass gateway')
    if len(sys.argv)>2 and sys.argv[2]=='stopped':
        try:request('gateway','/send',{'sample':'public'})
        except OSError:print('PASS: stopped gateway has no direct fallback');raise SystemExit(0)
        raise SystemExit('FAIL: stopped gateway accepted request')
    denied=request('gateway','/send',{'sample':'confidential'})
    allowed=request('gateway','/send',{'sample':'public'})
    assert denied['execution_state']=='prevented_in_gateway'
    assert allowed['execution_state']=='demo_received'
    print('PASS: bypass blocked, deny rejected, public request delivered')
    raise SystemExit(0)

received=[]
if sys.argv[1]=='gateway':
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from aisecure.gateway import Evidence,Gateway,sign_label
    key=Ed25519PrivateKey.generate()
    private=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    temp=tempfile.TemporaryDirectory();db=Evidence(Path(temp.name),secrets.token_bytes(32))
    class LabTransport:
        def send(self,body):
            request('receiver','/receive',json.loads(body));return 'lab-received'
    gateway=Gateway(db,public,'demo-network-lab',LabTransport())


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_GET(self):
        body={'ready':True,'received_count':len(received),'received':received}
        self.send_response(200);self.end_headers();self.wfile.write(json.dumps(body).encode())
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0'))
        if not 0<n<=10000:self.send_error(400);return
        body=json.loads(self.rfile.read(n))
        if sys.argv[1]=='receiver':
            assert self.path=='/receive'
            received.append(body);result={'received':True}
        else:
            assert self.path=='/send' and set(body)=={'sample'} and body['sample'] in {'public','confidential'}
            rid=uuid.uuid4().hex;text='SYNTHETIC PUBLIC ACCEPTANCE MESSAGE'
            label=sign_label(private,text,rid,gateway.model,body['sample'])
            result=gateway.send(text,rid,label,consent=True)
        self.send_response(200);self.end_headers();self.wfile.write(json.dumps(result).encode())

http.server.ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
