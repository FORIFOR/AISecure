from __future__ import annotations
import asyncio
import copy
import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

from aisecure.gateway import (Evidence, Gateway, GatewayError, DemoTransport, OpenAITransport,
    DeliveryUnknown, PinnedHTTPS, sign_label, verify_label, wire_body, valid_text)
from aisecure.workbench import App
from aisecure.posture import normalize_dlp, dlp_findings, assess, audit_tools
from aisecure.schema import canonical

HAS_CRYPTO=importlib.util.find_spec('cryptography') is not None


@unittest.skipUnless(HAS_CRYPTO,'workbench extra required; mandatory workbench CI installs it')
class GatewayTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key=Ed25519PrivateKey.generate()
        self.private=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        self.public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);self.master=secrets.token_bytes(32)
        self.db=Evidence(self.directory,self.master);self.transport=Mock();self.transport.send.return_value='synthetic-answer'
        self.g=Gateway(self.db,self.public,'test-model',self.transport)
        self.text='Published product description.';self.rid='a'*32
        self.label=sign_label(self.private,self.text,self.rid,self.g.model,'public')

    def tearDown(self):
        self.db.close();self.tmp.cleanup()

    def test_public_dispatches_exact_final_bytes(self):
        r=self.g.send(self.text,self.rid,self.label,consent=True)
        self.assertEqual(r['execution_state'],'demo_received')
        self.transport.send.assert_called_once_with(wire_body(self.text,self.g.model))
        self.assertEqual(r['output'],'synthetic-answer')

    def test_unknown_never_invokes_transport(self):
        self.assertEqual(self.g.send(self.text,self.rid,consent=True)['decision'],'review')
        self.transport.send.assert_not_called()

    def test_confidential_label_does_not_grant_permission(self):
        label=sign_label(self.private,self.text,self.rid,self.g.model,'confidential')
        self.assertEqual(self.g.send(self.text,self.rid,label,consent=True)['execution_state'],'prevented_in_gateway')
        self.transport.send.assert_not_called()

    def test_secret_blocks_even_with_valid_public_label(self):
        text='api_key=synthetic-long-secret'
        label=sign_label(self.private,text,self.rid,self.g.model,'public')
        self.assertEqual(self.g.send(text,self.rid,label,consent=True)['decision'],'block')
        self.transport.send.assert_not_called()

    def test_internal_not_automatically_allowed(self):
        label=sign_label(self.private,self.text,self.rid,self.g.model,'internal')
        self.assertEqual(self.g.check(self.text,self.rid,label)['decision'],'block')

    def test_consent_is_required(self):
        with self.assertRaises(GatewayError):self.g.send(self.text,self.rid,self.label)
        self.transport.send.assert_not_called()

    def test_labels_bound_to_body_model_id_endpoint_policy(self):
        for field,value in [('model','other'),('request_id','b'*32),('endpoint','https://other.example/'),('policy','relaxed'),('sha256','0'*64),('data_class','public')]:
            label=copy.deepcopy(self.label)
            if field=='data_class':label['signature']='A'*86
            else:label['claim'][field]=value
            with self.subTest(field=field),self.assertRaises(GatewayError):self.g.check(self.text,self.rid,label)
        with self.assertRaises(GatewayError):self.g.check(self.text+' altered',self.rid,self.label)

    def test_unknown_label_format_fails_closed(self):
        for x in [True,[],{}, {'claim':{},'signature':None}, {'claim':{**self.label['claim'],'bypass':True},'signature':self.label['signature']}]:
            with self.subTest(value=str(type(x))),self.assertRaises(GatewayError):self.g.check(self.text,self.rid,x)

    def test_expired_and_future_labels_fail(self):
        for at in [int(time.time())-301,int(time.time())+61]:
            label=sign_label(self.private,self.text,self.rid,self.g.model,'public',now=at)
            with self.assertRaises(GatewayError):self.g.send(self.text,self.rid,label,consent=True)
        self.transport.send.assert_not_called()

    def test_replay_never_resends_and_does_not_cache_output(self):
        self.g.send(self.text,self.rid,self.label,consent=True)
        result=self.g.send(self.text,self.rid,self.label,consent=True)
        self.assertTrue(result['replayed']);self.assertNotIn('output',result)
        self.assertEqual(self.transport.send.call_count,1)

    def test_id_cannot_be_rebound_to_other_content(self):
        self.g.send(self.text,self.rid,self.label,consent=True)
        text='Different published text'
        label=sign_label(self.private,text,self.rid,self.g.model,'public')
        with self.assertRaises(GatewayError):self.g.send(text,self.rid,label,consent=True)
        self.assertEqual(self.transport.send.call_count,1)

    def test_concurrent_retries_dispatch_once(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:self.g.send(self.text,self.rid,self.label,consent=True),range(8)))
        self.assertEqual(self.transport.send.call_count,1)
        self.assertTrue(any(r['execution_state']=='demo_received' for r in results))

    def test_exception_after_dispatch_is_unknown_and_not_retried(self):
        self.transport.send.side_effect=RuntimeError('private-provider-error')
        for _ in range(2):
            result=self.g.send(self.text,self.rid,self.label,consent=True)
            self.assertEqual(result['execution_state'],'delivery_unknown')
            self.assertNotIn('private-provider-error',json.dumps(result))
        self.assertEqual(self.transport.send.call_count,1)

    def test_pending_receipt_survives_process_restart(self):
        p=self.g.prepare(self.text,self.rid,self.label)
        self.db.reserve(self.rid,p.fingerprint,{**p.report,'execution_state':'dispatch_pending'})
        self.db.close();self.db=Evidence(self.directory,self.master)
        g=Gateway(self.db,self.public,'test-model',self.transport)
        result=g.send(self.text,self.rid,self.label,consent=True)
        self.assertEqual(result['execution_state'],'dispatch_pending');self.transport.send.assert_not_called()

    def test_stop_prevents_dispatch(self):
        sentinel=self.directory/'STOP';sentinel.touch()
        g=Gateway(self.db,self.public,'test-model',self.transport,stop=sentinel)
        with self.assertRaises(RuntimeError):g.send(self.text,self.rid,self.label,consent=True)
        self.transport.send.assert_not_called()

    def test_db_contains_no_request_label_or_reply(self):
        self.g.send(self.text,self.rid,self.label,consent=True)
        raw=(self.directory/'gateway.sqlite3').read_bytes()
        for secret in [self.text.encode(),b'synthetic-answer',self.label['signature'].encode(),b'demo_received']:
            self.assertNotIn(secret,raw)
        history=json.dumps(self.db.history())
        self.assertNotIn(self.text,history);self.assertNotIn('synthetic-answer',history)

    def test_wrong_key_does_not_reset_store(self):
        self.g.check(self.text,self.rid,self.label)
        with self.assertRaises(GatewayError):Evidence(self.directory,secrets.token_bytes(32))
        self.assertEqual(self.db.verify()['seq'],1)

    def test_corrupted_journal_prevents_send(self):
        self.g.check(self.text,self.rid,self.label)
        self.db.db.execute("UPDATE journal SET mac=? WHERE seq=1",('f'*64,))
        with self.assertRaises(GatewayError):self.g.send(self.text,self.rid,self.label,consent=True)
        self.transport.send.assert_not_called()

    def test_capacity_exhaustion_never_dispatches(self):
        self.db.limit=1
        with self.assertRaises(GatewayError):self.g.send(self.text,self.rid,self.label,consent=True)
        self.transport.send.assert_not_called()

    def test_backup_reopens_with_same_key(self):
        self.g.check(self.text,self.rid,self.label)
        out=self.directory/'copy';out.mkdir(mode=0o700)
        self.db.backup(out/'gateway.sqlite3')
        other=Evidence(out,self.master)
        try:self.assertEqual(other.verify(),self.db.verify())
        finally:other.close()

    def test_backup_refuses_overwrite(self):
        out=self.directory/'exists';out.write_text('keep')
        with self.assertRaises(FileExistsError):self.db.backup(out)
        self.assertEqual(out.read_text(),'keep')

    def test_prune_reanchors_and_verifies(self):
        with patch('aisecure.gateway.time.time',return_value=time.time()-3*86400):
            self.db.append({'kind':'old'})
        self.db.append({'kind':'new'})
        report=self.db.prune(int(time.time())-2*86400)
        self.assertEqual(report['pruned'],1)
        self.assertEqual(self.db.verify()['seq'],3)

    def test_prune_refuses_too_recent_cutoff(self):
        with self.assertRaises(GatewayError):self.db.prune(int(time.time()))

    def test_body_is_bounded_and_ids_are_opaque(self):
        for text,rid in [('x'*262145,self.rid),('x','person@example.invalid'),('\ud800',self.rid),('',self.rid)]:
            with self.assertRaises(GatewayError):valid_text(text,rid)

    def test_private_dns_resolution_refused_without_socket(self):
        for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','::1']:
            with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]),patch('socket.socket') as sock:
                with self.assertRaises(DeliveryUnknown):PinnedHTTPS('api.openai.com').connect()
                sock.assert_not_called()

    def test_provider_redirect_or_error_not_followed(self):
        for status in [301,302,307,401,429,500]:
            with patch('aisecure.gateway.PinnedHTTPS') as cls:
                response=cls.return_value.getresponse.return_value;response.status=status;response.read.return_value=b'private-detail'
                with self.assertRaises(DeliveryUnknown):OpenAITransport('synthetic-key-00000000000').send(b'{}')
                self.assertEqual(cls.return_value.request.call_count,1)

    def test_provider_completed_response_contract(self):
        with patch('aisecure.gateway.PinnedHTTPS') as cls:
            response=cls.return_value.getresponse.return_value;response.status=200
            response.read.return_value=json.dumps({'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'Answer'}]}]}).encode()
            body=wire_body(self.text,'test-model')
            self.assertEqual(OpenAITransport('synthetic-key-00000000000').send(body),'Answer')
            self.assertEqual(cls.return_value.request.call_args.kwargs['body'],body)

    def test_openai_wire_has_no_hidden_context_or_tools(self):
        obj=json.loads(wire_body(self.text,self.g.model))
        self.assertEqual(set(obj),{'model','input','store','stream','tools','max_output_tokens'})
        self.assertEqual(obj['input'],self.text);self.assertFalse(obj['store']);self.assertEqual(obj['tools'],[])

    def test_real_local_receiver_gets_allowed_bytes_only(self):
        received=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(200);self.end_headers();self.wfile.write(b'ok')
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        class LocalTestTransport:
            def send(_,body):
                c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=2)
                try:c.request('POST','/receive',body);c.getresponse().read();return 'test-received'
                finally:c.close()
        g=Gateway(self.db,self.public,self.g.model,LocalTestTransport())
        try:
            label=sign_label(self.private,self.text,self.rid,self.g.model,'confidential')
            g.send(self.text,self.rid,label,consent=True);self.assertEqual(received,[])
            rid='b'*32;label=sign_label(self.private,self.text,rid,self.g.model,'public')
            g.send(self.text,rid,label,consent=True);self.assertEqual(received,[wire_body(self.text,self.g.model)])
        finally:server.shutdown();server.server_close();thread.join()


@unittest.skipUnless(HAS_CRYPTO,'workbench extra required')
class AppTests(unittest.TestCase):
    # HTTP boundary tests without inheriting and recounting all core test methods.
    def setUp(self):
        GatewayTests.setUp(self);self.token='T'*40;self.app=App(self.g,self.token,8877,demo_key=self.private,collector_token='C'*40)

    def tearDown(self):
        GatewayTests.tearDown(self)

    def request(self,path,body=None,*,auth=None,extra=None,method=None):
        raw=json.dumps(body).encode() if body is not None else b''
        headers=[(b'host',b'127.0.0.1:8877'),(b'authorization',b'Bearer '+(auth if auth is not None else self.token).encode()),(b'content-type',b'application/json')]
        if extra:headers+=extra
        output=[]
        async def receive():return {'type':'http.request','body':raw,'more_body':False}
        async def send(value):output.append(value)
        scope={'type':'http','method':method or ('POST' if body is not None else 'GET'),'path':path,'headers':headers,'query_string':b''}
        asyncio.run(self.app(scope,receive,send))
        return output[0]['status'],json.loads(output[1]['body'])

    def test_http_unauthorized(self):self.assertEqual(self.request('/api/state',auth='wrong')[0],401)
    def test_http_cross_origin(self):self.assertEqual(self.request('/api/state',extra=[(b'origin',b'https://other.example')])[0],403)
    def test_http_duplicate_auth_header(self):self.assertEqual(self.request('/api/state',extra=[(b'authorization',b'Bearer '+self.token.encode())])[0],400)
    def test_http_no_approval_api(self):self.assertEqual(self.request('/api/classify',{})[0],404)
    def test_http_extra_fields_not_forwarded(self):
        for key in ['attachments','model','tools','destination','approved','data_class','previous_response_id']:
            status,_=self.request('/api/check',{'request_id':self.rid,'text':self.text,key:True})
            self.assertEqual(status,400,key)
        self.transport.send.assert_not_called()
    def test_http_demo_sample_runs_real_engine(self):
        status,result=self.request('/api/check',{'request_id':self.rid,'sample':'confidential'})
        self.assertEqual(status,200);self.assertEqual(result['decision'],'block')
    def test_http_live_cannot_use_demo_label(self):
        self.app.demo_key=None
        self.assertEqual(self.request('/api/send',{'request_id':self.rid,'sample':'public','consent':True})[0],400)
    def test_http_history_has_no_prompt(self):
        self.request('/api/check',{'request_id':self.rid,'text':self.text})
        status,state=self.request('/api/state');self.assertEqual(status,200)
        self.assertNotIn(self.text,json.dumps(state));self.assertFalse(state['coverage']['egress_verified'])
    def test_http_local_explanation_uses_existing_record(self):
        self.request('/api/check',{'request_id':self.rid,'sample':'confidential'})
        status,data=self.request('/api/explain',{'seq':1})
        self.assertEqual(status,200);self.assertFalse(data['llm_used'])
    def test_http_roles_separate(self):
        self.assertEqual(self.request('/api/ingest',{})[0],401)
        self.assertEqual(self.request('/api/state',auth='C'*40)[0],401)
    def test_http_rate_limit(self):
        for _ in range(60):self.request('/api/state')
        self.assertEqual(self.request('/api/state')[0],429)


class PostureTests(unittest.TestCase):
    def dlp(self,**kw):
        return {'event_id':'evt-1','source':'dlp-1','at':int(time.time()),'actor':'person@example.invalid',
                'operation':'upload','tenant':'personal','data_class':'confidential','bytes':100,'outcome':'allowed',**kw}
    def norm(self,**kw):return normalize_dlp(self.dlp(**kw),lambda b:hashlib.sha256(b).hexdigest())
    def test_dlp_hashes_actor_never_claims_enforcement(self):
        r=self.norm();self.assertNotIn('person@example.invalid',json.dumps(r));self.assertFalse(r['enforcement_verified'])
    def test_dlp_single_small_transfer_flagged(self):self.assertEqual(dlp_findings([self.norm()])[0]['rule'],'DLP-001')
    def test_dlp_slow_multiple_operations(self):
        now=int(time.time());events=[self.norm(event_id=f'ev-{i}',at=now-i*7200,data_class='unknown',bytes=1) for i in range(3)]
        self.assertEqual(dlp_findings(events)[0]['rule'],'DLP-002')
    def test_dlp_duplicates_do_not_inflate(self):self.assertEqual(len(dlp_findings([self.norm()]*5)),1)
    def test_dlp_rejects_extra_content_and_unknown_states(self):
        for change in [{'text':'secret'},{'at':int(time.time())+200},{'outcome':'verified'},{'bytes':True},{'operation':[]}]:
            with self.assertRaises(GatewayError):normalize_dlp(self.dlp(**change),lambda b:'hashed')
    def setup_assets(self,version='1.2.0'):
        now=int(time.time());stamp=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now))
        inv={'observed_at':stamp,'assets':[{'id':'vpn-1','vendor':'Example','product':'LabVPN','version':version,'internet_exposed':True,'privileged_path':True,'sensitive_path':True}]}
        adv={'observed_at':stamp,'advisories':[{'vendor':'Example','product':'LabVPN','cve':'CVE-2099-12345','introduced':'1.0','fixed':'1.3','source':'https://vendor.example/advisory'}]}
        kev={'dateReleased':stamp,'vulnerabilities':[]};return inv,adv,kev
    def test_exposure_prioritized_even_absent_from_kev(self):
        r=assess(*self.setup_assets());f=r['findings'][0];self.assertEqual(f['priority'],'P1');self.assertFalse(f['matches'][0]['known_exploited'])
    def test_unknown_version_never_safe(self):self.assertEqual(assess(*self.setup_assets('custom-build'))['findings'][0]['status'],'unknown')
    def test_no_vendor_match_not_safe(self):
        inv,adv,kev=self.setup_assets();adv['advisories']=[];self.assertEqual(assess(inv,adv,kev)['findings'][0]['status'],'unknown')
    def test_stale_feed_unknown_not_safe(self):
        inv,adv,kev=self.setup_assets('1.3');kev['dateReleased']='2020-01-01T00:00:00Z'
        self.assertEqual(assess(inv,adv,kev)['findings'][0]['status'],'unknown')
    def test_patch_boundary_matches_version_range_only(self):
        r=assess(*self.setup_assets('1.3'));self.assertEqual(r['findings'][0]['status'],'no_match_in_supplied_ranges');self.assertFalse(r['live_device_verified'])
    def test_invalid_boolean_or_future_timestamp_rejected(self):
        inv,adv,kev=self.setup_assets();inv['assets'][0]['internet_exposed']=1
        with self.assertRaises(GatewayError):assess(inv,adv,kev)
    def test_tool_manifest_permission_expansion_requires_reapproval(self):
        old={'tools':[{'id':'reader','sha256':'a'*64,'permissions':['read'],'publisher':'owner'}]}
        new=copy.deepcopy(old);new['tools'][0]['permissions'].append('network')
        self.assertEqual(len(audit_tools(new,old)['findings']),1)
        self.assertEqual(audit_tools(old,old)['findings'],[])
    def test_manifest_hash_drift(self):
        old={'tools':[{'id':'reader','sha256':'a'*64,'permissions':['read'],'publisher':'owner'}]}
        new=copy.deepcopy(old);new['tools'][0]['sha256']='b'*64
        self.assertTrue(audit_tools(new,old)['findings'][0]['requires_reapproval'])


if __name__=='__main__':unittest.main()
