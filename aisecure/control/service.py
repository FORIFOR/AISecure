"""Local integrated console. Separate collector and user identities; no signing API.

Not a public multi-tenant server, network proxy, or automatic browser enforcement.
"""
from __future__ import annotations
import asyncio
from collections import defaultdict,deque
import hmac
from pathlib import Path
import secrets
import time
from .common import ControlError,canonical,decode,opaque
from .analytics import analyze
from .events import EventStore
from .vpn import assess_vpn
from .bundles import redacted_text_preview

WEB=Path(__file__).parent/'web'
MAX_HTTP=24*1024*1024

class App:
    def __init__(self,gateway,token,port,*,collector_token=None,organization='local',source='collector',demo=False):
        if type(token) is not str or len(token)<32:raise ControlError('専用の認証トークンが必要です。')
        if collector_token is not None and (len(collector_token)<32 or hmac.compare_digest(token,collector_token)):
            raise ControlError('収集器の認証は分離してください。')
        self.gateway,self.audit,self.token,self.port=gateway,gateway.audit,token,port
        self.collector_token,self.organization,self.source,self.demo=collector_token,organization,source,demo
        self.events=EventStore(self.audit);self.posture=None;self.risky_assets=[];self.baselines=[]
        self.rates=defaultdict(deque);self.busy=0;self.last_collector=None
    async def __call__(self,scope,receive,send):
        if scope['type']=='lifespan':
            while True:
                ev=await receive()
                if ev['type']=='lifespan.startup':await send({'type':'lifespan.startup.complete'})
                if ev['type']=='lifespan.shutdown':await send({'type':'lifespan.shutdown.complete'});return
        if scope['type']!='http':return
        try:status,obj,mime=await self.route(scope,receive)
        except (ValueError,TypeError,KeyError):status,obj,mime=400,{'error':'入力・分類・権限を確認してください。'},'application/json'
        except Exception:status,obj,mime=503,{'error':'結果を確認できません。送信・実操作を自動再試行しないでください。'},'application/json'
        body=obj if type(obj) is bytes else canonical(obj)
        headers=[(b'content-type',mime.encode()),(b'content-length',str(len(body)).encode()),
                 (b'cache-control',b'no-store'),(b'x-content-type-options',b'nosniff'),
                 (b'x-frame-options',b'DENY'),(b'referrer-policy',b'no-referrer'),
                 (b'content-security-policy',b"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")]
        await send({'type':'http.response.start','status':status,'headers':headers})
        await send({'type':'http.response.body','body':body})
    async def route(self,scope,receive):
        items=scope.get('headers',[]);h={k.lower():v for k,v in items}
        for name in (b'host',b'authorization',b'origin',b'content-length',b'content-type'):
            if sum(k.lower()==name for k,_ in items)>1:return 400,{'error':'重複したヘッダーです。'},'application/json'
        host=f'127.0.0.1:{self.port}'.encode()
        if (h.get(b'host')!=host or scope.get('query_string') or h.get(b'origin') not in (None,b'http://'+host)
                or h.get(b'sec-fetch-site') not in (None,b'none',b'same-origin')):
            return 403,{'error':'この接続元は許可されていません。'},'application/json'
        path,method=scope['path'],scope['method']
        assets={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),
                '/app.css':('app.css','text/css; charset=utf-8')}
        if method=='GET' and path in assets:
            file,mime=assets[path];return 200,(WEB/file).read_bytes(),mime
        is_collector=path in {'/api/events','/api/posture'}
        token=self.collector_token if is_collector else self.token
        if not token or not hmac.compare_digest(h.get(b'authorization',b''),('Bearer '+token).encode()):
            return 401,{'error':'認証が必要です。'},'application/json'
        rate=self.rates['collector' if is_collector else 'user'];now=time.monotonic()
        while rate and rate[0]<now-60:rate.popleft()
        if len(rate)>=60:return 429,{'error':'要求回数の上限です。'},'application/json'
        rate.append(now)
        if method=='GET' and path=='/api/state':
            expected=[opaque(self.audit.key,'source',self.source)] if self.collector_token else []
            events=await asyncio.to_thread(self.events.read)
            analysis=await asyncio.to_thread(analyze,events,risky_assets=self.risky_assets,
                                             baselines=self.baselines,expected_sources=expected)
            return 200,{'mode':'demo' if self.demo else 'managed','delivery_enabled':self.gateway.delivery_enabled,'analysis':analysis,'vpn':self.posture,
                       'history':self.audit.evidence.history(),'collector_last_seen':self.last_collector,
                       'coverage':{'documents':True,'browser_enforcement':False,'whole_device':False,
                                   'vpn_containment_verified':False,'analysis_scope':'supplied_metadata'},
                       'checkpoint':self.audit.evidence.verify()},'application/json'
        if method=='GET' and path=='/api/audit':return 200,self.audit.export(1000),'application/x-ndjson'
        if method!='POST' or path not in {'/api/check','/api/send','/api/preview','/api/events','/api/posture','/api/demo'}:
            return 404,{'error':'未対応の操作です。'},'application/json'
        if h.get(b'content-type',b'').split(b';')[0]!=b'application/json' or b'transfer-encoding' in h:
            return 415,{'error':'JSON形式が必要です。'},'application/json'
        if self.busy>=2:return 429,{'error':'処理中の上限です。'},'application/json'
        self.busy+=1
        try:
            raw=bytearray();deadline=time.monotonic()+20
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ControlError('入力時間の上限です。')
                ev=await asyncio.wait_for(receive(),timeout=min(5,remaining))
                if ev['type']=='http.disconnect':raise ControlError('入力が中断されました。')
                raw.extend(ev.get('body',b''))
                if len(raw)>MAX_HTTP:return 413,{'error':'入力上限です。'},'application/json'
                if not ev.get('more_body'):break
            value=decode(bytes(raw),MAX_HTTP)
            if type(value) is not dict:raise ControlError('入力形式が不正です。')
            result=await asyncio.to_thread(self.process,path,value)
            return 200,result,'application/json'
        finally:self.busy-=1
    def process(self,path,value):
        if path=='/api/demo':
            if not self.demo or value:raise ControlError('デモ専用操作です。')
            from .samples import seed
            return seed(self)
        if path=='/api/events':
            result=self.events.ingest(value,organization=self.organization,source=self.source)
            self.last_collector=int(time.time());return result
        if path=='/api/posture':
            if set(value)!={'inventory','advisories','kev','controls'}:raise ControlError('台帳の項目が不正です。')
            result=assess_vpn(**value)
            org=opaque(self.audit.key,'organization',self.organization)
            risks=[(org,opaque(self.audit.key,self.organization+':asset',f['asset_id']))
                   for f in result['posture']['findings'] if f['status']=='affected' and f['priority']=='P1']
            self.audit.record(kind='vpn_assessment',request_id=secrets.token_hex(16),state='observed_only',
                              target=self.source,counts={'events':len(result['posture']['findings'])})
            self.posture,self.risky_assets=result,risks;self.last_collector=int(time.time())
            return result
        if path=='/api/preview':
            if set(value)!={'files','consent'} or value['consent'] is not True:raise ControlError('プレビューの確認が必要です。')
            # Live deployments use the same isolated worker for previews.
            return redacted_text_preview(value['files'],scanner=self.gateway.scanner)
        allowed={'question','files','request_id','label','consent'}
        if not set(value)<=allowed or not {'question','files','request_id'}<=set(value):raise ControlError('入力項目が不正です。')
        kwargs={k:value[k] for k in ('question','files','request_id','label') if k in value}
        if path=='/api/send':return self.gateway.send(**kwargs,consent=value.get('consent') is True)
        return self.gateway.check(**kwargs)
