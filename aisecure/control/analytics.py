"""Evidence-backed multi-source analysis, not proof of intrusion or exfiltration.

Input is authenticated collector metadata. Collectors own identity mapping;
matching raw identities within an organization receive identical keyed tokens.
An LLM never supplies trusted events, approves actions, or updates a baseline.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import statistics
import time
from .common import ControlError, canonical, ident, integer, timestamp, CLASSES, opaque

KINDS=frozenset({'vpn_login','idp_login','file_read','egress','privilege_change','collector_heartbeat'})
RESULTS=frozenset({'success','failure','blocked','unknown'})
CHANNELS=frozenset({'vpn','idp','filesystem','ai','cloud','usb','unknown'})
TARGETS=frozenset({'organization','personal','unknown'})


def normalize(value, *, key: bytes, organization: str, source: str, now=None):
    """Organization/source come from trusted collector configuration, not payload."""
    if type(value) is not dict or set(value) - {'id','at','kind','actor','session','asset','target',
            'result','channel','target_type','data_class','bytes','privileged','mfa','device_trusted'}:
        raise ControlError('観測項目が不正です。')
    if not {'id','at','kind','actor','result'} <= set(value): raise ControlError('観測項目が不足しています。')
    if value['kind'] not in KINDS or value['result'] not in RESULTS: raise ControlError('観測種別が不正です。')
    ident(organization);ident(source);ident(value['id'])
    timestamp(value['at'],now=now)
    for name in ('privileged','mfa','device_trusted'):
        if value.get(name) is not None and type(value[name]) is not bool: raise ControlError('条件値が不正です。')
    for name,allowed,default in [('channel',CHANNELS,'unknown'),('target_type',TARGETS,'unknown'),
                                  ('data_class',CLASSES,'unknown')]:
        if value.get(name,default) not in allowed: raise ControlError('分類が不正です。')
    def token(name):
        v=value.get(name)
        if v is None or v=='': return None
        if type(v) is not str or len(v.encode())>512: raise ControlError('識別情報が不正です。')
        return opaque(key,organization+':'+name,v)
    actor=token('actor')
    if actor is None: raise ControlError('利用者識別が必要です。')
    event={'id':opaque(key,organization+':event',source+':'+value['id']),
           'organization':opaque(key,'organization',organization),'source':opaque(key,'source',source),
           'at':value['at'],'kind':value['kind'],'result':value['result'],'actor':actor,
           'session':token('session'),'asset':token('asset'),'target':token('target'),
           'bytes':integer(value.get('bytes',0),0,2**53-1)}
    for name,default in [('channel','unknown'),('target_type','unknown'),('data_class','unknown'),
                          ('privileged',None),('mfa',None),('device_trusted',None)]:
        event[name]=value.get(name,default)
    return event

@dataclass(frozen=True)
class Baseline:
    actor: str
    organization: str
    until: int
    samples: tuple[int,...]
    # A reviewed, frozen baseline. User feedback is a candidate, not auto-training.
    def __post_init__(self):
        if type(self.until) is not int or not isinstance(self.samples,tuple) or not 14<=len(self.samples)<=365:
            raise ControlError('基準データは確認済みの14〜365日分が必要です。')
        for n in self.samples: integer(n,0,2**53-1)
        if not self.actor or not self.organization: raise ControlError('基準データの対象が必要です。')


def deduplicate(events):
    if type(events) is not list or len(events)>10000: raise ControlError('観測件数の上限です。')
    seen={}
    for event in events:
        if type(event) is not dict or type(event.get('id')) is not str: raise ControlError('観測形式が不正です。')
        old=seen.get(event['id'])
        if old is not None and canonical(old)!=canonical(event): raise ControlError('同じ観測IDの内容が一致しません。')
        seen[event['id']]=event
    return sorted(seen.values(),key=lambda e:(e['at'],e['id']))


def analyze(events, *, risky_assets=(), baselines=(), now=None, expected_sources=()):
    """Only normalized events accepted by trusted application code.

    risky_assets are (organization token, asset token) pairs obtained from a
    separate verified posture source; never derive vulnerability from the LLM.
    """
    now=int(time.time()) if now is None else now
    items=deduplicate(events)
    for e in items: timestamp(e['at'],now=now)
    cases=[]
    def case(rule,group,observed,hypothesis,unknown,priority='P2'):
        ids=list(dict.fromkeys(e['id'] for e in group))
        if not ids: return
        cid=hashlib.sha256(canonical([rule,sorted(ids)])).hexdigest()[:24]
        cases.append({'id':cid,'rule':rule,'priority':priority,'evidence_ids':ids[:32],
                      'evidence_count':len(ids),'evidence_truncated':len(ids)>32,
                      'observed':observed,'hypothesis':hypothesis,'unknown':unknown,
                      'leak_confirmed':False,'intrusion_confirmed':False,
                      'automatic_action':False,'first_at':min(e['at'] for e in group),
                      'last_at':max(e['at'] for e in group)})
    by_actor=defaultdict(list)
    for e in items: by_actor[(e['organization'],e['actor'])].append(e)
    risks=set(risky_assets)
    for (organization,actor),group in by_actor.items():
        recent=[e for e in group if e['at']>=now-86400]
        sensitive=[e for e in recent if e['kind']=='egress' and e['data_class'] in {'confidential','restricted'}
                   and e['target_type'] in {'personal','unknown'} and e['result']!='blocked']
        if sensitive:
            case('AN-SENSITIVE-EGRESS',sensitive,'機密分類の外部送信に関する観測があります。',
                 '許可されていない持ち出しの可能性があります。',
                 ['受信者が実際に取得した内容は未確認です。','分類の正確性は収集元に依存します。'],'P1')
        # Sliding 24h window; one event is not erased by correlation requirements.
        transfers=[e for e in recent if e['kind']=='egress' and e['target_type']!='organization'
                   and e['result']!='blocked' and e['data_class'] in {'internal','confidential','restricted'}]
        if len(transfers)>=3 and transfers[-1]['at']-transfers[0]['at']>=600:
            case('AN-LOW-SLOW',transfers,'24時間内に少量の外部送信が繰り返されています。',
                 '分割された持ち出しか、正常な反復作業かを確認してください。',
                 ['未収集の経路は分析していません。','同じファイルかは対象IDの対応範囲に依存します。'])
        logins=[e for e in group if e['kind'] in {'vpn_login','idp_login'} and e['result']=='success']
        for login in logins:
            failures=[e for e in group if e['kind'] in {'vpn_login','idp_login'} and e['result']=='failure'
                      and 0<login['at']-e['at']<=600 and e['source']==login['source']]
            if len(failures)>=5:
                case('AN-LOGIN-AFTER-FAILURES',failures+[login],
                     '同じ収集元で認証失敗が続いた後、成功が記録されています。',
                     '本人の再試行か、認証情報の悪用かを確認してください。',['接続元の本人性は未確認です。'])
            risky=(organization,login['asset']) in risks
            suspicious=login['privileged'] is True and (login['mfa'] is False or login['device_trusted'] is False)
            if not (risky and suspicious and login['session']): continue
            after=[e for e in group if e['session']==login['session'] and 0<=e['at']-login['at']<=3600]
            reads=[e for e in after if e['kind']=='file_read' and e['result']=='success'
                   and e['data_class'] in {'confidential','restricted'}]
            egress=[e for e in after if e['kind']=='egress' and e['result']!='blocked'
                    and e['target_type']!='organization' and e['data_class'] in {'confidential','restricted'}]
            if reads:
                evidence=[login]+reads+[e for e in egress if e['at']>=min(r['at'] for r in reads)]
                case('AN-VPN-PRIVILEGE-DATA-PATH',evidence,
                     'リスクのある機器を使った特権認証と、同じセッションの機密ファイル操作が連続しています。',
                     '侵入後の資料アクセスである可能性があり、優先確認が必要です。',
                     ['脆弱性が実際に悪用された証拠ではありません。','ファイル内容の外部到達は確認していません。'],'P1')
        for baseline in baselines:
            if (baseline.organization,baseline.actor)!=(organization,actor):continue
            start=now-86400
            if baseline.until>=start: raise ControlError('評価期間より前の基準データが必要です。')
            matched=[e for e in recent if e['kind']=='egress' and e['result']=='success']
            amount=sum(e['bytes'] for e in matched)
            median=statistics.median(baseline.samples)
            mad=statistics.median(abs(x-median) for x in baseline.samples)
            threshold=max(median*3,median+6*max(mad,1024),1024*1024)
            if amount>threshold:
                case('AN-BASELINE-DEVIATION',matched,'送信量が確認済み基準期間の上限条件を超えています。',
                     '業務増加か異常な送信かを確認してください。',['統計的な異常は不正行為の証明ではありません。'])
    last={}
    for e in items:last[e['source']]=max(last.get(e['source'],0),e['at'])
    stale=[source for source in expected_sources if now-last.get(source,0)>300]
    return {'cases':cases,'events':len(items),'analysis':'deterministic-correlation-v1',
            'baseline_status':'available' if baselines else 'not_configured',
            'missing_or_stale_sources':stale, 'coverage':'supplied_metadata_only',
            'automatic_action':False,'limitations':['収集されていない操作は見えません。','相関は因果関係を証明しません。']}


def load_baselines(path,*,key,organization):
    """Admin-owned frozen baseline; never learns directly from incoming incidents."""
    from pathlib import Path
    from .common import decode
    import os
    path=Path(path)
    if path.is_symlink() or (os.name!='nt' and path.stat().st_mode & 0o077):
        raise ControlError('基準データは管理者だけが読めるファイルにしてください。')
    with path.open('rb') as stream:value=decode(stream.read(1024*1024+1))
    if type(value) is not list or len(value)>1000:raise ControlError('基準データの形式が不正です。')
    result=[];actors=set()
    for row in value:
        if type(row) is not dict or set(row)!={'actor','until','samples'} or type(row['actor']) is not str or not 1<=len(row['actor'])<=512:
            raise ControlError('基準データの対象が不正です。')
        actor=opaque(key,organization+':actor',row['actor'])
        if actor in actors:raise ControlError('基準データの対象が重複しています。')
        actors.add(actor)
        result.append(Baseline(actor,opaque(key,'organization',organization),row['until'],tuple(row['samples'])))
    return result
