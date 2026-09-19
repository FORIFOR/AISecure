"""VPN posture and a narrow registered FortiOS firewall-policy adapter.

A configuration change is NOT evidence of VPN containment. No exploit probing,
firmware installation, arbitrary shell, arbitrary targets or TLS bypass exists.
Device/firmware acceptance and a single-writer operational boundary are required
before constructing a live writer. Nothing enables live writes automatically.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import ssl
from urllib.parse import urlencode
from .common import ControlError, canonical, decode, ident, integer, timestamp
from ..posture import assess, iso_time
from ..providers.fortios_inventory import DeviceHTTPS, collect
from ..gateway import PinnedHTTPS

CVE=re.compile(r'CVE-\d{4}-\d{4,10}\Z')


def assess_vpn(inventory, advisories, kev, controls=(), *, now=None):
    """Explicit supplied inventory + vendor advisories; missing facts stay unknown.

    KEV published date is not its last successful fetch date. Do not silently
    replace the published date with fetched_at in the underlying source record.
    """
    now=datetime.now(timezone.utc) if now is None else now
    now_seconds=int(now.timestamp())
    published=iso_time(kev.get('dateReleased'))
    if published>now_seconds+60:raise ControlError('脆弱性情報の公開日時が未来です。')
    effective=kev
    if 'fetched_at' in kev:
        timestamp(kev['fetched_at'],now=now_seconds)
        if published>kev['fetched_at']+60:raise ControlError('公開日時と取得日時が矛盾しています。')
        # Freshness-only adapter for the legacy assessor; preserve source metadata.
        effective={**kev,'dateReleased':datetime.fromtimestamp(kev['fetched_at'],timezone.utc).isoformat()}
    result=assess(inventory,advisories,effective,now=now_seconds)
    extra=[]
    for item in controls:
        if type(item) is not dict or set(item)!={'asset_id','observed_at','mfa_required','admin_public','supported'}:
            raise ControlError('VPN制御の観測項目が不正です。')
        ident(item['asset_id']);timestamp(item['observed_at'],now=int(now.timestamp()))
        for key in ('mfa_required','admin_public','supported'):
            if item[key] is not None and type(item[key]) is not bool: raise ControlError('VPN条件値が不正です。')
        if int(now.timestamp())-item['observed_at']>86400:
            extra.append({'rule':'VPN-STALE-CONTROLS','asset':item['asset_id'],'priority':'P2',
                          'observed':'VPN設定の観測が古く、現在の状態は未確認です。'})
            continue
        for key,unsafe,rule,message in [('mfa_required',False,'VPN-MFA','多要素認証が必須ではない設定が報告されています。'),
                                        ('admin_public',True,'VPN-ADMIN-PUBLIC','管理画面の外部公開が報告されています。'),
                                        ('supported',False,'VPN-EOL','サポート対象外の機器・版数が報告されています。')]:
            if item[key] is unsafe:
                extra.append({'rule':rule,'asset':item['asset_id'],'priority':'P1','observed':message})
            elif item[key] is None:
                extra.append({'rule':'VPN-UNKNOWN','asset':item['asset_id'],'priority':'P2',
                              'observed':'必要なVPN設定の一部が未確認です。'})
    return {'posture':result,'controls':extra,'scope':'supplied_inventory_and_controls',
            'intrusion_confirmed':False,'containment_verified':False,
            'next_steps':['影響版・公開面・到達性を確認する。','管理対象機器の更新計画と代替経路を確認する。',
                          '認証・ファイル操作の関連する証跡を確認する。'],
            'kev_freshness_basis':'fetched_at' if 'fetched_at' in kev else 'published_at_fallback',
            'kev_published_at':kev.get('dateReleased'), 'kev_fetched_at':kev.get('fetched_at'),
            'kev_fetch_fresh':type(kev.get('fetched_at')) is int and 0<=int(now.timestamp())-kev['fetched_at']<=172800}


def fetch_kev():
    """Opt-in fixed public feed. No redirect/custom URL or credentials."""
    conn=PinnedHTTPS('www.cisa.gov',timeout=15,context=ssl.create_default_context())
    try:
        conn.request('GET','/sites/default/files/feeds/known_exploited_vulnerabilities.json',
                     headers={'Accept':'application/json'})
        reply=conn.getresponse();raw=reply.read(10*1024*1024+1)
        if reply.status!=200:raise ControlError('脆弱性情報を取得できません。')
        value=decode(raw,10*1024*1024)
        if type(value) is not dict or type(value.get('vulnerabilities')) is not list or len(value['vulnerabilities'])>20000:
            raise ControlError('脆弱性情報の形式が不正です。')
        if any(type(e) is not dict or type(e.get('cveID')) is not str or not CVE.fullmatch(e['cveID']) for e in value['vulnerabilities']):
            raise ControlError('脆弱性情報の識別子が不正です。')
        value['fetched_at']=int(datetime.now(timezone.utc).timestamp())
        value['source_sha256']=hashlib.sha256(raw).hexdigest()
        return value
    except Exception:raise ControlError('脆弱性情報を確認できません。既存の観測日時を更新しません。') from None
    finally:conn.close()

@dataclass(frozen=True)
class PolicyTarget:
    id: str
    host: str
    policy_id: int
    vdom: str='root'
    port: int=443
    ca_file: str | None=None
    expected_uuid: str=''
    def __post_init__(self):
        ident(self.id);integer(self.policy_id,1,2**31-1);integer(self.port,1,65535)
        if type(self.host) is not str or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',self.host):raise ControlError('機器ホストが不正です。')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}',self.vdom):raise ControlError('VDOMが不正です。')
        if not re.fullmatch(r'[a-fA-F0-9-]{36}',self.expected_uuid):raise ControlError('登録済みルールのUUIDが必要です。')

class FortiOSPolicyAdapter:
    """Use only through ResponseController; do not expose this object to the AI.

    `deployment_verified` attests admin acceptance, not a check implemented here.
    Disabling an accept rule may permit fallthrough elsewhere. Existing sessions,
    IPv6, HA peers, VPN listeners and reachable paths require independent checks.
    """
    def __init__(self,target:PolicyTarget,token:str,*,deployment_verified=False):
        if type(token) is not str or len(token)<16 or not token.isascii() or any(c.isspace() for c in token):
            raise ControlError('専用の機器APIトークンが必要です。')
        self.target,self._token,self.deployment_verified=target,token,deployment_verified is True
    @property
    def target_id(self):return self.target.id
    def _request(self,method,body=None):
        path=f'/api/v2/cmdb/firewall/policy/{self.target.policy_id}?'+urlencode({'vdom':self.target.vdom})
        conn=DeviceHTTPS(self.target.host,port=self.target.port,timeout=15,
                         context=ssl.create_default_context(cafile=self.target.ca_file))
        try:
            conn.request(method,path,body=canonical(body) if body is not None else None,
                         headers={'Authorization':'Bearer '+self._token,'Content-Type':'application/json'})
            reply=conn.getresponse();raw=reply.read(1024*1024+1)
            if reply.status!=200:raise ControlError('機器の操作結果を確認できません。')
            value=decode(raw)
            if (value.get('status')!='success' or value.get('http_method')!=method or value.get('vdom')!=self.target.vdom):
                raise ControlError('機器の操作結果が一致しません。')
            return value
        except Exception:raise ControlError('機器の操作結果は未確認です。') from None
        finally:conn.close()
    def read_state(self):
        value=self._request('GET');items=value.get('results')
        if type(items) is not list or len(items)!=1:raise ControlError('対象ルールを一意に確認できません。')
        policy=items[0]
        if (policy.get('policyid')!=self.target.policy_id or policy.get('uuid')!=self.target.expected_uuid or
                policy.get('action')!='accept' or policy.get('status') not in {'enable','disable'}):
            raise ControlError('登録済みの許可ルールと一致しません。')
        revision=value.get('revision')
        if type(revision) is not str or len(revision)>128:raise ControlError('機器の版を確認できません。')
        return {'target':self.target.id,'status':policy['status'],
                'state_hash':hashlib.sha256(canonical([self.target.id,revision,policy])).hexdigest()}
    def apply(self,operation):
        if not self.deployment_verified:raise ControlError('実機検証と単一管理経路の確認が必要です。')
        if operation not in {'disable_registered_rule','restore_registered_rule'}:raise ControlError('未対応の操作です。')
        self._request('PUT',{'status':'disable' if operation=='disable_registered_rule' else 'enable'})
    def expected(self,operation):return 'disable' if operation=='disable_registered_rule' else 'enable'
