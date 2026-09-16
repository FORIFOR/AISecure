"""Read-only asset/advisory assessment and normalized DLP evidence.

No network scanning, VPN writes, endpoint isolation or arbitrary command exec.
An external collector's 'blocked' status is reported evidence, not independent
proof of enforcement. Unsupported version schemes remain unknown.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from .gateway import GatewayError, PinnedHTTPS
from .schema import read_json

CVE = re.compile(r'CVE-\d{4}-\d{4,8}\Z')
OPAQUE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z')


def normalize_dlp(value: dict, digest) -> dict:
    required = {'event_id', 'source', 'at', 'actor', 'operation', 'tenant', 'data_class', 'bytes', 'outcome'}
    if type(value) is not dict or set(value) != required:
        raise GatewayError('DLPの入力項目が不正です。本文やファイル名を含めないでください。')
    for field in ('event_id', 'source'):
        if type(value[field]) is not str or not OPAQUE.fullmatch(value[field]):
            raise GatewayError('DLPの識別子が不正です。')
    if type(value['actor']) is not str or not 1 <= len(value['actor']) <= 200:
        raise GatewayError('操作者の識別子が不正です。')
    if type(value['at']) is not int or not int(time.time()) - 30*86400 <= value['at'] <= int(time.time()) + 60:
        raise GatewayError('DLPの観測時刻を確認してください。')
    for field, choices in {'operation': {'upload','usb','sync','download'}, 'tenant': {'managed','personal','unknown'},
                            'data_class': {'public','internal','confidential','restricted','unknown'},
                            'outcome': {'blocked','allowed','unknown'}}.items():
        if type(value[field]) is not str or value[field] not in choices:
            raise GatewayError('DLPの分類または結果が不正です。')
    if value['bytes'] is not None and (type(value['bytes']) is not int or not 0 <= value['bytes'] <= 2**40):
        raise GatewayError('DLPのサイズが不正です。')
    return {**{k: value[k] for k in required - {'actor'}},
            'actor': digest(value['actor'].encode()), 'kind': 'dlp_observation',
            'enforcement_verified': False, 'source_trust': 'authenticated_collector_report'}


def dlp_findings(events: list[dict]) -> list[dict]:
    """One sensitive transfer is enough; no suspicious-login prerequisite."""
    if type(events) is not list or len(events) > 10000:
        raise GatewayError('DLP履歴の上限を超えています。')
    groups = defaultdict(list)
    results = []
    seen = set()
    for e in events:
        if e.get('kind') != 'dlp_observation': continue
        identity = (e['source'], e['event_id'])
        if identity in seen: continue
        seen.add(identity)
        if e['tenant'] in {'personal','unknown'}:
            groups[e['actor']].append(e)
        if e['tenant'] != 'managed' and e['data_class'] in {'confidential','restricted'}:
            results.append({'rule':'DLP-001','evidence_ids':[e['event_id']],
                'summary':'機密情報の持ち出し操作を確認してください。',
                'observed_outcome':e['outcome'],'verdict':'requires_review','leak_confirmed':False})
    for actor, items in groups.items():
        items.sort(key=lambda e:e['at'])
        left = 0
        for right,e in enumerate(items):
            while e['at'] - items[left]['at'] > 86400: left += 1
            window=items[left:right+1]
            if len(window) >= 3:
                results.append({'rule':'DLP-002','evidence_ids':[v['event_id'] for v in window[:100]],
                    'summary':'24時間以内の複数回の持ち出し操作を確認してください。',
                    'verdict':'requires_review','leak_confirmed':False})
                break
    return results


def numeric_version(value: str):
    if type(value) is not str or not re.fullmatch(r'\d{1,6}(?:\.\d{1,6}){0,5}', value):
        return None
    parts=tuple(map(int,value.split('.')))
    return parts+(0,)*(6-len(parts))


def iso_time(value):
    if type(value) is not str: raise GatewayError('取得日時が不正です。')
    try:
        d=datetime.fromisoformat(value.replace('Z','+00:00'))
        if d.tzinfo is None: raise ValueError
        return int(d.timestamp())
    except ValueError:
        raise GatewayError('タイムゾーン付きの取得日時が必要です。') from None


def assess(inventory: dict, advisories: dict, kev: dict, *, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    if type(inventory) is not dict or set(inventory) != {'observed_at','assets'} or type(inventory['assets']) is not list or len(inventory['assets']) > 2000:
        raise GatewayError('資産台帳の形式または上限が不正です。')
    if type(advisories) is not dict or set(advisories) != {'observed_at','advisories'} or type(advisories['advisories']) is not list or len(advisories['advisories']) > 10000:
        raise GatewayError('脆弱性台帳の形式が不正です。')
    if type(kev) is not dict or type(kev.get('vulnerabilities')) is not list or len(kev['vulnerabilities'])>100000:
        raise GatewayError('KEVの形式が不正です。')
    observed=iso_time(inventory['observed_at'])
    advtime=iso_time(advisories['observed_at'])
    kevtime=iso_time(kev.get('dateReleased'))
    if any(t>now+60 for t in (observed,advtime,kevtime)):
        raise GatewayError('未来の取得日時は使用できません。')
    cves=set()
    for v in kev['vulnerabilities']:
        if type(v) is not dict or type(v.get('cveID')) is not str or not CVE.fullmatch(v['cveID']):
            raise GatewayError('KEVのCVE識別子が不正です。')
        cves.add(v['cveID'])
    by_product=defaultdict(list)
    for v in advisories['advisories']:
        if type(v) is not dict or set(v)!={'vendor','product','cve','introduced','fixed','source'}:
            raise GatewayError('脆弱性台帳の項目が不正です。')
        if (any(type(v[k]) is not str or not 1<=len(v[k])<=200 for k in v)
                or not CVE.fullmatch(v['cve']) or not v['source'].startswith('https://')):
            raise GatewayError('脆弱性台帳の値が不正です。')
        by_product[(v['vendor'].casefold(),v['product'].casefold())].append(v)
    results=[]; ids=set()
    for a in inventory['assets']:
        if type(a) is not dict or set(a)!={'id','vendor','product','version','internet_exposed','privileged_path','sensitive_path'}:
            raise GatewayError('資産情報の項目が不正です。')
        if type(a['id']) is not str or not OPAQUE.fullmatch(a['id']) or a['id'] in ids:
            raise GatewayError('資産IDは一意の仮名識別子にしてください。')
        ids.add(a['id'])
        if any(type(a[k]) is not str or len(a[k])>200 for k in ('vendor','product','version')):
            raise GatewayError('製品情報が不正です。')
        for k in ('internet_exposed','privileged_path','sensitive_path'):
            if a[k] is not None and type(a[k]) is not bool: raise GatewayError('公開・到達性はtrue/false/nullです。')
        reasons=[]; matches=[]; unknown=False
        version=numeric_version(a['version'])
        candidates=by_product[(a['vendor'].casefold(),a['product'].casefold())]
        if not candidates: reasons.append('照合できるベンダー情報がありません。安全とは判断しません。');unknown=True
        if now-observed>86400: reasons.append('資産情報が24時間より古く、再確認が必要です。');unknown=True
        if now-advtime>172800 or now-kevtime>172800: reasons.append('脆弱性情報が48時間より古く、更新が必要です。');unknown=True
        if any(a[k] is None for k in ('internet_exposed','privileged_path','sensitive_path')):
            reasons.append('公開面または到達性が未確認です。');unknown=True
        for v in candidates:
            low,high=numeric_version(v['introduced']),numeric_version(v['fixed'])
            if None in (version,low,high) or low>=high:
                unknown=True;reasons.append('版数の比較方式が未対応です。ベンダー情報を確認してください。');continue
            if low<=version<high:
                matches.append({'cve':v['cve'],'known_exploited':v['cve'] in cves,'fixed':v['fixed'],'source':v['source']})
        urgent=bool(matches) and a['internet_exposed'] is True and (any(v['known_exploited'] for v in matches) or a['sensitive_path'] is True)
        results.append({'asset_id':a['id'],'priority':'P1' if urgent else 'P2',
            'status':'affected' if matches else 'unknown' if unknown else 'no_match_in_supplied_ranges',
            'matches':matches,'reasons':list(dict.fromkeys(reasons)), 'action_executed':False,
            'next_steps':['管理者がベンダー情報と実機を照合し、接続制限・修正・復旧手順を承認してください。']})
    return {'findings':results,'scope':'supplied_inventory_and_advisories_only',
            'live_device_verified':False,'kev_absence_is_not_safe':True}


def refresh_kev(target: Path):
    """Public feed only. Never sends inventory or secrets, never follows redirects."""
    conn=PinnedHTTPS('www.cisa.gov',timeout=20)
    try:
        conn.request('GET','/sites/default/files/feeds/known_exploited_vulnerabilities.json',headers={'Accept':'application/json'})
        r=conn.getresponse();raw=r.read(10*1024*1024+1)
        if r.status!=200 or len(raw)>10*1024*1024:raise GatewayError('KEVを更新できません。古い情報を安全とは扱いません。')
        obj=json.loads(raw)
        if type(obj.get('vulnerabilities')) is not list or type(obj.get('dateReleased')) is not str:raise GatewayError('KEV形式が不正です。')
        iso_time(obj['dateReleased'])
        target=Path(target);temp=target.with_name(target.name+'.tmp')
        if temp.exists() or temp.is_symlink() or target.is_symlink():raise GatewayError('更新先を確認してください。')
        with temp.open('xb') as f:f.write(raw)
        temp.replace(target)
        return {'sha256':hashlib.sha256(raw).hexdigest(),'fetched_at':int(time.time()),'entries':len(obj['vulnerabilities'])}
    except (OSError,ValueError):
        raise GatewayError('KEVの取得または保存に失敗しました。') from None
    finally:conn.close()


def audit_tools(manifest: dict, approved: dict):
    """Offline manifest diff; no execution or downloading a Skill/MCP server."""
    def validate(doc):
        if type(doc) is not dict or set(doc)!={'tools'} or type(doc['tools']) is not list or len(doc['tools'])>1000:
            raise GatewayError('ツール台帳の形式が不正です。')
        tools={}
        for t in doc['tools']:
            if type(t) is not dict or set(t)!={'id','sha256','permissions','publisher'}:
                raise GatewayError('ツール台帳の項目が不正です。')
            if type(t['id']) is not str or not OPAQUE.fullmatch(t['id']) or t['id'] in tools:
                raise GatewayError('ツールIDが不正です。')
            if type(t['sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',t['sha256']):
                raise GatewayError('ツール内容のハッシュが必要です。')
            if type(t['publisher']) is not str or not OPAQUE.fullmatch(t['publisher']):raise GatewayError('配布元IDが不正です。')
            if type(t['permissions']) is not list or len(t['permissions'])>20 or any(type(p) is not str or p not in {'read','write','network','execute','delete','share'} for p in t['permissions']):
                raise GatewayError('ツール権限が不正です。')
            tools[t['id']]=t
        return tools
    current,base=validate(manifest),validate(approved)
    return {'findings':[{'tool_id':name,'requires_reapproval':True,'reason':'new_or_changed_manifest'}
                         for name,t in current.items() if base.get(name)!=t],
            'execution_enforced':False,'scope':'manifest_comparison_only'}


def main(argv=None):
    p=argparse.ArgumentParser(description='読み取り専用の資産・ツール監査。実機操作は行いません。')
    sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('assess');a.add_argument('inventory',type=Path);a.add_argument('advisories',type=Path);a.add_argument('kev',type=Path)
    t=sub.add_parser('tools');t.add_argument('manifest',type=Path);t.add_argument('approved',type=Path)
    f=sub.add_parser('refresh-kev');f.add_argument('output',type=Path)
    args=p.parse_args(argv)
    def load(path, maximum=2*1024*1024):
        if path.is_symlink():raise GatewayError('シンボリックリンクは使用できません。')
        with path.open('rb') as file:return read_json(file.read(maximum+1), maximum)
    try:
        if args.cmd=='assess':result=assess(load(args.inventory),load(args.advisories),load(args.kev, 10*1024*1024))
        elif args.cmd=='tools':result=audit_tools(load(args.manifest),load(args.approved))
        else:result=refresh_kev(args.output)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (OSError,ValueError):p.exit(2,'入力・設定・取得状況を確認してください。実機操作は行っていません。\n')


if __name__=='__main__':main()
