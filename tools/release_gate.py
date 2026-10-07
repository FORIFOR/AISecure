"""Evidence-completeness gate, NOT a security certification or live verifier.

A person responsible for the environment must validate the referenced reports.
Code integration, screenshots and simulated tests cannot satisfy device gates.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import unicodedata

REQUIRED={'managed_pilot':{'provider_e2e','egress_e2e','classification_review','backup_restore','normal_business_evaluation'},
          'organization_production':{'provider_e2e','egress_e2e','classification_review','backup_restore','normal_business_evaluation',
              'dlp_device_e2e','vpn_device_e2e','okta_restore','identity_roles','key_rotation','retention_deletion','independent_security_review'}}


def missing(report):
    if type(report) is not dict:raise ValueError('invalid report')
    scope=report.get('scope')
    if type(scope) is not str or scope not in REQUIRED:raise ValueError('unknown scope')
    entries=report.get('evidence',[])
    if type(entries) is not list:raise ValueError('invalid evidence')
    seen=set();valid=set()
    for item in entries:
        if type(item) is not dict or set(item)!={'gate','status','environment','reviewer','sha256','executed_at'}:raise ValueError('invalid entry')
        gate=item['gate']
        if type(gate) is not str or gate not in REQUIRED[scope] or gate in seen:raise ValueError('invalid or duplicate gate')
        seen.add(gate)
        if item['status']!='pass':continue
        environment=item['environment']
        if (type(environment) is not str or not environment.strip()
                or len(environment)>200 or any(ord(c)<32 or ord(c)==127 for c in environment)):
            raise ValueError('invalid environment')
        if unicodedata.normalize('NFKC',environment).strip().casefold() in {'demo','synthetic','mock','unknown'}:continue
        if type(item['reviewer']) is not str or not item['reviewer'].strip():continue
        if type(item['sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',item['sha256']):continue
        try:
            at=datetime.fromisoformat(item['executed_at'].replace('Z','+00:00'))
            if at.tzinfo is None or at>datetime.now(timezone.utc):continue
        except (ValueError,TypeError,AttributeError):continue
        valid.add(gate)
    return sorted(REQUIRED[scope]-valid)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('report',type=Path,nargs='?');p.add_argument('--self-test',action='store_true');a=p.parse_args()
    if a.self_test:
        assert missing({'scope':'organization_production','evidence':[]})
        assert len(REQUIRED['organization_production'])==12
        def synthetic(environment):
            return {'scope':'managed_pilot','evidence':[
                {'gate':gate,'status':'pass','environment':environment,'reviewer':'self-test',
                 'sha256':'0'*64,'executed_at':datetime.now(timezone.utc).isoformat()}
                for gate in REQUIRED['managed_pilot']]}
        for label in ('demo',' DEMO ','Ｓｙｎｔｈｅｔｉｃ','UNKNOWN'):
            assert missing(synthetic(label))
        for invalid in (None,False,123,'   '):
            try:missing(synthetic(invalid))
            except ValueError:pass
            else:raise AssertionError('invalid environment passed')
        print('PASS: empty, malformed and synthetic evidence cannot pass the release gate')
    elif a.report:
        try:
            gaps=missing(json.loads(a.report.read_text()))
            print(json.dumps({'missing':gaps,'evidence_manifest_complete':not gaps,'evidence_authenticity_independently_verified':False},indent=2))
            raise SystemExit(2 if gaps else 0)
        except ValueError:p.exit(3,'Invalid evidence manifest\n')
    else:p.error('report or --self-test is required')
