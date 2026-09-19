"""Explicit OFFLINE/operator tools. Private signing keys are never HTTP inputs."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
from .common import ControlError,canonical,decode
from .documents import Scanner,MAX_FILE
from .bundles import sign_bundle
from .response import plan,sign,ResponseController
from .vpn import PolicyTarget,FortiOSPolicyAdapter,assess_vpn
from .audit import Audit
from ..gateway import Evidence
from ..workbench import key_from_env


def load(path,maximum=24*1024*1024):
    if path.is_symlink():raise ControlError('リンクの入力は使用できません。')
    with path.open('rb') as stream:return decode(stream.read(maximum+1),maximum)

def output(path,data):
    # Deliberate private output; never silently overwrites data or prints secrets.
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data+b'\n')

def adapter(config):
    value=load(config,65536)
    if set(value)!={'target','deployment_verified','single_writer_verified'}:raise ControlError('機器設定が不正です。')
    target=PolicyTarget(**value['target'])
    return FortiOSPolicyAdapter(target,os.environ.get('AISECURE_FORTIOS_WRITE_TOKEN',''),
          deployment_verified=value['deployment_verified'] is True and value['single_writer_verified'] is True)

def main(argv=None):
    p=argparse.ArgumentParser(description='AISecure管理者専用コマンド。実機操作はexecuteだけ。')
    sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('inspect');a.add_argument('file',type=Path);a.add_argument('--worker-image');a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('label');a.add_argument('request',type=Path);a.add_argument('--model',required=True);a.add_argument('--organization',required=True);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('plan');a.add_argument('--config',type=Path,required=True);a.add_argument('--operation',choices=['disable_registered_rule','restore_registered_rule'],required=True);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('approve');a.add_argument('proposal',type=Path);a.add_argument('--approver',required=True);a.add_argument('--role',choices=['primary','secondary'],required=True);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('execute');a.add_argument('proposal',type=Path);a.add_argument('--config',type=Path,required=True);a.add_argument('--approval',type=Path,action='append',required=True);a.add_argument('--public-keys',type=Path,required=True);a.add_argument('--data-dir',type=Path,required=True);a.add_argument('--confirm',required=True);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('audit-export');a.add_argument('--data-dir',type=Path,required=True);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('vpn-assess');a.add_argument('input',type=Path);a.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv)
    evidence=None
    try:
        if args.cmd=='inspect':
            if args.file.is_symlink():raise ControlError('リンクは使用できません。')
            with args.file.open('rb') as stream:raw=stream.read(MAX_FILE+1)
            scanner=Scanner('podman',args.worker_image) if args.worker_image else Scanner()
            result=scanner.inspect(raw,args.file.suffix[1:].lower()).report()
        elif args.cmd=='label':
            request=load(args.request)
            if set(request)!={'question','files','request_id'}:raise ControlError('最終要求の項目が不正です。')
            result=sign_bundle(key_from_env('AISECURE_LABEL_PRIVATE_KEY'),**request,model=args.model,organization=args.organization)
        elif args.cmd=='plan':result=plan(adapter(args.config),args.operation)
        elif args.cmd=='approve':result=sign(key_from_env('AISECURE_APPROVAL_PRIVATE_KEY'),load(args.proposal),args.approver,args.role)
        elif args.cmd=='vpn-assess':result=assess_vpn(**load(args.input))
        else:
            key=key_from_env('AISECURE_GATEWAY_KEY');evidence=Evidence(args.data_dir,key);audit=Audit(evidence,key)
            if args.cmd=='audit-export':output(args.output,audit.export(1000));return 0
            if args.confirm!='EXECUTE REGISTERED VPN RULE CHANGE':raise ControlError('実機操作の確認文が必要です。')
            device=adapter(args.config);keys=load(args.public_keys,65536)
            keys={name:bytes.fromhex(value) for name,value in keys.items()}
            controller=ResponseController(audit,{device.target_id:device},keys,args.data_dir/'STOP')
            result=controller.execute(load(args.proposal),[load(path,16384) for path in args.approval],consent=True)
        output(args.output,canonical(result));print('結果を権限を制限したファイルへ保存しました。');return 0
    except Exception:
        p.exit(2,'処理を完了できませんでした。実操作を要求した場合、再試行する前に監査と機器の状態を確認してください。\n')
    finally:
        if evidence:evidence.close()
if __name__=='__main__':raise SystemExit(main())
