"""Offline operator tasks; signing authority is never exposed over HTTP.

Environment keys are supplied by the operator/secret manager. No key is silently
created for an existing live store. Never commit keys, labels or live evidence.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import time
from .gateway import Evidence, GatewayError, sign_label
from .workbench import key_from_env


def main(argv=None):
    p=argparse.ArgumentParser(description='分類証明・暗号化監査保管の管理。HTTP APIではありません。')
    sub=p.add_subparsers(dest='cmd',required=True)
    label=sub.add_parser('label')
    label.add_argument('--request-id',required=True);label.add_argument('--model',required=True)
    label.add_argument('--class',dest='data_class',required=True,choices=['public','internal','confidential','restricted'])
    for name in ['checkpoint','backup','prune']:
        parser=sub.add_parser(name);parser.add_argument('--data-dir',type=Path,required=True)
        if name=='backup':parser.add_argument('--output',type=Path,required=True)
        if name=='prune':
            parser.add_argument('--retain-days',type=int,default=30)
            parser.add_argument('--checkpoint-file',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        if args.cmd=='label':
            raw=sys.stdin.buffer.read(262145)
            if len(raw)>262144:raise GatewayError('本文が上限を超えています。')
            result=sign_label(key_from_env('AISECURE_LABEL_PRIVATE_KEY'),raw.decode('utf-8'),args.request_id,args.model,args.data_class)
        else:
            db=Evidence(args.data_dir,key_from_env('AISECURE_GATEWAY_KEY'))
            try:
                if args.cmd=='checkpoint':result=db.verify()
                elif args.cmd=='backup':
                    db.backup(args.output);result={'backup_created':True,'checkpoint':db.verify()}
                else:
                    if not 1<=args.retain_days<=3650:raise GatewayError('保持日数が不正です。')
                    # Require the exact current checkpoint to have been exported.
                    supplied=json.loads(args.checkpoint_file.read_text())
                    if supplied!=db.verify():raise GatewayError('独立保管した最新チェックポイントと一致しません。')
                    result=db.prune(int(time.time())-args.retain_days*86400)
            finally:db.close()
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (ValueError,OSError,ImportError):
        p.exit(2,'管理入力・外部鍵・権限・保管状態を確認してください。秘密情報は出力しません。\n')


if __name__=='__main__':main()
