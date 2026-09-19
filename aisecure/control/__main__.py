"""Integrated local console. Demo never contacts an AI provider or VPN appliance."""
import argparse
import os
from pathlib import Path
import secrets
import tempfile
from ..gateway import Evidence,DemoTransport,OpenAITransport
from ..workbench import key_from_env,token_from_env
from .audit import Audit
from .bundles import BundleGateway
from .documents import Scanner
from .service import App

def main(argv=None):
    p=argparse.ArgumentParser(description='資料検査・VPN台帳・高度分析・小さな監査ログ（開発版）')
    modes=p.add_mutually_exclusive_group();modes.add_argument('--demo',action='store_true');modes.add_argument('--live',action='store_true');modes.add_argument('--managed',action='store_true')
    p.add_argument('--port',type=int,default=8878);p.add_argument('--data-dir',type=Path)
    p.add_argument('--organization',default='local');p.add_argument('--source',default='collector')
    p.add_argument('--baseline-file',type=Path,help='管理者が確認した固定基準データ。UIからは更新不可')
    p.add_argument('--worker-image',help='事前構築・検証したPodmanイメージ@sha256:...')
    p.add_argument('--ack-managed-egress',action='store_true')
    args=p.parse_args(argv)
    if not 1024<=args.port<=65535:p.error('portは1024〜65535です。')
    from .common import ident
    ident(args.organization);ident(args.source)
    temp=None
    try:
        if args.live:
            if not args.data_dir or not args.worker_image or not args.ack_managed_egress:
                p.error('実送信には専用保存先・隔離解析イメージ・管理送信経路の確認が必要です。')
            master=key_from_env('AISECURE_GATEWAY_KEY');public=key_from_env('AISECURE_LABEL_PUBLIC_KEY')
            token=token_from_env('AISECURE_GATEWAY_TOKEN')
            collector=token_from_env('AISECURE_COLLECTOR_TOKEN') if os.environ.get('AISECURE_COLLECTOR_TOKEN') else None
            model=os.environ.get('AISECURE_OPENAI_MODEL','');transport=OpenAITransport(os.environ.get('OPENAI_API_KEY',''))
            scanner=Scanner('podman',args.worker_image);directory=args.data_dir
        elif args.managed:
            if not args.data_dir:p.error('管理モードには専用保存先が必要です。')
            master=key_from_env('AISECURE_GATEWAY_KEY');token=token_from_env('AISECURE_GATEWAY_TOKEN')
            collector=token_from_env('AISECURE_COLLECTOR_TOKEN') if os.environ.get('AISECURE_COLLECTOR_TOKEN') else None
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
            public=key_from_env('AISECURE_LABEL_PUBLIC_KEY') if os.environ.get('AISECURE_LABEL_PUBLIC_KEY') else Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
            model='inspection-only';transport=DemoTransport();directory=args.data_dir
            scanner=Scanner('podman',args.worker_image) if args.worker_image else Scanner()
        else:
            if args.data_dir:p.error('デモは一時保管です。--data-dirを外してください。')
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
            temp=tempfile.TemporaryDirectory(prefix='aisecure-control-demo-');directory=Path(temp.name)
            public=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
            master=secrets.token_bytes(32);token=secrets.token_urlsafe(32);collector=None
            model='demo-local';transport=DemoTransport();scanner=Scanner()
        evidence=Evidence(directory,master);audit=Audit(evidence,master)
        gateway=BundleGateway(audit,public,model,transport,args.organization,live=args.live,
                              stop_file=directory/'STOP',scanner=scanner,delivery_enabled=not args.managed)
        app=App(gateway,token,args.port,collector_token=collector,organization=args.organization,source=args.source,demo=not (args.live or args.managed))
        if args.baseline_file:
            from .analytics import load_baselines
            app.baselines=load_baselines(args.baseline_file,key=master,organization=args.organization)
        print(f'Open: http://127.0.0.1:{args.port}/#token={token}',flush=True)
        print('開発版 / 管理された経路だけが対象。ブラウザ全体・VPN封じ込めの保証ではありません。',flush=True)
        import uvicorn
        uvicorn.run(app,host='127.0.0.1',port=args.port,access_log=False,log_level='warning')
    except (OSError,ValueError):p.exit(2,'設定・依存関係・鍵・権限を確認してください。秘密情報は出力しません。\n')
    finally:
        if temp:temp.cleanup()

if __name__=='__main__':main()
