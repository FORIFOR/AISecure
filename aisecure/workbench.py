"""Loopback ASGI workbench. Explicit demo by default; live mode is opt-in.

Run with python -m aisecure.workbench --demo. No third-party browser connection,
no HTTP classification/approval authority, no provider key in the client.
"""
from __future__ import annotations
import argparse
import asyncio
from collections import defaultdict, deque
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import uuid

from .gateway import (Gateway, GatewayError, Evidence, DemoTransport, OpenAITransport,
                      sign_label, b64, unb64, ENDPOINT)
from .preflight import decode, InputError
from .explain import Explainer

WEB = Path(__file__).parent / 'workbench_web'
SAMPLES = {
    'public': ('公開済みの製品説明を、分かりやすい一文にしてください。', 'public'),
    'confidential': ('社内の顧客管理資料です。この情報は外部に送信しません。', 'confidential'),
    'secret': ('api_key=synthetic-demo-credential-not-a-real-key', 'public'),
    'unknown': ('分類がまだ確認されていない業務メモです。', None),
}
LIMIT = 1024 * 1024


def key_from_env(name):
    value = os.environ.get(name, '')
    try: key = bytes.fromhex(value)
    except ValueError: key = b''
    if len(key) != 32:
        raise GatewayError(f'{name}に32バイトの外部管理鍵が必要です。')
    return key


def token_from_env(name):
    value = os.environ.get(name, '')
    if len(value) < 32 or not value.isascii() or any(c.isspace() for c in value):
        raise GatewayError(f'{name}に十分な長さの専用トークンが必要です。')
    return value


class App:
    def __init__(self, gateway: Gateway, token: str, port: int, *, demo_key: bytes | None = None,
                 collector_token: str | None = None, model: str | None = None, posture_loader=None):
        if collector_token is not None and hmac.compare_digest(token, collector_token):
            raise GatewayError('利用者と収集器のトークンは分離してください。')
        self.gateway, self.token, self.port = gateway, token, port
        self.demo_key, self.collector_token = demo_key, collector_token
        self.explainer = Explainer(model)
        self.posture_loader = posture_loader
        self.limits = defaultdict(deque)
        self.started_at = int(time.time())
        self.last_ingest = None

    def rate_ok(self, identity: str):
        now = time.monotonic()
        q = self.limits[identity]
        while q and q[0] < now - 60: q.popleft()
        if len(q) >= 60: return False
        q.append(now)
        return True

    def headers(self, mime='application/json; charset=utf-8'):
        return [(b'content-type', mime.encode()), (b'cache-control', b'no-store'),
                (b'x-content-type-options', b'nosniff'), (b'x-frame-options', b'DENY'),
                (b'referrer-policy', b'no-referrer'),
                (b'content-security-policy', b"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")]

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            while True:
                event = await receive()
                if event['type'] == 'lifespan.startup': await send({'type': 'lifespan.startup.complete'})
                if event['type'] == 'lifespan.shutdown':
                    await send({'type': 'lifespan.shutdown.complete'}); return
        if scope['type'] != 'http': return
        status, mime = 200, 'application/json; charset=utf-8'
        try:
            status, output, mime = await self.route(scope, receive)
        except (GatewayError, InputError, ValueError, TypeError, KeyError):
            status, output = 400, {'error': '入力・権限・分類証明を確認してください。処理が拒否されました。'}
        except Exception:
            # Never echo payloads, SQL, paths, provider messages or credentials.
            status, output = 503, {'error': '処理結果を確認できません。送信操作を自動再試行しないでください。'}
        body = output if isinstance(output, bytes) else json.dumps(output, ensure_ascii=False).encode()
        await send({'type': 'http.response.start', 'status': status,
                    'headers': self.headers(mime) + [(b'content-length', str(len(body)).encode())]})
        await send({'type': 'http.response.body', 'body': body})

    async def route(self, scope, receive):
        items = scope.get('headers', [])
        headers = {k.lower(): v for k, v in items}
        for name in (b'host', b'authorization', b'origin', b'content-length', b'content-type'):
            if sum(k.lower() == name for k, _ in items) > 1:
                return 400, {'error': '重複するヘッダーは使用できません。'}, 'application/json'
        host = f'127.0.0.1:{self.port}'.encode()
        if headers.get(b'host') != host or scope.get('query_string'):
            return 403, {'error': '接続先またはURLが不正です。'}, 'application/json'
        origin = headers.get(b'origin')
        if origin is not None and origin != b'http://' + host:
            return 403, {'error': '別サイトからの操作を拒否しました。'}, 'application/json'
        if headers.get(b'sec-fetch-site') not in (None, b'same-origin', b'none'):
            return 403, {'error': '別サイトからの操作を拒否しました。'}, 'application/json'
        method, path = scope['method'], scope['path']
        assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/app.css': ('app.css', 'text/css; charset=utf-8')}
        if path in assets and method == 'GET':
            file, mime = assets[path]
            return 200, (WEB / file).read_bytes(), mime
        expected = self.collector_token if path == '/api/ingest' else self.token
        auth = headers.get(b'authorization', b'')
        if not expected or not hmac.compare_digest(auth, ('Bearer ' + expected).encode()):
            return 401, {'error': '認証が必要です。'}, 'application/json'
        identity = 'collector' if path == '/api/ingest' else 'user'
        if not self.rate_ok(identity):
            return 429, {'error': '操作回数の上限です。少し間隔を空けてください。'}, 'application/json'
        if method == 'GET' and path == '/api/state':
            history = await asyncio.to_thread(self.gateway.evidence.history)
            from .posture import dlp_findings
            observations = await asyncio.to_thread(self.gateway.evidence.observations)
            posture = {'findings': [], 'scope': 'not_connected', 'live_device_verified': False}
            if self.posture_loader:
                try: posture = await asyncio.to_thread(self.posture_loader)
                except Exception: posture = {'findings': [], 'scope': 'collection_failed_or_invalid', 'live_device_verified': False}
            return 200, {'mode': self.gateway.mode, 'history': history, 'posture': posture, 'dlp_findings': dlp_findings(observations),
                'coverage': {'managed_text': True, 'provider': self.gateway.mode,
                    'whole_device': False, 'vpn_enforcement': False, 'egress_verified': False,
                    'collector_configured': bool(self.collector_token),
                    'collector_last_seen': self.last_ingest,
                    'collector_stale': self.last_ingest is None or time.time() - self.last_ingest > 300},
                'checkpoint': self.gateway.evidence.verify(),
                'samples': list(SAMPLES) if self.demo_key else []}, 'application/json'
        if method != 'POST' or path not in {'/api/check', '/api/send', '/api/explain', '/api/ingest'}:
            return 404, {'error': '未対応の操作です。'}, 'application/json'
        if headers.get(b'content-type', b'').split(b';')[0] != b'application/json':
            return 415, {'error': 'JSON形式で送信してください。'}, 'application/json'
        if b'transfer-encoding' in headers:
            return 400, {'error': '未対応の転送方式です。'}, 'application/json'
        raw = bytearray()
        deadline = time.monotonic() + 10
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise GatewayError('入力の受信がタイムアウトしました。')
            event = await asyncio.wait_for(receive(), timeout=min(5, remaining))
            if event['type'] == 'http.disconnect': raise GatewayError('切断されました。')
            raw.extend(event.get('body', b''))
            if len(raw) > LIMIT:
                return 413, {'error': '入力が上限を超えています。'}, 'application/json'
            if not event.get('more_body'): break
        value = decode(bytes(raw))
        if type(value) is not dict:
            raise GatewayError('JSONオブジェクトが必要です。')
        if path == '/api/ingest':
            from .posture import normalize_dlp
            report = normalize_dlp(value, self.gateway.evidence.digest)
            event_key = hashlib.sha256(('collector:' + report['source'] + ':' + report['event_id']).encode()).hexdigest()[:32]
            fingerprint = self.gateway.evidence.digest(json.dumps(report, sort_keys=True).encode())
            previous = await asyncio.to_thread(self.gateway.evidence.reserve, event_key, fingerprint, report)
            self.last_ingest = int(time.time())
            return 200, {'accepted': True, 'duplicate': previous is not None, 'enforcement_verified': False}, 'application/json'
        if path == '/api/explain':
            if set(value) != {'seq'} or type(value['seq']) is not int:
                raise GatewayError('証跡を選択してください。')
            rows = await asyncio.to_thread(self.gateway.evidence.history)
            row = next((r for r in rows if r['seq'] == value['seq'] and r.get('kind') in {'inspection', 'text_request'}), None)
            if row is None: raise GatewayError('証跡を確認できません。')
            # Only fixed generated reasons and a generated ID, not source text.
            finding = {'rule': 'PREFLIGHT', 'priority': 'P2', 'title': '送信前チェック',
                       'reasons': row['reasons'], 'evidence_ids': [row['event_id']]}
            answer = await asyncio.to_thread(self.explainer.explain, finding, bool(self.explainer.model))
            return 200, answer, 'application/json'
        allowed = {'request_id', 'text', 'label', 'sample', 'consent'}
        if not set(value) <= allowed or 'request_id' not in value:
            raise GatewayError('未対応の項目があります。')
        text, label = value.get('text'), value.get('label')
        if 'sample' in value:
            if not self.demo_key or 'text' in value or 'label' in value or value['sample'] not in SAMPLES:
                raise GatewayError('サンプルはデモ専用です。')
            text, cls = SAMPLES[value['sample']]
            label = sign_label(self.demo_key, text, value['request_id'], self.gateway.model, cls) if cls else None
        fn = self.gateway.send if path == '/api/send' else self.gateway.check
        kwargs = {'consent': value.get('consent') is True} if path == '/api/send' else {}
        result = await asyncio.to_thread(fn, text, value['request_id'], label, **kwargs)
        return 200, result, 'application/json'


def main(argv=None):
    parser = argparse.ArgumentParser(description='AISecure送信前チェック。管理されたローカル環境専用。')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--demo', action='store_true')
    modes.add_argument('--live', action='store_true', help='実OpenAI送信を有効化。費用と外部送信が発生します。')
    parser.add_argument('--port', type=int, default=8877)
    parser.add_argument('--data-dir', type=Path)
    parser.add_argument('--ollama-model')
    parser.add_argument('--ack-managed-egress', action='store_true')
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--advisories', type=Path)
    parser.add_argument('--kev', type=Path)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535: parser.error('portは1024〜65535です。')
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        import uvicorn
        temp = None
        if args.live:
            if not args.ack_managed_egress or args.data_dir is None:
                raise GatewayError('実送信には専用保存先と--ack-managed-egressが必要です。組み込み先の通信制限を確認してください。')
            master = key_from_env('AISECURE_GATEWAY_KEY')
            public_key = key_from_env('AISECURE_LABEL_PUBLIC_KEY')
            token = token_from_env('AISECURE_GATEWAY_TOKEN')
            collector = token_from_env('AISECURE_COLLECTOR_TOKEN') if os.environ.get('AISECURE_COLLECTOR_TOKEN') else None
            model = os.environ.get('AISECURE_OPENAI_MODEL', '')
            transport = OpenAITransport(os.environ.get('OPENAI_API_KEY', ''))
            demo_key = None
            directory = args.data_dir
        else:
            if args.data_dir is not None:
                raise GatewayError('デモは一時保存専用です。--data-dirを外してください。')
            temp = tempfile.TemporaryDirectory(prefix='aisecure-demo-')
            directory, master, token, collector, model = Path(temp.name), secrets.token_bytes(32), secrets.token_urlsafe(32), None, 'demo-local'
            private = Ed25519PrivateKey.generate()
            demo_key = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            public_key = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            transport = DemoTransport()
        evidence = Evidence(directory, master)
        gateway = Gateway(evidence, public_key, model, transport, mode='openai' if args.live else 'demo', stop=directory / 'STOP')
        posture_loader = None
        if any((args.inventory, args.advisories, args.kev)):
            if not all((args.inventory, args.advisories, args.kev)):
                raise GatewayError('資産台帳・ベンダー情報・KEVの3ファイルを指定してください。')
            def posture_loader():
                from .posture import assess
                from .schema import read_json
                docs = []
                for path in (args.inventory, args.advisories, args.kev):
                    if path.is_symlink(): raise GatewayError('台帳のリンクを確認してください。')
                    with path.open('rb') as f: docs.append(read_json(f.read(10*1024*1024+1), 10*1024*1024))
                return assess(*docs)
        app = App(gateway, token, args.port, demo_key=demo_key, collector_token=collector, model=args.ollama_model, posture_loader=posture_loader)
        print('Live provider: OpenAI (料金・外部送信あり)' if args.live else 'Demo only: 外部AIへ送信しません。一時記録は終了時に削除します。', flush=True)
        print(f'Open: http://127.0.0.1:{args.port}/#token={token}', flush=True)
        print('端末全体・VPNは未監視。トークン付きURLを共有しないでください。', flush=True)
        try:
            uvicorn.run(app, host='127.0.0.1', port=args.port, proxy_headers=False,
                        access_log=False, server_header=False, limit_concurrency=16,
                        timeout_keep_alive=5, log_level='warning')
        finally:
            evidence.close()
            if temp: temp.cleanup()
    except (GatewayError, ImportError) as exc:
        if isinstance(exc, ImportError):
            parser.exit(2, "起動依存を導入してください: python -m pip install '.[workbench]'\n")
        parser.exit(2, str(exc) + '\n')


if __name__ == '__main__': main()
