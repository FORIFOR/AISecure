"""Managed text gateway: inspect the exact final input before a fixed transport.

Not host-wide DLP. The caller/process, administrator configuration and OS must
be trusted. The live server holds a label VERIFICATION key, never a signing key.
Provider errors after dispatch are uncertain, not proof that no data was sent.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from typing import Protocol

from .preflight import Request, Policy, Grant, evaluate, MAX_TEXT_BYTES, InputError
from .schema import canonical
from .storage import StorageCipher
from .safety import EmergencyStop

ENDPOINT = 'https://api.openai.com/v1/responses'
POLICY_VERSION = 'managed-text-v1'
MAX_REPLY = 2 * 1024 * 1024
REQUEST_ID = re.compile(r'[a-f0-9]{32}\Z')
CLASSES = frozenset({'public', 'internal', 'confidential', 'restricted'})


class GatewayError(ValueError):
    """No user input, provider response, credential or path in error messages."""


class DeliveryUnknown(RuntimeError):
    pass


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def unb64(value: str, length: int) -> bytes:
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', value):
        raise GatewayError('署名の形式を確認してください。')
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except ValueError:
        raise GatewayError('署名を確認できません。') from None
    if len(raw) != length:
        raise GatewayError('署名の長さを確認してください。')
    return raw


def valid_text(text: str, request_id: str) -> None:
    if type(request_id) is not str or not REQUEST_ID.fullmatch(request_id):
        raise GatewayError('新しいリクエストIDを指定してください。')
    if type(text) is not str or not text.strip():
        raise GatewayError('検査するテキストが必要です。')
    try:
        if len(text.encode('utf-8')) > MAX_TEXT_BYTES:
            raise GatewayError('検査上限を超えています。分割して迂回せず管理者へ確認してください。')
    except UnicodeError:
        raise GatewayError('テキストの文字コードが不正です。') from None


def wire_body(text: str, model: str) -> bytes:
    """No hidden memory, prior response ID, tools, attachments or extra prompts."""
    return canonical({'model': model, 'input': text, 'store': False,
                      'stream': False, 'tools': [], 'max_output_tokens': 512}).encode()


def sign_label(private_key: bytes, text: str, request_id: str, model: str,
               data_class: str, *, now: int | None = None) -> dict:
    """Offline administrator operation. Not exposed on the gateway HTTP API."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    valid_text(text, request_id)
    if type(data_class) is not str or data_class not in CLASSES:
        raise GatewayError('分類が不正です。')
    now = int(time.time()) if now is None else now
    claim = {'request_id': request_id, 'sha256': hashlib.sha256(wire_body(text, model)).hexdigest(),
             'model': model, 'endpoint': ENDPOINT, 'policy': POLICY_VERSION,
             'data_class': data_class, 'issued_at': now, 'expires_at': now + 300}
    return {'claim': claim, 'signature': b64(Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical(claim).encode()))}


def verify_label(label: dict | None, public_key: bytes, text: str, request_id: str,
                 model: str, now: int) -> str:
    if label is None:
        return 'unknown'
    if type(label) is not dict or set(label) != {'claim', 'signature'}:
        raise GatewayError('管理者の分類証明を確認できません。')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    claim = label['claim']
    if type(claim) is not dict or set(claim) != {'request_id', 'sha256', 'model', 'endpoint', 'policy', 'data_class', 'issued_at', 'expires_at'}:
        raise GatewayError('分類証明の項目が不正です。')
    expected = {'request_id': request_id, 'sha256': hashlib.sha256(wire_body(text, model)).hexdigest(),
                'model': model, 'endpoint': ENDPOINT, 'policy': POLICY_VERSION}
    if any(claim[k] != v for k, v in expected.items()):
        raise GatewayError('分類証明は、現在の本文・送信先・モデルに対応していません。')
    if type(claim['data_class']) is not str or claim['data_class'] not in CLASSES:
        raise GatewayError('分類証明の分類が不正です。')
    issued, expires = claim['issued_at'], claim['expires_at']
    if (type(issued) is not int or type(expires) is not int or
            not now - 300 <= issued <= now + 15 or not now < expires <= issued + 300):
        raise GatewayError('分類証明の期限が切れています。再確認してください。')
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(unb64(label['signature'], 64), canonical(claim).encode())
    except Exception:
        raise GatewayError('分類証明の署名を検証できません。') from None
    return claim['data_class']


class Evidence:
    """Bounded encrypted journal and durable at-most-one dispatch reservation.

    Same-host key compromise is out of scope. Tail truncation requires an
    independently retained checkpoint. Payloads are metadata, never text/replies.
    """
    def __init__(self, directory: Path, master_key: bytes, limit: int = 20000):
        if type(master_key) is not bytes or len(master_key) != 32:
            raise GatewayError('外部管理鍵は32バイトで指定してください。')
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink():
            raise GatewayError('保管ディレクトリにシンボリックリンクは使用できません。')
        if os.name != 'nt' and directory.stat().st_mode & 0o077:
            raise GatewayError('保管ディレクトリは所有者だけが読める権限にしてください。')
        path = directory / 'gateway.sqlite3'
        if path.is_symlink():
            raise GatewayError('保管ファイルを確認できません。')
        self.key = hmac.digest(master_key, b'gateway-journal-v1', 'sha256')
        self.cipher = StorageCipher(hmac.digest(master_key, b'gateway-encryption-v1', 'sha256'))
        self.limit, self.lock = limit, threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=5)
        if os.name != 'nt':
            path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
          CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY, at INTEGER, payload TEXT, prev TEXT, mac TEXT);
          CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, fingerprint TEXT, report TEXT, at INTEGER);''')
        check = hmac.new(self.key, b'gateway-key-check', hashlib.sha256).hexdigest()
        old = self.db.execute("SELECT v FROM meta WHERE k='key'").fetchone()
        if old and not hmac.compare_digest(old['v'], check):
            self.db.close()
            raise GatewayError('保管鍵が一致しません。新しい鍵で上書きしません。')
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('key',?)", (check,))
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('anchor',?)", ('0'*64,))
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('anchor_seq','0')")
        self.verify()

    def digest(self, body: bytes) -> str:
        return hmac.new(self.key, b'request\0' + body, hashlib.sha256).hexdigest()

    def _mac(self, seq, at, payload, prev):
        return hmac.new(self.key, canonical([seq, at, payload, prev]).encode(), hashlib.sha256).hexdigest()

    def verify(self) -> dict:
        with self.lock:
            prev = self.db.execute("SELECT v FROM meta WHERE k='anchor'").fetchone()['v']
            seq = int(self.db.execute("SELECT v FROM meta WHERE k='anchor_seq'").fetchone()['v'])
            for row in self.db.execute('SELECT * FROM journal ORDER BY seq'):
                if row['seq'] != seq + 1 or row['prev'] != prev or not hmac.compare_digest(row['mac'], self._mac(row['seq'], row['at'], row['payload'], prev)):
                    raise GatewayError('監査記録が不整合です。送信を停止します。')
                self.cipher.decrypt(row['payload'], f"event:{row['seq']}")
                seq, prev = row['seq'], row['mac']
            return {'seq': seq, 'mac': prev, 'independent_anchor_required': True}

    def _append(self, report):
        checkpoint = self.verify()
        if self.db.execute('SELECT count(*) FROM journal').fetchone()[0] >= self.limit:
            raise GatewayError('監査記録の上限です。保管・保持手順を確認してください。')
        seq, at = checkpoint['seq'] + 1, int(time.time())
        body = self.cipher.encrypt(canonical(report), f'event:{seq}')
        self.db.execute('INSERT INTO journal VALUES(?,?,?,?,?)', (seq, at, body, checkpoint['mac'], self._mac(seq, at, body, checkpoint['mac'])))

    def append(self, report):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self._append(report)
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise

    def reserve(self, request_id: str, fingerprint: str, initial: dict) -> dict | None:
        with self.lock:
            self.verify()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row = self.db.execute('SELECT * FROM receipts WHERE id=?', (request_id,)).fetchone()
                if row:
                    if not hmac.compare_digest(row['fingerprint'], fingerprint):
                        raise GatewayError('同じIDで本文や分類を変更できません。新しいIDで再検査してください。')
                    result = json.loads(self.cipher.decrypt(row['report'], 'receipt:' + request_id))
                    self.db.execute('COMMIT')
                    return {**result, 'replayed': True}
                for event in self.db.execute('SELECT seq,payload FROM journal'):
                    prior_event = json.loads(self.cipher.decrypt(event['payload'], f"event:{event['seq']}"))
                    if prior_event.get('kind') in {'text_request', 'bundle_request', 'response_request'} and prior_event.get('request_id') == request_id:
                        raise GatewayError('送信予約の記録が不整合です。再送しません。')
                # Reserve capacity for both intent and result, including concurrent requests.
                count = self.db.execute('SELECT count(*) FROM journal').fetchone()[0]
                pending = sum(json.loads(self.cipher.decrypt(r['report'], 'receipt:' + r['id'])).get('execution_state') == 'dispatch_pending'
                              for r in self.db.execute('SELECT id,report FROM receipts'))
                if count + pending + 2 > self.limit:
                    raise GatewayError('監査容量が不足しています。送信しません。')
                self.db.execute('INSERT INTO receipts VALUES(?,?,?,?)', (request_id, fingerprint, self.cipher.encrypt(canonical(initial), 'receipt:' + request_id), int(time.time())))
                self._append(initial)
                self.db.execute('COMMIT')
                return None
            except Exception:
                self.db.execute('ROLLBACK')
                raise

    def finish(self, request_id: str, report: dict):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self._append(report)
                self.db.execute('UPDATE receipts SET report=? WHERE id=?', (self.cipher.encrypt(canonical(report), 'receipt:' + request_id), request_id))
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise

    def history(self):
        with self.lock:
            self.verify()
            return [{**json.loads(self.cipher.decrypt(r['payload'], f"event:{r['seq']}")), 'seq': r['seq'], 'at': r['at']}
                    for r in self.db.execute('SELECT * FROM journal ORDER BY seq DESC LIMIT 100')]

    def observations(self):
        with self.lock:
            self.verify()
            result = []
            for r in self.db.execute('SELECT seq,payload FROM journal ORDER BY seq DESC LIMIT 10000'):
                event = json.loads(self.cipher.decrypt(r['payload'], f"event:{r['seq']}"))
                if event.get('kind') == 'dlp_observation': result.append(event)
            return result

    def prune(self, before: int) -> dict:
        """Offline maintenance after independent checkpoint backup; never via UI."""
        if type(before) is not int or before > int(time.time()) - 86400:
            raise GatewayError('最低1日分の記録を残してください。')
        with self.lock:
            old = self.verify()
            rows = self.db.execute('SELECT * FROM journal ORDER BY seq').fetchall()
            prefix = []
            for r in rows:
                if r['at'] >= before: break
                prefix.append(r)
            if not prefix: return {'pruned': 0, 'checkpoint': old}
            self.db.execute('BEGIN IMMEDIATE')
            try:
                last = prefix[-1]
                self.db.execute("UPDATE meta SET v=? WHERE k='anchor'", (last['mac'],))
                self.db.execute("UPDATE meta SET v=? WHERE k='anchor_seq'", (str(last['seq']),))
                self.db.execute('DELETE FROM journal WHERE seq<=?', (last['seq'],))
                self.db.execute('DELETE FROM receipts WHERE at<?', (before,))
                self._append({'kind': 'retention', 'pruned': len(prefix), 'previous_checkpoint': old})
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK')
                raise
            self.db.execute('VACUUM')
            return {'pruned': len(prefix), 'checkpoint': self.verify()}

    def backup(self, target: Path):
        target = Path(target)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with self.lock:
            self.verify()
            dest = sqlite3.connect(target)
            try: self.db.backup(dest)
            finally: dest.close()

    def close(self):
        self.db.close()


class Transport(Protocol):
    def send(self, body: bytes) -> str: ...


class PinnedHTTPS(http.client.HTTPSConnection):
    """Resolve once, reject non-public IPs, connect to checked IP with SNI/TLS.

    No proxy env support, redirect following or automatic application retry.
    """
    def connect(self):
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise DeliveryUnknown('接続先の検証に失敗しました。')
        address = addresses[0]
        sock = socket.socket(address[0], address[1], address[2])
        sock.settimeout(self.timeout)
        try:
            sock.connect(address[4])
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class OpenAITransport:
    """Text-only Responses API. store=false is NOT a zero retention guarantee."""
    def __init__(self, api_key: str):
        if type(api_key) is not str or len(api_key) < 16 or not api_key.isascii() or any(c.isspace() for c in api_key):
            raise GatewayError('API鍵が未設定または不正です。')
        self._key = api_key

    def send(self, body: bytes) -> str:
        conn = PinnedHTTPS('api.openai.com', timeout=25, context=ssl.create_default_context())
        try:
            conn.request('POST', '/v1/responses', body=body,
                         headers={'Authorization': 'Bearer ' + self._key, 'Content-Type': 'application/json'})
            response = conn.getresponse()
            data = response.read(MAX_REPLY + 1)
            if response.status != 200 or len(data) > MAX_REPLY:
                raise DeliveryUnknown('送信後の結果を確認できません。自動再送しません。')
            obj = json.loads(data)
            if obj.get('status') != 'completed':
                raise DeliveryUnknown('送信後の完了を確認できません。')
            parts = []
            for item in obj.get('output', []):
                if item.get('type') == 'message':
                    for content in item.get('content', []):
                        if content.get('type') == 'output_text' and type(content.get('text')) is str:
                            parts.append(content['text'])
            return '\n'.join(parts)[:20000]
        except Exception:
            raise DeliveryUnknown('送信結果は未確認です。本文が届いていないとは断定しません。') from None
        finally:
            conn.close()


class DemoTransport:
    def send(self, body: bytes) -> str:
        return 'デモ受信器が検査済みの本文を受け取りました。外部AIへの送信ではありません。'


@dataclass(frozen=True)
class Prepared:
    request_id: str
    text: str
    data_class: str
    body: bytes
    fingerprint: str
    report: dict


class Gateway:
    def __init__(self, evidence: Evidence, public_key: bytes, model: str, transport: Transport,
                 *, mode='demo', stop: Path | None = None):
        if type(model) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}', model):
            raise GatewayError('管理者がモデルを設定してください。')
        if mode not in {'demo', 'openai'} or len(public_key) != 32:
            raise GatewayError('送信設定が不正です。')
        self.evidence, self.public_key, self.model, self.transport = evidence, public_key, model, transport
        self.mode, self.stop = mode, EmergencyStop(stop)
        self.policy = Policy((Grant('ai.prompt', ENDPOINT, ('public',)),))

    def prepare(self, text: str, request_id: str, label: dict | None = None) -> Prepared:
        valid_text(text, request_id)
        data_class = verify_label(label, self.public_key, text, request_id, self.model, int(time.time()))
        event = Request('EV-' + str(int(request_id[:9], 16)), 'ai.prompt', ENDPOINT, text, data_class)
        decision = evaluate(event, self.policy)
        report = {**decision.report(), 'request_id': request_id, 'data_class': data_class,
                  'mode': self.mode, 'kind': 'text_request', 'next_steps': (
                    ['送信しません。機密情報を除いた新しい本文で再検査してください。'] if decision.decision == 'block' else
                    ['送信しません。管理者へ本文を確認してもらい、期限付き分類証明を取得してください。'] if decision.decision == 'review' else
                    ['送信先と本文を確認してから、明示的に送信してください。'])}
        body = wire_body(text, self.model)
        # Include classification in idempotency: a changed label requires a new ID.
        fingerprint = self.evidence.digest(body + b'\0' + data_class.encode())
        return Prepared(request_id, text, data_class, body, fingerprint, report)

    def check(self, text: str, request_id: str, label=None) -> dict:
        p = self.prepare(text, request_id, label)
        self.evidence.append({**p.report, 'kind': 'inspection'})
        return p.report

    def send(self, text: str, request_id: str, label=None, *, consent=False) -> dict:
        if consent is not True:
            raise GatewayError('送信には明示的な確認が必要です。')
        p = self.prepare(text, request_id, label)
        self.stop.assert_clear()
        initial = {**p.report, 'execution_state': 'dispatch_pending' if p.report['decision'] == 'allow' else 'prevented_in_gateway'}
        prior = self.evidence.reserve(request_id, p.fingerprint, initial)
        if prior is not None:
            return prior
        if p.report['decision'] != 'allow':
            return initial
        try:
            # Recheck the operator stop immediately before dispatch. No fallback.
            self.stop.assert_clear()
            output = self.transport.send(p.body)
            final = {**p.report, 'execution_state': 'demo_received' if self.mode == 'demo' else 'provider_completed'}
        except Exception:
            final = {**p.report, 'execution_state': 'delivery_unknown',
                     'next_steps': ['自動再送はしません。送信先の記録を確認してください。']}
            output = None
        self.evidence.finish(request_id, final)
        # Reply is displayed once, never persisted or sent to the explanation LLM.
        return {**final, **({'output': output} if output is not None else {})}
