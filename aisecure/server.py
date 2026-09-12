"""Loopback-only development UI. Not an Internet-facing production server."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlsplit
from .schema import read_json, canonical, object_keys, MAX_BYTES, ValidationError
from .store import Store, ConflictError, IntegrityError
from .demo import sample
from .explain import Explainer

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, store: Store, port: int = 8765, model: str | None = None):
        self.store = store
        self.token = secrets.token_urlsafe(32)
        self.explainer = Explainer(model)
        self.llm_gate = threading.Lock()
        self.rate_lock = threading.Lock()
        self.last_mutations: list[float] = []
        super().__init__(("127.0.0.1", port), Handler)
        self.host_header = f"127.0.0.1:{self.server_port}"
        self.origin = "http://" + self.host_header

    def rate_allowed(self) -> bool:
        with self.rate_lock:
            now = time.monotonic()
            self.last_mutations = [t for t in self.last_mutations if now - t < 60]
            if len(self.last_mutations) >= 40:
                return False
            self.last_mutations.append(now)
            return True


class Handler(BaseHTTPRequestHandler):
    server_version = "AI-Secure-Local/0.1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(8)

    def log_message(self, *_):
        # Avoid tokens, payloads, filenames, and personal identifiers in access logs.
        pass

    def reply(self, status: int, data, content_type: str = "application/json; charset=utf-8"):
        raw = canonical(data).encode() if not isinstance(data, bytes) else data
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def guard(self, api: bool) -> bool:
        if self.headers.get("Host") != self.server.host_header:
            self.reply(403, {"error": "許可されていないHostです。127.0.0.1でアクセスしてください。"})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != self.server.origin:
            self.reply(403, {"error": "異なるOriginからの操作は許可しません。"})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.reply(403, {"error": "クロスサイトの要求は拒否しました。"})
            return False
        if api:
            expected = ("Bearer " + self.server.token).encode()
            received = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(received, expected):
                self.reply(401, {"error": "起動時に表示されたアクセストークンが必要です。"})
                return False
        return True

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if not self.guard(path.startswith("/api/")):
            return
        if parts.query:
            self.reply(400, {"error": "クエリ文字列は受け付けません。"})
            return
        try:
            if path == "/api/state":
                state = self.server.store.state()
                state["llm"] = {"configured": bool(self.server.explainer.model), "requested_model": self.server.explainer.model, "default_provider": "deterministic-template", "real_connection_tested": False}
                self.reply(200, state)
            elif path == "/api/export":
                state = self.server.store.state()
                # Dataset + findings + truncated UI audit log; not a forensic acquisition.
                self.server.store.record("report.exported", {"snapshot_id": state["snapshot_id"]})
                self.reply(200, self.server.store.state())
            elif path in {"/", "/index.html", "/style.css", "/app.js"}:
                name = "index.html" if path == "/" else path[1:]
                content = {"index.html": "text/html; charset=utf-8", "style.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8"}[name]
                self.reply(200, (WEB_DIR / name).read_bytes(), content)
            else:
                self.reply(404, {"error": "見つかりません。"})
        except IntegrityError:
            self.reply(409, {"error": "保存データの完全性検証に失敗しました。変更を停止してください。"})
        except Exception:
            self.reply(500, {"error": "ローカル処理に失敗しました。"})

    def do_POST(self):
        if not self.guard(True):
            return
        parts = urlsplit(self.path)
        if parts.query:
            self.reply(400, {"error": "クエリ文字列は受け付けません。"})
            return
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            self.reply(400, {"error": "単一のContent-Lengthが必要です。"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.reply(400, {"error": "Content-Lengthが不正です。"})
            return
        if not 1 <= length <= MAX_BYTES:
            self.reply(413, {"error": "要求は2 MiB以下にしてください。"})
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self.reply(415, {"error": "application/jsonのみ受け付けます。"})
            return
        if not self.server.rate_allowed():
            self.reply(429, {"error": "操作回数が上限に達しました。少し間をあけてください。"})
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValidationError("要求が途中で切れています。")
            body = read_json(raw)
            path = parts.path
            if path == "/api/demo":
                object_keys(body, {"confirm"})
                if body["confirm"] != "LOAD SYNTHETIC DATA":
                    raise ValidationError("デモ読み込みの確認が必要です。")
                sid = self.server.store.ingest(sample(), "demo")
                self.reply(200, {"snapshot_id": sid, "source_mode": "demo"})
            elif path == "/api/ingest":
                sid = self.server.store.ingest(body)
                self.reply(200, {"snapshot_id": sid, "source_mode": "imported"})
            elif path == "/api/plan":
                object_keys(body, {"snapshot_id", "finding_id"})
                self.reply(200, self.server.store.propose(body["snapshot_id"], body["finding_id"]))
            elif path == "/api/approve":
                object_keys(body, {"proposal_id", "snapshot_id", "confirmation", "reason"})
                self.reply(200, self.server.store.approve_and_simulate(body["proposal_id"], body["snapshot_id"], body["confirmation"], body["reason"]))
            elif path == "/api/explain":
                object_keys(body, {"snapshot_id", "finding_id", "use_llm"})
                if type(body["use_llm"]) is not bool:
                    raise ValidationError("use_llmは真偽値が必要です。")
                f = self.server.store.get_finding(body["snapshot_id"], body["finding_id"])
                if not self.server.llm_gate.acquire(blocking=False):
                    raise ConflictError("説明処理が進行中です。")
                try:
                    explanation = self.server.explainer.explain(f, body["use_llm"])
                    # Prevent attaching an explanation to a different current input.
                    self.server.store.get_finding(body["snapshot_id"], body["finding_id"])
                    self.server.store.record("finding.explained", {"snapshot_id": body["snapshot_id"], "finding_id": f["id"], "actual_provider": explanation["actual_provider"], "llm_used": explanation["llm_used"]})
                    self.reply(200, explanation)
                finally:
                    self.server.llm_gate.release()
            else:
                self.reply(404, {"error": "見つかりません。"})
        except ValidationError as exc:
            self.reply(400, {"error": str(exc)})
        except ConflictError as exc:
            self.reply(409, {"error": str(exc)})
        except IntegrityError:
            self.reply(409, {"error": "保存データまたは計画の完全性検証に失敗しました。操作を拒否します。"})
        except Exception:
            self.reply(500, {"error": "ローカル処理に失敗しました。入力形式を確認してください。"})

    def do_OPTIONS(self):
        self.reply(405, {"error": "CORSは有効になっていません。"})
