"""Fuzz the other untrusted boundary: the loopback HTTP server.

Throw malformed and random requests at the running server and assert the
invariants that must always hold: it never crashes (a known-good request still
succeeds afterward), it never returns a response that leaks an internal path or
a Python traceback, authenticated endpoints always require the token, and every
response is a valid HTTP status — never a hang. Deterministic via a seeded RNG.
"""
from __future__ import annotations
import http.client
import random
import tempfile
import threading
import unittest

from aisecure.server import LocalServer
from aisecure.store import Store

HOSTILE_PATHS = ["/", "/api/state", "/api/ingest", "/api/plan", "/api/approve", "/api/explain", "/api/demo",
                 "/api/export", "/../aisecure/store.py", "/master.key", "/app.js", "/%2e%2e/", "/api/state%00",
                 "/" + "A" * 5000, "/api/\x00", "/api/../../etc/passwd", "//api//state", "/api/state?x=1"]
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "FOObar"]
LEAKY = ["Traceback", "/Users/", "/aisecure/", "site-packages", "File \"", "line ", "sqlite3", "Errno"]


class HTTPFuzzTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = Store(cls.temp.name)
        cls.server = LocalServer(cls.store, 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host, cls.port = "127.0.0.1", cls.server.server_port
        cls.host_header = cls.server.host_header
        cls.token = cls.server.token

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
        cls.store.close(); cls.temp.cleanup()

    def raw(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.read(65536)
        finally:
            conn.close()

    def test_fuzz_requests_never_crash_or_leak(self):
        rng = random.Random(20260913)
        for i in range(200):
            method = rng.choice(METHODS)
            path = rng.choice(HOSTILE_PATHS)
            headers = {"Host": rng.choice([self.host_header, "evil.example", "", "a" * 300])}
            if rng.random() < 0.6:
                headers["Authorization"] = rng.choice(["", "Bearer wrong", "Bearer " + self.token, "Basic x",
                                                       "Bearer \x00", "Bearer " + "A" * 4000])
            if rng.random() < 0.4:
                headers["Content-Type"] = rng.choice(["application/json", "text/plain", "", "application/json; x"])
            if rng.random() < 0.3:
                headers["Origin"] = rng.choice(["https://evil.example", self.server.origin, "null"])
            if rng.random() < 0.3:
                headers["Sec-Fetch-Site"] = rng.choice(["cross-site", "same-origin", "none"])
            body = None
            if method in ("POST", "PUT", "PATCH"):
                body = rng.choice([b"", b"{", b"[]", b"{\"confirm\":1}", b"\x00\xff" * 50,
                                   b"{" + b"\"a\":" * 200 + b"1" + b"}" * 200,
                                   ("{\"x\":\"" + "A" * 3000 + "\"}").encode(), b"not json",
                                   bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 300)))])
            try:
                status, payload = self.raw(method, path, headers, body)
            except http.client.HTTPException:
                continue  # a protocol-level rejection is acceptable
            self.assertTrue(100 <= status <= 599, f"case {i}: invalid status {status}")
            text = payload.decode("utf-8", "replace")
            for tok in LEAKY:
                self.assertNotIn(tok, text, f"case {i}: response leaked '{tok}' (method={method} path={path})")

    def test_auth_always_enforced_after_fuzz(self):
        # every API path must still reject a missing/wrong token
        for path in ["/api/state", "/api/export", "/api/ingest", "/api/plan", "/api/approve"]:
            status, _ = self.raw("GET" if path in ("/api/state", "/api/export") else "POST", path,
                                 {"Host": self.host_header}, None if "GET" else b"{}")
            self.assertEqual(status, 401, f"{path} did not require a token")

    def test_server_still_healthy_after_fuzz(self):
        status, body = self.raw("GET", "/api/state",
                                {"Host": self.host_header, "Authorization": "Bearer " + self.token})
        self.assertEqual(status, 200)
        self.assertIn(b"rule_config", body)


if __name__ == "__main__":
    unittest.main()
