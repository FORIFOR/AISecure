from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
from threading import Thread
import unittest

from aisecure.audit_sink import AuditSinkConfig, AuditSinkError, ExternalAuditSink
from aisecure.schema import canonical, ValidationError


class CheckpointHandler(BaseHTTPRequestHandler):
    body = None
    headers = None
    response_status = "accepted"
    mismatch = False

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).body = self.rfile.read(length)
        type(self).headers = dict(self.headers)
        request = json.loads(type(self).body)
        count = request["count"] + (1 if type(self).mismatch else 0)
        response = json.dumps({"status": type(self).response_status,
                               "count": count, "tip": request["tip"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class AuditSinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CheckpointHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/checkpoint"
        cls.secret = b"a" * 32

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        CheckpointHandler.body = None
        CheckpointHandler.headers = None
        CheckpointHandler.response_status = "accepted"
        CheckpointHandler.mismatch = False

    def sink(self):
        return ExternalAuditSink(AuditSinkConfig(self.url, self.secret, allow_insecure_localhost=True))

    def test_signed_checkpoint_requires_exact_acknowledgement(self):
        checkpoint = {"count": 7, "tip": "b" * 64}
        result = self.sink().publish(checkpoint)
        self.assertEqual(result["status"], "accepted")
        payload = json.loads(CheckpointHandler.body)
        self.assertEqual(payload["count"], 7)
        self.assertEqual(payload["tip"], checkpoint["tip"])
        headers = {key.lower(): value for key, value in CheckpointHandler.headers.items()}
        signature = headers["x-aisecure-checkpoint-signature"]
        expected = hmac.new(self.secret, canonical(payload).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(signature, "sha256=" + expected)

    def test_mismatched_ack_is_not_success(self):
        CheckpointHandler.mismatch = True
        with self.assertRaises(AuditSinkError):
            self.sink().publish({"count": 7, "tip": "b" * 64})

    def test_sink_rejects_invalid_configuration_and_checkpoint(self):
        with self.assertRaises(ValidationError):
            AuditSinkConfig("http://example.com/checkpoint", self.secret)
        with self.assertRaises(ValidationError):
            self.sink().publish({"count": 1, "tip": "not-a-tip"})


if __name__ == "__main__":
    unittest.main()
