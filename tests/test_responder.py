from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import threading
import tempfile
import unittest
from pathlib import Path

from aisecure.demo import sample
from aisecure.responder import ResponderConfig, ResponderError, SignedWebhookResponder
from aisecure.schema import ValidationError
from aisecure.store import Store, ConflictError


class CaptureHandler(BaseHTTPRequestHandler):
    payload = None
    headers = None
    response_status = "verified"
    response_request_id = None

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        type(self).payload = self.rfile.read(length)
        type(self).headers = dict(self.headers)
        request = json.loads(type(self).payload)
        body = json.dumps({"status": type(self).response_status, "provider": "test-responder",
                           "request_id": type(self).response_request_id or request["request_id"],
                           "proposal_id": request["proposal_id"]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class ResponderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.httpd.server_port}/contain"
        cls.secret = b"s" * 32

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.sid = self.store.ingest(sample(), "demo")
        self.finding = self.store.state()["findings"][0]
        self.pid = self.store.propose(self.sid, self.finding["id"])["proposal_id"]
        CaptureHandler.payload = None
        CaptureHandler.headers = None
        CaptureHandler.response_status = "verified"
        CaptureHandler.response_request_id = None

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def responder(self):
        return SignedWebhookResponder(ResponderConfig(
            url=self.url,
            secret=self.secret,
            allowed_actions=frozenset({"revoke_session", "restrict_remote_access", "review_evidence"}),
        ))

    def test_real_execution_requires_two_distinct_approvers(self):
        with self.assertRaises(ConflictError):
            self.store.execute_approved(self.pid, self.sid, self.responder(), "session-test")
        with self.assertRaises(ValidationError):
            self.store.approve_for_execution(self.pid, self.sid, "EXECUTE REAL ACTION",
                                             "SECOND APPROVER CONFIRMED", "根拠と影響を確認しました。",
                                             "same", "same")

    def test_signed_webhook_is_verified_and_audited(self):
        approval = self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "根拠と業務影響を確認しました。", "operator-a", "operator-b", "provider-session-42")
        self.assertEqual(approval["status"], "approved")
        result = self.store.execute_approved(self.pid, self.sid, self.responder(), "provider-session-42")
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["executed"])
        verified = next(record for record in self.store.state()["audit_records"]
                        if record["action"] == "plan.verified")
        self.assertEqual(verified["payload"]["provider"], "test-responder")
        proposal = self.store.state()["proposals"][0]
        self.assertEqual(proposal["status"], "verified")
        payload = json.loads(CaptureHandler.payload)
        self.assertEqual(payload["proposal_id"], self.pid)
        self.assertEqual(payload["snapshot_id"], self.sid)
        self.assertEqual(payload["target"], "provider-session-42")
        self.assertNotIn("vendor-maintenance@example.invalid", CaptureHandler.payload.decode())
        headers = {key.lower(): value for key, value in CaptureHandler.headers.items()}
        signature_body = headers["x-aisecure-timestamp"].encode() + b"." + CaptureHandler.payload
        expected = hmac.new(self.secret, signature_body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["x-aisecure-signature"], "sha256=" + expected)
        self.assertEqual(headers["x-aisecure-idempotency-key"], self.pid)

    def test_execution_target_must_match_the_target_that_was_approved(self):
        self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "対象と影響を確認しました。", "operator-a", "operator-b", "approved-target")
        with self.assertRaises(ConflictError):
            self.store.execute_approved(self.pid, self.sid, self.responder(), "different-target")
        self.assertEqual(self.store.state()["proposals"][0]["status"], "approved")

    def test_provider_failure_is_not_recorded_as_success(self):
        self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "影響と復旧手順を確認しました。", "operator-a", "operator-b", "provider-session-42")
        CaptureHandler.response_status = "failed"
        result = self.store.execute_approved(self.pid, self.sid, self.responder(), "provider-session-42")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["executed"])
        self.assertEqual(self.store.state()["proposals"][0]["status"], "failed")

    def test_emergency_stop_blocks_request_before_delivery(self):
        stop_file = Path(self.temp.name) / "STOP"
        stop_file.touch()
        self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "影響と復旧手順を確認しました。", "operator-a", "operator-b", "provider-session-42")
        responder = SignedWebhookResponder(ResponderConfig(
            url=self.url, secret=self.secret,
            allowed_actions=frozenset({"revoke_session"}),
            emergency_stop_file=str(stop_file),
        ))
        with self.assertRaises(ResponderError):
            self.store.execute_approved(self.pid, self.sid, responder, "provider-session-42")
        self.assertIsNone(CaptureHandler.payload)
        self.assertEqual(self.store.state()["proposals"][0]["status"], "failed")

    def test_real_webhook_rejects_non_loopback_http(self):
        with self.assertRaises(ValidationError):
            ResponderConfig("http://example.com/contain", self.secret,
                            allowed_actions=frozenset({"review_evidence"}))

    def test_responder_requires_verified_provider_status(self):
        self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "対象と影響を確認しました。", "operator-a", "operator-b", "provider-session-42")
        CaptureHandler.response_status = "unknown"
        with self.assertRaises(ResponderError):
            self.store.execute_approved(self.pid, self.sid, self.responder(), "provider-session-42")
        self.assertEqual(self.store.state()["proposals"][0]["status"], "failed")

    def test_responder_must_echo_the_current_request(self):
        self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "対象と影響を確認しました。", "operator-a", "operator-b", "provider-session-42")
        CaptureHandler.response_request_id = "different-request"
        with self.assertRaises(ResponderError):
            self.store.execute_approved(self.pid, self.sid, self.responder(), "provider-session-42")
        self.assertEqual(self.store.state()["proposals"][0]["status"], "failed")

    def test_malformed_provider_result_fails_closed(self):
        self.store.approve_for_execution(
            self.pid, self.sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "対象と影響を確認しました。", "operator-a", "operator-b", "provider-session-42")

        class MalformedResponder:
            adapter_name = "malformed"

            def execute(self, _plan, _context):
                return None

        result = self.store.execute_approved(self.pid, self.sid, MalformedResponder(), "provider-session-42")
        self.assertEqual(result, {"status": "failed", "executed": False})
        self.assertEqual(self.store.state()["proposals"][0]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
