from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
import tempfile
import unittest
from urllib.parse import urlsplit

from aisecure.connectors import load_profile
from aisecure.providers.okta import (OktaClient, OktaConfig, OktaError,
                                     OktaSessionResponder, OktaSystemLogCollector)
from aisecure.schema import ValidationError
from aisecure.store import Store


TOKEN = "t" * 32
USER_ID = "00u1234567890abcdef"


class OktaHandler(BaseHTTPRequestHandler):
    clear_calls = 0
    log_calls = 0
    emit_clear = True
    log_events = None

    def log_message(self, *_args):
        pass

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_DELETE(self):
        parsed = urlsplit(self.path)
        if parsed.path != f"/api/v1/users/{USER_ID}/sessions" or parsed.query != "oauthTokens=false" or not self._authorized():
            self.send_response(404)
            self.end_headers()
            return
        type(self).clear_calls += 1
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if urlsplit(self.path).path != "/api/v1/logs" or not self._authorized():
            self.send_response(404)
            self.end_headers()
            return
        type(self).log_calls += 1
        events = type(self).log_events
        if events is None and type(self).emit_clear:
            events = [{"eventType": "user.session.clear", "target": [{"id": USER_ID}]}]
        events = events or []
        body = json.dumps(events).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class OktaResponderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), OktaHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()

    def setUp(self):
        OktaHandler.clear_calls = 0
        OktaHandler.log_calls = 0
        OktaHandler.emit_clear = True
        OktaHandler.log_events = None

    def responder(self, verification_timeout=0.5):
        return OktaSessionResponder(OktaConfig(
            f"http://127.0.0.1:{self.server.server_port}", TOKEN,
            timeout=2, verification_timeout=verification_timeout,
            allow_insecure_localhost=True,
        ))

    def plan(self, action="revoke_session"):
        return {"action": action, "execution_mode": "real", "automatic_execution": False}

    def test_clear_sessions_requires_verified_system_log_event(self):
        result = self.responder().execute(self.plan(), {"provider_target": USER_ID})
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["executed"])
        self.assertEqual(result["verification"], "user.session.clear")
        self.assertEqual(OktaHandler.clear_calls, 1)
        self.assertGreaterEqual(OktaHandler.log_calls, 1)

    def test_missing_system_log_event_is_not_success(self):
        OktaHandler.emit_clear = False
        result = self.responder(verification_timeout=0.5).execute(self.plan(), {"provider_target": USER_ID})
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["executed"])
        self.assertEqual(OktaHandler.clear_calls, 1)

    def test_emergency_stop_blocks_session_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            stop_file = Path(directory) / "STOP"
            stop_file.touch()
            responder = OktaSessionResponder(OktaConfig(
                f"http://127.0.0.1:{self.server.server_port}", TOKEN,
                timeout=2, verification_timeout=0.5,
                allow_insecure_localhost=True,
                emergency_stop_file=str(stop_file),
            ))
            with self.assertRaises(OktaError):
                responder.execute(self.plan(), {"provider_target": USER_ID})
        self.assertEqual(OktaHandler.clear_calls, 0)

    def test_target_and_action_are_narrowly_allowlisted(self):
        with self.assertRaises(ValidationError):
            self.responder().execute(self.plan(), {"provider_target": "alice@example.invalid"})
        with self.assertRaises(OktaError):
            self.responder().execute(self.plan("restrict_remote_access"), {"provider_target": USER_ID})

    def test_system_log_collector_maps_only_login_metadata(self):
        OktaHandler.log_events = [{
            "uuid": "okta-login-invalid", "eventType": "user.session.start",
            "published": "2026-09-15T00:00:00.000Z", "actor": [],
            "authenticationContext": {"externalSessionId": "okta-session-invalid"},
            "outcome": {"result": "SUCCESS"},
        }, {
            "uuid": "okta-login-001", "eventType": "user.session.start",
            "published": "2026-09-15T00:00:01.000Z",
            "actor": {"alternateId": "operator@example.invalid"},
            "authenticationContext": {"externalSessionId": "okta-session-001"},
            "outcome": {"result": "SUCCESS"},
            "debugContext": {"debugData": {"requestUri": "/secret"}},
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assets.csv"
            path.write_text(
                "asset_id,type,exposed,admin_path,sensitive_path,patch,observed_at,advisory,cvss,kev\n"
                "okta-idp,saas,no,なし,なし,適用済,2026-09-15T09:00:00,,,\n",
                encoding="utf-8",
            )
            config = OktaConfig(
                f"http://127.0.0.1:{self.server.server_port}", TOKEN,
                timeout=2, allow_insecure_localhost=True,
            )
            collector = OktaSystemLogCollector(
                OktaClient(config), (path, load_profile("generic-asset-csv")),
                lookback_seconds=1800,
            )
            frozen = datetime(2026, 9, 15, 1, tzinfo=timezone.utc)
            snapshot, quality = collector.collect(now=frozen)
            store = Store(Path(directory) / "state")
            try:
                store.ingest(snapshot, now=frozen, verified_provenance=True)
                stored_document = store.snapshot()[1]
                stored_coverage = store.state()["coverage"]
            finally:
                store.close()
        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(snapshot["events"][0]["success"], True)
        self.assertEqual(snapshot["events"][0]["gateway_id"], "okta-idp")
        self.assertEqual(snapshot["provenance"][-1]["connector"], "okta-system-log-api")
        self.assertNotIn("/secret", json.dumps(snapshot, ensure_ascii=False))
        self.assertNotIn("operator@example.invalid", json.dumps(stored_document, ensure_ascii=False))
        self.assertNotIn("okta-session-001", json.dumps(stored_document, ensure_ascii=False))
        self.assertEqual(stored_coverage["live_connectors"], 1)
        self.assertEqual(stored_coverage["live_connector_names"], ["okta-system-log-api"])
        self.assertFalse(stored_coverage["snapshot_only"])
        self.assertEqual(quality["sources"][-1]["rows_read"], 2)
        self.assertEqual(quality["sources"][-1]["rows_imported"], 1)


if __name__ == "__main__":
    unittest.main()
