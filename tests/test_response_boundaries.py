"""Synthetic, offline regressions for authorization and action evidence.

These prove only the named code boundaries, not real IdP containment.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from aisecure.demo import sample
from aisecure.providers.okta import (OktaClient, OktaConfig, OktaError,
                                     OktaSessionResponder, SessionClearReceipt)
from aisecure.responder import ResponderError
from aisecure.schema import iso, utcnow
from aisecure.store import Store, ConflictError

USER = "00uSyntheticTarget0001"
REQUEST = "synthetic-provider-request-001"
NOW = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)


def event(**changes):
    return {"eventType": "user.session.clear", "target": [{"id": USER}],
            "outcome": {"result": "SUCCESS"}, "published": NOW.isoformat(),
            "debugContext": {"debugData": {"requestId": REQUEST}}, **changes}


class OktaEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.receipt = SessionClearReceipt(NOW, REQUEST)
        self.client = OktaClient(OktaConfig("https://example.okta.com", "synthetic-" + "x" * 32))

    def matches(self, value):
        return self.client._matches_clear(value, USER, self.receipt, NOW + timedelta(seconds=1))

    def test_exact_success_is_observed(self):
        self.assertTrue(self.matches(event()))

    def test_failed_missing_unknown_outcomes_are_not_verification(self):
        for outcome in ({"result": "FAILURE"}, {"result": "UNKNOWN"}, {}, None, "SUCCESS"):
            with self.subTest(outcome=outcome):
                self.assertFalse(self.matches(event(outcome=outcome)))

    def test_stale_future_missing_invalid_and_timezone_free_times_are_rejected(self):
        for published in ("2000-01-01T00:00:00Z", (NOW + timedelta(minutes=1)).isoformat(),
                          None, "yesterday", "2026-10-06T12:00:00", False):
            with self.subTest(published=published):
                self.assertFalse(self.matches(event(published=published)))

    def test_clock_allowance_is_bounded_and_still_needs_request_match(self):
        self.assertTrue(self.matches(event(published=(NOW - timedelta(seconds=2)).isoformat())))
        self.assertFalse(self.matches(event(published=(NOW - timedelta(seconds=3)).isoformat())))

    def test_unrelated_or_missing_request_never_verifies(self):
        for debug in ({"debugData": {"requestId": "other-request"}}, {"debugData": {}}, {}, None):
            with self.subTest(debug=debug):
                self.assertFalse(self.matches(event(debugContext=debug)))

    def test_unrelated_event_target_and_malformed_entries_are_rejected(self):
        for value in (event(eventType="user.session.start"), event(target=[{"id": "00uOtherTarget0001"}]),
                      event(target=[]), None, [], "private-synthetic-content"):
            with self.subTest(value=value):
                self.assertFalse(self.matches(value))

    def test_missing_correlation_header_cannot_be_verified(self):
        self.client._request = Mock(return_value=(204, b"", {}))
        receipt = self.client.clear_user_sessions(USER)
        self.assertIsNone(receipt.request_id)
        self.client.system_log = Mock()
        self.assertFalse(self.client.verify_session_clear(USER, receipt))
        self.client.system_log.assert_not_called()

    def test_delete_scope_remains_only_idp_sessions(self):
        self.client._request = Mock(return_value=(204, b"", {"X-Okta-Request-Id": REQUEST}))
        receipt = self.client.clear_user_sessions(USER)
        self.assertEqual(receipt.request_id, REQUEST)
        self.assertEqual(self.client._request.call_args.args[0], "DELETE")
        self.assertTrue(self.client._request.call_args.args[1].endswith("/sessions?oauthTokens=false"))

    def test_accepted_write_and_failed_evidence_read_remains_unknown(self):
        for error in (OktaError("HTTP 403"), OktaError("HTTP 429"), OktaError("timeout"),
                      OktaError("pagination exceeded")):
            responder = OktaSessionResponder(self.client.config)
            responder.client.clear_user_sessions = Mock(return_value=self.receipt)
            responder.client.verify_session_clear = Mock(side_effect=error)
            result = responder.execute({"execution_mode": "real", "automatic_execution": False,
                                        "action": "revoke_session"}, {"provider_target": USER})
            self.assertEqual(result["status"], "delivery_unknown")
            self.assertIsNone(result["executed"])
            self.assertTrue(result["action_accepted"])
            self.assertFalse(result["automatic_retry"])
            self.assertNotIn(REQUEST, json.dumps(result))
            responder.client.clear_user_sessions.assert_called_once_with(USER)

    def test_reordered_and_duplicate_logs_still_need_exact_positive_evidence(self):
        self.client.system_log = Mock(return_value=[event(outcome={"result": "FAILURE"}),
                                                    event(), event()])
        with patch("aisecure.providers.okta.datetime") as clock:
            clock.now.return_value = NOW + timedelta(seconds=1)
            self.assertTrue(self.client.verify_session_clear(USER, self.receipt))
        self.assertIn('outcome.result eq "SUCCESS"', self.client.system_log.call_args.kwargs["filter_expression"])


class StoredOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.sid = self.store.ingest(sample(), "demo")
        self.finding = self.store.state()["findings"][0]
        self.pid = self.store.propose(self.sid, self.finding["id"])["proposal_id"]
        self.store.approve_for_execution(self.pid, self.sid, "EXECUTE REAL ACTION",
                                        "SECOND APPROVER CONFIRMED", "Synthetic reviewed operation",
                                        "alice", "bob", USER)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def responder(self, result):
        return Mock(adapter_name="synthetic-offline-responder", execute=Mock(return_value=result))

    def test_unknown_is_durable_and_same_proposal_or_finding_cannot_retry(self):
        responder = self.responder({"status": "delivery_unknown", "executed": None, "action_accepted": True})
        result = self.store.execute_approved(self.pid, self.sid, responder, USER)
        self.assertEqual(result["status"], "delivery_unknown")
        self.assertIsNone(result["executed"])
        self.assertEqual(self.store.state()["proposals"][0]["status"], "delivery_unknown")
        with self.assertRaises(ConflictError):
            self.store.execute_approved(self.pid, self.sid, responder, USER)
        with self.assertRaises(ConflictError):
            self.store.propose(self.sid, self.finding["id"])
        responder.execute.assert_called_once()
        self.store.close()
        self.store = Store(self.temp.name)
        with self.assertRaises(ConflictError):
            self.store.propose(self.sid, self.finding["id"])

    def test_post_dispatch_exception_is_not_proof_of_non_execution(self):
        responder = self.responder(None)
        responder.execute.side_effect = RuntimeError("synthetic-private-provider-error")
        with self.assertRaises(ResponderError) as raised:
            self.store.execute_approved(self.pid, self.sid, responder, USER)
        self.assertNotIn("private-provider", str(raised.exception))
        self.assertEqual(self.store.state()["proposals"][0]["status"], "delivery_unknown")
        audit = next(r for r in self.store.state()["audit_records"] if r["action"] == "plan.delivery_unknown")
        self.assertIsNone(audit["payload"]["executed"])
        self.assertNotIn("private-provider", json.dumps(audit))

    def test_preapproved_sibling_cannot_retry_an_unknown_action(self):
        sibling = self.store.propose(self.sid, self.finding["id"])["proposal_id"]
        self.store.approve_for_execution(sibling, self.sid, "EXECUTE REAL ACTION",
                                        "SECOND APPROVER CONFIRMED", "Synthetic reviewed operation",
                                        "alice", "bob", USER)
        responder = self.responder({"status": "delivery_unknown", "executed": None})
        self.store.execute_approved(self.pid, self.sid, responder, USER)
        with self.assertRaises(ConflictError):
            self.store.execute_approved(sibling, self.sid, responder, USER)
        responder.execute.assert_called_once()

    def test_snapshot_refresh_cannot_create_retry_for_same_unknown_finding(self):
        responder = self.responder({"status": "delivery_unknown", "executed": None})
        self.store.execute_approved(self.pid, self.sid, responder, USER)
        changed = sample()
        changed["as_of"] = iso(utcnow() + timedelta(seconds=1))
        new_sid = self.store.ingest(changed, "demo")
        with self.assertRaises(ConflictError):
            self.store.propose(new_sid, self.finding["id"])
        responder.execute.assert_called_once()

    def test_sibling_cannot_dispatch_while_first_call_is_still_executing(self):
        sibling = self.store.propose(self.sid, self.finding["id"])["proposal_id"]
        self.store.approve_for_execution(sibling, self.sid, "EXECUTE REAL ACTION",
                                        "SECOND APPROVER CONFIRMED", "Synthetic reviewed operation",
                                        "alice", "bob", USER)
        second = self.responder({"status": "verified", "executed": True})
        first = self.responder(None)
        def execute(*_):
            with self.assertRaises(ConflictError):
                self.store.execute_approved(sibling, self.sid, second, USER)
            return {"status": "verified", "executed": True}
        first.execute.side_effect = execute
        self.store.execute_approved(self.pid, self.sid, first, USER)
        first.execute.assert_called_once()
        second.execute.assert_not_called()

    def test_snapshot_refresh_does_not_rewrite_known_execution(self):
        responder = self.responder(None)
        def execute(*_):
            changed = sample()
            changed["as_of"] = iso(utcnow() + timedelta(seconds=1))
            self.store.ingest(changed, "demo")
            return {"status": "verified", "executed": True}
        responder.execute.side_effect = execute
        result = self.store.execute_approved(self.pid, self.sid, responder, USER)
        self.assertEqual(result["status"], "verified")
        self.assertIs(result["executed"], True)
        self.assertFalse(result["snapshot_current"])
        audit = next(r for r in self.store.state()["audit_records"] if r["action"] == "plan.verified")
        self.assertEqual(audit["payload"]["snapshot_id"], self.sid)

    def test_malformed_inconsistent_provider_result_is_unknown(self):
        for bad in (None, {"status": "verified", "executed": False},
                    {"status": "failed", "executed": True}):
            # Result normalization is exercised in a fresh proposal for each case.
            with tempfile.TemporaryDirectory() as directory:
                store = Store(directory)
                try:
                    sid = store.ingest(sample(), "demo")
                    pid = store.propose(sid, store.state()["findings"][0]["id"])["proposal_id"]
                    store.approve_for_execution(pid, sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
                                                "Synthetic reviewed operation", "alice", "bob", USER)
                    result = store.execute_approved(pid, sid, self.responder(bad), USER)
                    self.assertEqual(result["status"], "delivery_unknown")
                    self.assertIsNone(result["executed"])
                finally:
                    store.close()


if __name__ == "__main__":
    unittest.main()
