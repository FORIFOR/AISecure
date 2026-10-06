from __future__ import annotations

import base64
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from datetime import timedelta

from aisecure.__main__ import main
from aisecure.approvals import canonical_responder_audience, responder_audience, verify_pair
from aisecure.demo import sample
from aisecure.providers.okta import OktaConfig, OktaSessionResponder
from aisecure.responder import ResponderConfig, SignedWebhookResponder
from aisecure.schema import canonical, iso, utcnow, ValidationError
from aisecure.store import Store, ConflictError


HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


class ApprovalAudienceTests(unittest.TestCase):
    def test_okta_audience_is_the_configured_canonical_origin(self):
        responder = OktaSessionResponder(OktaConfig("https://Example.Okta.com:443/", "t" * 32))
        self.assertEqual(responder_audience(responder), "https://example.okta.com")

    def test_webhook_audience_retains_exact_path_and_nondefault_port(self):
        responder = SignedWebhookResponder(ResponderConfig(
            "https://Example.invalid:8443/Contain%2FUser/", b"s" * 32,
            allowed_actions=frozenset({"revoke_session"})))
        self.assertEqual(responder_audience(responder), "https://example.invalid:8443/Contain%2FUser/")
        self.assertEqual(canonical_responder_audience("https://Example.invalid:443"), "https://example.invalid/")
        self.assertEqual(canonical_responder_audience("http://[::1]:8080/contain"), "http://[::1]:8080/contain")

    def test_audience_rejects_ambiguous_or_unsafe_endpoints(self):
        for url in ("", "https://example.invalid:bad/", "https://user:password@example.invalid/",
                    "https://@example.invalid/", "https://example.invalid/?token=x", "https://example.invalid/#x",
                    "https://example.invalid/\n", " https://example.invalid/", "https://example.invalid\\/",
                    "http://example.invalid/", "https://example.invalid:0/"):
            with self.subTest(url=url), self.assertRaises(ValidationError):
                canonical_responder_audience(url)
        with self.assertRaises(ValidationError):
            canonical_responder_audience("https://example.okta.com/api/v1/users", origin_only=True)

    def test_unknown_adapter_cannot_self_assert_an_audience(self):
        adapter = Mock(adapter_name="okta-session-revoker", audience="https://example.okta.com")
        with self.assertRaises(ValidationError):
            responder_audience(adapter)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is installed only for the production-attestation test environment")
class ApprovalAttestationTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.private = {"alice": Ed25519PrivateKey.generate(), "bob": Ed25519PrivateKey.generate()}
        self.temp = tempfile.TemporaryDirectory()
        self.keys_path = Path(self.temp.name) / "keys.json"
        self.write_keys()
        self.proposal_id = "P-approval"
        self.snapshot_id = "S-approval"
        self.target = "provider-target"
        self.audience = "https://example.okta.com"

    def tearDown(self):
        self.temp.cleanup()

    def write_keys(self):
        from cryptography.hazmat.primitives import serialization
        self.keys_path.write_text(json.dumps({
            name: base64.urlsafe_b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )).rstrip(b"=").decode()
            for name, key in self.private.items()
        }), encoding="utf-8")

    def claim(self, approver, role, *, action="revoke_session", issued=None, expires=None):
        issued = issued or utcnow()
        expires = expires or issued + timedelta(minutes=5)
        return {"schema_version": 2, "proposal_id": self.proposal_id,
                "snapshot_id": self.snapshot_id, "action": action,
                "provider_target": self.target, "audience": self.audience,
                "approver": approver, "role": role, "decision": "approve",
                "issued_at": iso(issued), "expires_at": iso(expires),
                "nonce": approver + "-nonce-0123456789"}

    def write_approval(self, name, claim, *, filename=None):
        path = Path(self.temp.name) / f"{filename or name}.json"
        signature = self.private[name].sign(canonical(claim).encode("utf-8"))
        path.write_text(json.dumps({"payload": claim, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}), encoding="utf-8")
        return path

    def pair(self):
        return (self.write_approval("alice", self.claim("alice", "primary")),
                self.write_approval("bob", self.claim("bob", "secondary")))

    def verify(self, primary, secondary, **expected):
        binding = {"expected_provider_target": self.target, "expected_audience": self.audience}
        binding.update(expected)
        return verify_pair(primary, secondary, self.keys_path, self.proposal_id, self.snapshot_id, **binding)

    def test_two_signed_approvals_are_bound_to_exact_action_target_and_audience(self):
        claims = self.verify(*self.pair())
        self.assertEqual([claim["approver"] for claim in claims], ["alice", "bob"])
        self.assertTrue(all(claim["provider_target"] == self.target and claim["audience"] == self.audience for claim in claims))

    def test_expected_target_or_audience_substitution_is_rejected(self):
        pair = self.pair()
        for expected in ({"expected_provider_target": "other-target"},
                         {"expected_audience": "https://other.okta.com"},
                         {"expected_audience": "https://example.okta.com/"}):
            with self.subTest(expected=expected), self.assertRaises(ValidationError):
                self.verify(*pair, **expected)

    def test_pair_cannot_authorize_different_targets_tenants_or_paths(self):
        primary, _ = self.pair()
        for field, value in (("provider_target", "other-target"), ("audience", "https://other.okta.com"),
                             ("audience", "https://example.okta.com/different-responder"),
                             ("action", "restrict_remote_access")):
            claim = self.claim("bob", "secondary")
            claim[field] = value
            secondary = self.write_approval("bob", claim)
            with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                self.verify(primary, secondary)

    def test_schema2_requires_every_field_and_exact_schema_version(self):
        primary, _ = self.pair()
        for field in self.claim("bob", "secondary"):
            claim = self.claim("bob", "secondary")
            del claim[field]
            with self.subTest(missing=field), self.assertRaises(ValidationError):
                self.verify(primary, self.write_approval("bob", claim))
        for version in (1, True, 2.0, "2", None, 3):
            claim = self.claim("bob", "secondary")
            claim["schema_version"] = version
            with self.subTest(version=version), self.assertRaises(ValidationError):
                self.verify(primary, self.write_approval("bob", claim))

    def test_legacy_schema1_requires_reissuance(self):
        primary, _ = self.pair()
        claim = self.claim("bob", "secondary")
        claim["schema_version"] = 1
        del claim["provider_target"], claim["audience"]
        with self.assertRaises(ValidationError):
            self.verify(primary, self.write_approval("bob", claim))

    def test_duplicate_key_under_different_names_is_rejected(self):
        self.private["bob"] = self.private["alice"]
        self.write_keys()
        with self.assertRaisesRegex(ValidationError, "公開鍵"):
            self.verify(*self.pair())

    def test_same_approver_in_both_roles_is_rejected(self):
        primary, _ = self.pair()
        secondary = self.write_approval("alice", self.claim("alice", "secondary"), filename="alice-secondary")
        with self.assertRaises(ValidationError):
            self.verify(primary, secondary)

    def test_unsigned_claim_changes_fail_even_when_expected_values_match(self):
        for field, value, expected in (
            ("provider_target", "other-target", {"expected_provider_target": "other-target"}),
            ("audience", "https://other.okta.com", {"expected_audience": "https://other.okta.com"}),
            ("nonce", "changed-nonce-0123456789", {}),
        ):
            primary, secondary = self.pair()
            for path in (primary, secondary):
                document = json.loads(path.read_text())
                document["payload"][field] = value
                path.write_text(json.dumps(document), encoding="utf-8")
            with self.subTest(field=field), self.assertRaisesRegex(ValidationError, "署名検証"):
                self.verify(primary, secondary, **expected)

    def test_signature_bit_tampering_is_rejected(self):
        primary, secondary = self.pair()
        document = json.loads(secondary.read_text())
        signature = bytearray(base64.urlsafe_b64decode(document["signature"] + "=="))
        signature[0] ^= 1
        document["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        secondary.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "署名検証"):
            self.verify(primary, secondary)

    def test_malformed_binding_and_role_are_rejected(self):
        primary, _ = self.pair()
        for field, value in (("provider_target", None), ("provider_target", ""), ("provider_target", "x\n"),
                             ("audience", None), ("audience", []), ("audience", "https://Other.Okta.com:443"),
                             ("role", []), ("action", {})):
            claim = self.claim("bob", "secondary")
            claim[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                self.verify(primary, self.write_approval("bob", claim))

    def test_expired_or_reversed_validity_is_rejected(self):
        primary, _ = self.pair()
        now = utcnow()
        for issued, expires in ((now - timedelta(minutes=10), now - timedelta(minutes=5)),
                                (now + timedelta(seconds=60), now + timedelta(seconds=30))):
            secondary = self.write_approval("bob", self.claim("bob", "secondary", issued=issued, expires=expires))
            with self.subTest(issued=issued, expires=expires), self.assertRaises(ValidationError):
                self.verify(primary, secondary)

    def approve(self, store, claims, *, target=None, audience=None):
        return store.approve_for_execution(
            self.proposal_id, self.snapshot_id, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
            "対象と影響を確認しました。", "alice", "bob", target or self.target, claims,
            responder_audience=audience or self.audience)

    def prepare_store(self, store):
        self.snapshot_id = store.ingest(sample(), "demo")
        finding = store.state()["findings"][0]
        self.proposal_id = store.propose(self.snapshot_id, finding["id"])["proposal_id"]

    def test_store_records_attested_approval_and_binds_target_and_audience(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            try:
                self.prepare_store(store)
                self.approve(store, self.verify(*self.pair()))
                approved = next(row for row in store.state()["audit_records"] if row["action"] == "plan.approved")
                self.assertTrue(approved["payload"]["identity_attested"])
            finally:
                store.close()

    def test_store_rejects_verified_claims_for_other_target_or_audience(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            try:
                self.prepare_store(store)
                claims = self.verify(*self.pair())
                for kwargs in ({"target": "other-target"}, {"audience": "https://other.okta.com"}):
                    with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                        self.approve(store, claims, **kwargs)
                self.assertEqual(store.state()["proposals"][0]["status"], "pending")
            finally:
                store.close()

    def test_signed_expiry_is_persisted_and_enforced_at_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            try:
                self.prepare_store(store)
                now = utcnow()
                primary = self.write_approval("alice", self.claim("alice", "primary", expires=now + timedelta(seconds=15)))
                secondary = self.write_approval("bob", self.claim("bob", "secondary", expires=now + timedelta(seconds=90)))
                self.approve(store, self.verify(primary, secondary))
                store.close()
                store = Store(directory)
                responder = OktaSessionResponder(OktaConfig(self.audience, "synthetic-token-" + "x" * 32))
                with patch.object(responder, "execute") as execute:
                    with patch("aisecure.store.utcnow", return_value=now + timedelta(seconds=30)), self.assertRaises(ConflictError):
                        store.execute_approved(self.proposal_id, self.snapshot_id, responder, self.target)
                    execute.assert_not_called()
            finally:
                store.close()

    def test_old_stored_attestation_without_audience_or_expiry_cannot_dispatch(self):
        for missing in ("approved_audience_hmac", "approval_expires_at"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                store = Store(directory)
                try:
                    self.prepare_store(store)
                    self.approve(store, self.verify(*self.pair()))
                    # Simulate an approval written before that binding existed.
                    store.db.execute(f"UPDATE proposals SET {missing}=NULL WHERE id=?", (self.proposal_id,))
                    store.close()
                    store = Store(directory)
                    responder = OktaSessionResponder(OktaConfig(self.audience, "synthetic-token-" + "x" * 32))
                    with patch.object(responder, "execute") as execute, self.assertRaises(ConflictError):
                        store.execute_approved(self.proposal_id, self.snapshot_id, responder, self.target)
                    execute.assert_not_called()
                finally:
                    store.close()

    def test_store_rejects_endpoint_change_before_any_provider_call(self):
        self.audience = "https://example.invalid/approved-responder"
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            try:
                self.prepare_store(store)
                self.approve(store, self.verify(*self.pair()))
                store.close()
                store = Store(directory)
                responder = SignedWebhookResponder(ResponderConfig(
                    "https://example.invalid/other-responder", b"s" * 32,
                    allowed_actions=frozenset({"revoke_session"})))
                with patch.object(responder, "execute") as execute, self.assertRaises(ConflictError):
                    store.execute_approved(self.proposal_id, self.snapshot_id, responder, self.target)
                execute.assert_not_called()
                self.assertEqual(store.state()["proposals"][0]["status"], "approved")
            finally:
                store.close()

    def test_store_executes_the_attested_endpoint_after_reopening(self):
        self.audience = "https://example.invalid/approved-responder"
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            try:
                self.prepare_store(store)
                self.approve(store, self.verify(*self.pair()))
                store.close()
                store = Store(directory)
                responder = SignedWebhookResponder(ResponderConfig(
                    self.audience, b"s" * 32, allowed_actions=frozenset({"revoke_session"})))
                response = {"status": "verified", "executed": True, "provider": "synthetic"}
                with patch.object(responder, "execute", return_value=response) as execute:
                    result = store.execute_approved(self.proposal_id, self.snapshot_id, responder, self.target)
                self.assertTrue(result["executed"])
                execute.assert_called_once()
                self.assertEqual(execute.call_args.args[1]["provider_target"], self.target)
                self.assertEqual(store.state()["proposals"][0]["status"], "verified")
            finally:
                store.close()

    def cli_args(self, command, endpoint):
        primary, secondary = self.pair()
        args = ["aisecure", command, "--proposal-id", self.proposal_id, "--snapshot-id", self.snapshot_id,
                "--provider-target", self.target, "--primary-operator", "alice", "--secondary-operator", "bob",
                "--approval-keys", str(self.keys_path), "--primary-approval", str(primary),
                "--secondary-approval", str(secondary), "--require-attested-approvals",
                "--reason", "対象と影響を確認しました。", "--confirm", "EXECUTE REAL ACTION",
                "--second-confirm", "SECOND APPROVER CONFIRMED"]
        return args + (["--okta-domain", endpoint] if command == "execute-okta" else
                       ["--webhook-url", endpoint, "--allow-action", "revoke_session"])

    def run_cli(self, args, store, output=None):
        with patch("sys.argv", args), patch("aisecure.__main__._store", return_value=store), \
                patch.dict(os.environ, {"OKTA_ACCESS_TOKEN": "t" * 32, "AISECURE_WEBHOOK_SECRET": "s" * 32}), \
                redirect_stdout(output if output is not None else io.StringIO()):
            main()

    def test_cli_verifies_against_the_constructed_responder_configuration(self):
        for command, endpoint, audience in (
            ("execute-okta", "https://Example.Okta.com:443/", "https://example.okta.com"),
            ("execute", "https://Example.invalid:443/contain", "https://example.invalid/contain"),
        ):
            with self.subTest(command=command):
                self.audience = audience
                store = Mock()
                store.execute_approved.return_value = {"status": "verified", "executed": True}
                self.run_cli(self.cli_args(command, endpoint), store)
                store.approve_for_execution.assert_called_once()
                self.assertEqual(store.approve_for_execution.call_args.kwargs["responder_audience"], audience)
                actual = store.execute_approved.call_args.args[2]
                self.assertEqual(responder_audience(actual), audience)

    def test_cli_unverified_result_prints_json_exits_two_and_never_retries(self):
        for command, audience in (("execute-okta", "https://example.okta.com"),
                                  ("execute", "https://example.invalid/contain")):
            for result in ({"status": "delivery_unknown", "executed": None},
                           {"status": "failed", "executed": False},
                           {"status": "verified", "executed": False},
                           {"status": "delivery_unknown", "executed": True}):
                with self.subTest(command=command, result=result):
                    self.audience = audience
                    store = Mock()
                    store.execute_approved.return_value = result
                    output = io.StringIO()
                    with self.assertRaises(SystemExit) as raised:
                        self.run_cli(self.cli_args(command, audience), store, output)
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(json.loads(output.getvalue()), result)
                    store.approve_for_execution.assert_called_once()
                    store.execute_approved.assert_called_once()
                    store.close.assert_called_once()

    def test_cli_rejects_substituted_responder_configuration_before_approval(self):
        for command, signed_audience, endpoint in (
            ("execute-okta", "https://example.okta.com", "https://other.okta.com"),
            ("execute", "https://example.invalid/approved", "https://example.invalid/other"),
        ):
            with self.subTest(command=command):
                self.audience = signed_audience
                store = Mock()
                with self.assertRaises(ValidationError):
                    self.run_cli(self.cli_args(command, endpoint), store)
                store.approve_for_execution.assert_not_called()
                store.execute_approved.assert_not_called()


if __name__ == "__main__":
    unittest.main()
