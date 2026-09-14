from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from datetime import timedelta

from aisecure.approvals import verify_pair
from aisecure.demo import sample
from aisecure.schema import canonical, iso, utcnow, ValidationError
from aisecure.store import Store


HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is installed only for the production-attestation test environment")
class ApprovalAttestationTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.private = {"alice": Ed25519PrivateKey.generate(), "bob": Ed25519PrivateKey.generate()}
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.keys_path = root / "keys.json"
        self.keys_path.write_text(json.dumps({
            name: base64.urlsafe_b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )).rstrip(b"=").decode()
            for name, key in self.private.items()
        }), encoding="utf-8")
        self.proposal_id = "P-approval"
        self.snapshot_id = "S-approval"

    def tearDown(self):
        self.temp.cleanup()

    def claim(self, approver, role, *, action="revoke_session", issued=None, expires=None):
        issued = issued or utcnow()
        expires = expires or issued + timedelta(minutes=5)
        return {"schema_version": 1, "proposal_id": self.proposal_id,
                "snapshot_id": self.snapshot_id, "action": action,
                "approver": approver, "role": role, "decision": "approve",
                "issued_at": iso(issued), "expires_at": iso(expires),
                "nonce": approver + "-nonce-0123456789"}

    def write_approval(self, name, claim):
        path = Path(self.temp.name) / f"{name}.json"
        signature = self.private[name].sign(canonical(claim).encode("utf-8"))
        path.write_text(json.dumps({"payload": claim, "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode()}), encoding="utf-8")
        return path

    def test_two_signed_approvals_are_bound_to_the_exact_action(self):
        primary = self.write_approval("alice", self.claim("alice", "primary"))
        secondary = self.write_approval("bob", self.claim("bob", "secondary"))
        claims = verify_pair(primary, secondary, self.keys_path, self.proposal_id, self.snapshot_id)
        self.assertEqual([claim["approver"] for claim in claims], ["alice", "bob"])

    def test_tampering_or_expiry_is_rejected(self):
        primary_claim = self.claim("alice", "primary")
        primary = self.write_approval("alice", primary_claim)
        secondary_claim = self.claim("bob", "secondary")
        secondary_claim["action"] = "restrict_remote_access"
        secondary = self.write_approval("bob", secondary_claim)
        with self.assertRaises(ValidationError):
            verify_pair(primary, secondary, self.keys_path, self.proposal_id, self.snapshot_id)

        expired = self.write_approval("bob", self.claim(
            "bob", "secondary", issued=utcnow() - timedelta(minutes=10),
            expires=utcnow() - timedelta(minutes=5)))
        with self.assertRaises(ValidationError):
            verify_pair(primary, expired, self.keys_path, self.proposal_id, self.snapshot_id)

    def test_store_records_attested_approval_and_binds_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory)
            try:
                sid = store.ingest(sample(), "demo")
                finding = store.state()["findings"][0]
                pid = store.propose(sid, finding["id"])["proposal_id"]
                self.proposal_id, self.snapshot_id = pid, sid
                primary = self.write_approval("alice", self.claim("alice", "primary"))
                secondary = self.write_approval("bob", self.claim("bob", "secondary"))
                claims = verify_pair(primary, secondary, self.keys_path, pid, sid)
                store.approve_for_execution(
                    pid, sid, "EXECUTE REAL ACTION", "SECOND APPROVER CONFIRMED",
                    "対象と影響を確認しました。", "alice", "bob", "provider-target", claims)
                approved = next(row for row in store.state()["audit_records"] if row["action"] == "plan.approved")
                self.assertTrue(approved["payload"]["identity_attested"])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
