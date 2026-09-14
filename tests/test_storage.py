from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

from aisecure.demo import sample
from aisecure.store import IntegrityError, Store


HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography is installed only for the production-storage test environment")
class EncryptedStorageTests(unittest.TestCase):
    key = b"k" * 32

    def test_sensitive_store_fields_are_encrypted_and_reopenable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root, master_key=self.key)
            sid = store.ingest(sample(), "demo")
            state = store.state()
            self.assertEqual(state["snapshot_id"], sid)
            self.assertTrue(state["storage"]["encrypted_at_rest"])
            self.assertEqual(state["storage"]["key_source"], "external-secret")
            store.close()

            self.assertFalse((root / "master.key").exists())
            database = (root / "state.sqlite3").read_bytes()
            self.assertNotIn(b"DEMO-ADV-001", database)
            self.assertNotIn(b'"events"', database)
            self.assertNotIn(b"revoke_session", database)

            reopened = Store(root, master_key=self.key)
            try:
                self.assertEqual(reopened.state()["snapshot_id"], sid)
                self.assertEqual(reopened.state()["storage"]["encrypted_at_rest"], True)
            finally:
                reopened.close()

    def test_wrong_or_missing_external_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root, master_key=self.key)
            store.ingest(sample(), "demo")
            store.close()
            with self.assertRaises(IntegrityError):
                Store(root, master_key=b"w" * 32)
            with self.assertRaises(IntegrityError):
                Store(root)

    def test_plaintext_store_cannot_be_opened_as_encrypted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = Store(root)
            store.ingest(sample(), "demo")
            store.close()
            with self.assertRaises(IntegrityError):
                Store(root, master_key=self.key)


if __name__ == "__main__":
    unittest.main()
