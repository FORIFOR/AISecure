from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from aisecure.connectors import load_profile
from aisecure.monitor import FileMonitor, OktaSystemLogMonitor
from aisecure.schema import iso, utcnow
from aisecure.store import Store


ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "examples" / "logs"


@unittest.skipUnless((LOGS / "assets.csv").exists(), "example logs not generated")
class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.sources = []
        for name, profile in (("assets.csv", "generic-asset-csv"),
                              ("auth.csv", "generic-auth-csv"),
                              ("file-access.jsonl", "generic-file-access-jsonl")):
            target = root / name
            shutil.copyfile(LOGS / name, target)
            self.sources.append((target, load_profile(profile)))
        self.store = Store(root / "state")
        self.monitor = FileMonitor(self.store, self.sources, interval=1)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_first_poll_ingests_and_second_unchanged_poll_is_noop(self):
        first = self.monitor.poll_once()
        self.assertTrue(first.changed)
        self.assertIsNotNone(first.snapshot_id)
        self.assertGreaterEqual(first.priority_one, 1)
        self.assertGreater(first.quality["totals"]["events"], 0)
        second = self.monitor.poll_once()
        self.assertFalse(second.changed)
        self.assertEqual(second.snapshot_id, first.snapshot_id)
        self.assertEqual(self.store.state()["audit_records"][0]["action"], "monitor.polled")

    def test_changed_source_creates_a_new_snapshot(self):
        first = self.monitor.poll_once()
        access = self.sources[2][0]
        with access.open("a", encoding="utf-8") as handle:
            handle.write('{"ts": 1788195729999, "event_id": "new-event", "user": {"id": "new-user"}, "session": "new-session", "host": "backup-01", "path": "/share/new", "label": "", "bytes": 1}\n')
        second = self.monitor.poll_once()
        self.assertTrue(second.changed)
        self.assertNotEqual(second.snapshot_id, first.snapshot_id)
        self.assertEqual(second.quality["totals"]["events"], first.quality["totals"]["events"] + 1)

    def test_authenticated_live_monitor_deduplicates_an_unchanged_window(self):
        stamp = iso(utcnow())

        class FakeCollector:
            def collect(self):
                return ({"schema_version": 1, "as_of": stamp,
                         "assets": [{"id": "okta-idp", "kind": "saas", "patch_state": "unknown",
                                     "observed_at": stamp, "vulnerability": None,
                                     "internet_exposed": None, "privileged_path": None, "sensitive_path": None}],
                         "events": [{"id": "okta-login-1", "type": "login", "at": stamp,
                                     "actor": "operator@example.invalid", "session": "session-1",
                                     "gateway_id": "okta-idp", "success": True,
                                     "privileged": None, "device_trusted": None, "approved": None}],
                         "provenance": [{"label": "okta-system-log-api", "sha256": "0" * 64,
                                         "rows_read": 1, "rows_imported": 1,
                                         "connector": "okta-system-log-api"}]},
                        {"totals": {"events": 1}, "warnings": [], "sources": [],
                         "shadow_assets": [], "unknown_assets_policy": "record"})

        monitor = OktaSystemLogMonitor(self.store, FakeCollector(), interval=1)
        first = monitor.poll_once()
        second = monitor.poll_once()
        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertEqual(second.snapshot_id, first.snapshot_id)

    def test_file_monitor_records_a_poll_failure_and_keeps_running(self):
        class BrokenMonitor(FileMonitor):
            def poll_once(self):
                raise ValueError("bad input must not enter the audit payload")

        class StopAfterWait:
            def __init__(self):
                self.stopped = False

            def is_set(self):
                return self.stopped

            def wait(self, _interval):
                self.stopped = True
                return True

        monitor = BrokenMonitor(self.store, self.sources, interval=1)
        stop = StopAfterWait()
        monitor.run(stop)
        failures = [record for record in self.store.state()["audit_records"]
                    if record["action"] == "monitor.poll_failed"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["payload"], {"error_type": "ValueError"})

    def test_okta_monitor_records_api_failure_without_secret_details(self):
        class BrokenCollector:
            def collect(self):
                raise RuntimeError("token=secret must not enter the audit payload")

        class StopAfterWait:
            def __init__(self):
                self.stopped = False

            def is_set(self):
                return self.stopped

            def wait(self, _interval):
                self.stopped = True
                return True

        monitor = OktaSystemLogMonitor(self.store, BrokenCollector(), interval=1)
        stop = StopAfterWait()
        monitor.run(stop)
        failures = [record for record in self.store.state()["audit_records"]
                    if record["action"] == "monitor.poll_failed"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["payload"], {"connector": "okta-system-log-api", "error_type": "RuntimeError"})


if __name__ == "__main__":
    unittest.main()
