from __future__ import annotations
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from aisecure.__main__ import main

ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "examples" / "logs"


def run(*argv) -> tuple[str, str]:
    out, err = io.StringIO(), io.StringIO()
    with patch.object(sys, "argv", ["aisecure", *argv]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        main()
    return out.getvalue(), err.getvalue()


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.state = str(self.dir / "state")

    def test_profiles_are_listed(self):
        out, _ = run("profiles")
        self.assertIn("generic-auth-csv", out)
        self.assertIn("generic-file-access-jsonl", out)

    def test_baseline_writes_a_valid_scenario(self):
        target = self.dir / "scenario.json"
        run("baseline", "--days", "1", "--users", "4", "--attack", "--out", str(target))
        data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(data["scenario_version"], 1)
        self.assertTrue(data["labels"]["malicious_event_ids"])

    def test_baseline_is_reproducible_from_the_command_line(self):
        first, second = self.dir / "a.json", self.dir / "b.json"
        run("baseline", "--seed", "7", "--days", "1", "--users", "4", "--out", str(first))
        run("baseline", "--seed", "7", "--days", "1", "--users", "4", "--out", str(second))
        self.assertEqual(first.read_text(encoding="utf-8"), second.read_text(encoding="utf-8"))

    def test_evaluate_reports_detections_and_false_positives(self):
        clean, incident = self.dir / "clean.json", self.dir / "incident.json"
        run("baseline", "--name", "clean", "--seed", "2", "--days", "1", "--users", "6", "--out", str(clean))
        run("baseline", "--name", "incident", "--seed", "3", "--days", "1", "--users", "6", "--attack", "--out", str(incident))
        report = self.dir / "report.md"
        run("evaluate", str(clean), str(incident), "--out", str(report))
        text = report.read_text(encoding="utf-8")
        self.assertIn("# 誤検知評価レポート", text)
        self.assertIn("実環境の誤検知率ではありません", text)

    def test_evaluate_can_save_recommended_thresholds(self):
        clean, incident = self.dir / "clean.json", self.dir / "incident.json"
        run("baseline", "--name", "clean", "--seed", "2", "--days", "1", "--users", "6", "--out", str(clean))
        run("baseline", "--name", "incident", "--seed", "3", "--days", "1", "--users", "6", "--attack", "--out", str(incident))
        saved = self.dir / "rules.json"
        run("evaluate", str(clean), str(incident), "--sweep", "--format", "json",
            "--out", str(self.dir / "r.json"), "--save-rules", str(saved))
        values = json.loads(saved.read_text(encoding="utf-8"))
        self.assertIn("distinct_file_threshold", values)
        self.assertIn("window_seconds", values)

    @unittest.skipUnless((LOGS / "assets.csv").exists(), "example logs not generated")
    def test_import_of_the_bundled_example_logs(self):
        snapshot, quality = self.dir / "snapshot.json", self.dir / "quality.json"
        run("import", "--source", f"generic-asset-csv={LOGS / 'assets.csv'}",
            "--source", f"generic-auth-csv={LOGS / 'auth.csv'}",
            "--source", f"generic-file-access-jsonl={LOGS / 'file-access.jsonl'}",
            "--out", str(snapshot), "--quality", str(quality))
        document = json.loads(snapshot.read_text(encoding="utf-8"))
        self.assertEqual(len(document["provenance"]), 3)
        self.assertEqual(json.loads(quality.read_text(encoding="utf-8"))["totals"]["rows_skipped"], 0)

    @unittest.skipUnless((LOGS / "assets.csv").exists(), "example logs not generated")
    def test_import_then_analyze_finds_the_correlation(self):
        snapshot = self.dir / "snapshot.json"
        run("import", "--source", f"generic-asset-csv={LOGS / 'assets.csv'}",
            "--source", f"generic-auth-csv={LOGS / 'auth.csv'}",
            "--source", f"generic-file-access-jsonl={LOGS / 'file-access.jsonl'}",
            "--out", str(snapshot))
        out, _ = run("--data-dir", self.state, "analyze", str(snapshot))
        result = json.loads(out)
        self.assertIn("AS-004", {f["rule"] for f in result["findings"]})
        self.assertEqual(len(result["coverage"]["provenance"]), 3)

    def test_import_requires_a_profile_assignment(self):
        with self.assertRaises(ValueError):
            run("import", "--source", str(LOGS / "assets.csv"))

    def test_rules_file_changes_the_active_configuration(self):
        path = self.dir / "rules.json"
        path.write_text(json.dumps({"distinct_file_threshold": 250}), encoding="utf-8")
        run("--data-dir", self.state, "--rules", str(path), "checkpoint")
        out, _ = run("--data-dir", self.state, "verify-audit")
        self.assertTrue(json.loads(out)["valid"])

    def test_invalid_rules_file_is_refused(self):
        path = self.dir / "rules.json"
        path.write_text(json.dumps({"distinct_file_threshold": 0}), encoding="utf-8")
        with self.assertRaises(ValueError):
            run("--data-dir", self.state, "--rules", str(path), "checkpoint")

    def test_baseline_warns_when_the_scenario_ends_in_the_future(self):
        target = self.dir / "future.json"
        _, err = run("baseline", "--days", "90", "--users", "3", "--out", str(target))
        self.assertIn("未来", err)

    def test_baseline_start_makes_the_scenario_analyzable(self):
        scenario, snapshot = self.dir / "past.json", self.dir / "snapshot.json"
        run("baseline", "--days", "20", "--users", "3", "--start", "2026-01-01T00:00:00+09:00", "--out", str(scenario))
        data = json.loads(scenario.read_text(encoding="utf-8"))
        snapshot.write_text(json.dumps(data["snapshot"]), encoding="utf-8")
        out, _ = run("--data-dir", self.state, "analyze", str(snapshot))
        self.assertIn("findings", json.loads(out))

    def test_sample_command_needs_no_database(self):
        out, _ = run("sample")
        self.assertEqual(json.loads(out)["schema_version"], 1)
        self.assertFalse((self.dir / "state").exists())


if __name__ == '__main__':
    unittest.main()
