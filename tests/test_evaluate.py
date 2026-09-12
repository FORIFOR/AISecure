from __future__ import annotations
import json
import unittest

from aisecure.baseline import scenario, load_scenario, BEHAVIORAL_RULES
from aisecure.evaluate import evaluate, markdown, prepare, score, sweep
from aisecure.rules import DEFAULT as DEFAULT_RULES
from aisecure.schema import ValidationError

SMALL = dict(days=2, users=10)


class BaselineTests(unittest.TestCase):
    def test_generation_is_deterministic(self):
        first = scenario("a", seed=3, **SMALL)
        second = scenario("a", seed=3, **SMALL)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_different_seeds_differ(self):
        self.assertNotEqual(scenario("a", seed=3, **SMALL)["snapshot"]["events"],
                            scenario("a", seed=4, **SMALL)["snapshot"]["events"])

    def test_clean_baseline_has_no_labeled_incident(self):
        data = scenario("clean", seed=1, **SMALL)
        self.assertEqual(data["labels"]["malicious_event_ids"], [])
        self.assertEqual(data["labels"]["expect_rules"], [])

    def test_attack_scenario_labels_only_incident_events(self):
        data = scenario("incident", seed=1, attack=True, **SMALL)
        labeled = set(data["labels"]["malicious_event_ids"])
        sessions = {e["session"] for e in data["snapshot"]["events"] if e["id"] in labeled}
        self.assertEqual(sessions, {"incident-session"})
        self.assertEqual(len(labeled), 131)
        self.assertEqual(set(data["labels"]["expect_rules"]), set(BEHAVIORAL_RULES))

    def test_normal_traffic_contains_legitimate_bulk_access(self):
        document = prepare(scenario("clean", seed=5, **SMALL))["normalized"]
        backup = [e for e in document["events"] if e["type"] == "file_access"]
        self.assertGreater(len(backup), 1000)

    def test_scenario_validation_rejects_unknown_keys(self):
        data = scenario("clean", seed=1, **SMALL)
        data["execute"] = True
        with self.assertRaises(ValidationError):
            load_scenario(data)

    def test_scenario_version_is_checked(self):
        data = scenario("clean", seed=1, **SMALL)
        data["scenario_version"] = 2
        with self.assertRaises(ValidationError):
            load_scenario(data)


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean = prepare(scenario("clean", seed=11, **SMALL))
        cls.incident = prepare(scenario("incident", seed=12, attack=True, **SMALL))

    def test_incident_is_detected_at_the_default_thresholds(self):
        result = score(self.incident, DEFAULT_RULES)
        self.assertEqual(result["missed_rules"], [])
        self.assertEqual(result["per_rule"]["AS-004"]["tp"], 1)
        self.assertEqual(result["per_rule"]["AS-004"].get("fp", 0), 0)

    def test_clean_baseline_produces_no_true_positives(self):
        result = score(self.clean, DEFAULT_RULES)
        self.assertEqual(result["behavioral"]["tp"], 0)

    def test_legitimate_bulk_access_is_counted_as_a_false_positive(self):
        result = score(self.clean, DEFAULT_RULES)
        self.assertGreater(result["per_rule"]["AS-003"]["fp"], 0)

    def test_correlation_does_not_fire_on_normal_traffic(self):
        self.assertEqual(score(self.clean, DEFAULT_RULES)["per_rule"].get("AS-004", {}).get("fp", 0), 0)

    def test_asset_rules_are_excluded_from_precision(self):
        result = score(self.incident, DEFAULT_RULES)
        for rule in ("AS-001", "AS-005"):
            self.assertEqual(result["per_rule"].get(rule, {}).get("fp", 0), 0)
        self.assertGreaterEqual(result["hygiene_alerts"], 1)

    def test_raising_the_threshold_trades_detection_for_quiet(self):
        loose = evaluate([self.clean, self.incident], DEFAULT_RULES)["totals"]
        strict = evaluate([self.clean, self.incident], DEFAULT_RULES.replace(distinct_file_threshold=800))["totals"]
        self.assertLess(strict["false_positives"], loose["false_positives"])
        self.assertGreater(strict["missed"], loose["missed"])

    def test_totals_add_up(self):
        report = evaluate([self.clean, self.incident], DEFAULT_RULES)
        totals = report["totals"]
        self.assertEqual(totals["scenarios"], 2)
        self.assertEqual(totals["true_positives"], sum(r["behavioral"]["tp"] for r in report["scenarios"]))
        self.assertEqual(totals["false_positives"], sum(r["behavioral"]["fp"] for r in report["scenarios"]))
        self.assertEqual(totals["expected_detections"], len(BEHAVIORAL_RULES))

    def test_report_records_the_configuration_used(self):
        config = DEFAULT_RULES.replace(window_seconds=600)
        report = evaluate([self.clean], config)
        self.assertEqual(report["rule_config"]["digest"], config.digest)
        self.assertEqual(report["rule_config"]["values"]["window_seconds"], 600)

    def test_empty_scenario_list_refused(self):
        with self.assertRaises(ValidationError):
            evaluate([], DEFAULT_RULES)

    def test_evaluation_does_not_mutate_the_scenario(self):
        before = json.dumps(self.clean["snapshot"], sort_keys=True)
        evaluate([self.clean], DEFAULT_RULES)
        self.assertEqual(before, json.dumps(self.clean["snapshot"], sort_keys=True))


class SweepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = [scenario("clean", seed=21, **SMALL), scenario("incident", seed=22, attack=True, **SMALL)]
        cls.report = sweep(cls.scenarios, DEFAULT_RULES, thresholds=(100, 400), windows=(120, 300))

    def test_every_cell_is_measured(self):
        self.assertEqual(len(self.report["cells"]), 4)
        for cell in self.report["cells"]:
            self.assertIn("AS-004", cell["per_rule"])

    def test_a_high_threshold_misses_the_incident(self):
        cell = next(c for c in self.report["cells"] if c["distinct_file_threshold"] == 400 and c["window_seconds"] == 120)
        self.assertGreater(cell["missed"], 0)

    def test_recommendation_detects_everything(self):
        self.assertIsNotNone(self.report["recommended"])
        self.assertEqual(self.report["recommended"]["missed"], 0)

    def test_recommendation_is_absent_when_nothing_detects(self):
        report = sweep(self.scenarios, DEFAULT_RULES, thresholds=(100000,), windows=(300,))
        self.assertIsNone(report["recommended"])

    def test_markdown_report_states_its_limits(self):
        text = markdown(evaluate(self.scenarios, DEFAULT_RULES), self.report)
        self.assertIn("実環境の誤検知率ではありません", text)
        self.assertIn("## 閾値スイープ", text)
        self.assertIn("## この結果から言えること", text)
        self.assertIn("AS-004", text)


if __name__ == '__main__':
    unittest.main()
