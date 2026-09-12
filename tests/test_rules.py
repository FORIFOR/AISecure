from __future__ import annotations
from datetime import datetime, timezone
import tempfile
import unittest

from aisecure import rules
from aisecure.demo import sample
from aisecure.engine import analyze
from aisecure.schema import normalize, ValidationError
from aisecure.store import Store

NOW = datetime(2026, 9, 12, 3, 0, tzinfo=timezone.utc)
KEY = b'x' * 32


def normalized(data=None):
    return normalize(data or sample(NOW), KEY, source_mode='demo', now=NOW)


def found(config=None, data=None):
    return {f['rule'] for f in analyze(normalized(data), config)}


class RuleConfigTests(unittest.TestCase):
    def test_defaults_match_v01_behaviour(self):
        self.assertEqual(rules.DEFAULT.distinct_file_threshold, 100)
        self.assertEqual(rules.DEFAULT.window_seconds, 300)
        self.assertEqual(found(rules.DEFAULT), {'AS-001', 'AS-002', 'AS-003', 'AS-004'})

    def test_unknown_key_rejected(self):
        with self.assertRaises(ValidationError):
            rules.from_mapping({'distinct_file_threshold': 50, 'enable_everything': True})

    def test_out_of_range_rejected_not_clamped(self):
        with self.assertRaises(ValidationError):
            rules.from_mapping({'distinct_file_threshold': 1})
        with self.assertRaises(ValidationError):
            rules.from_mapping({'window_seconds': 0})

    def test_boolean_is_not_an_integer(self):
        with self.assertRaises(ValidationError):
            rules.from_mapping({'distinct_file_threshold': True})

    def test_sensitive_minimum_cannot_exceed_threshold(self):
        with self.assertRaises(ValidationError):
            rules.from_mapping({'distinct_file_threshold': 10, 'sensitive_file_minimum': 11})

    def test_identity_conditions_limited_to_known_choices(self):
        self.assertEqual(rules.from_mapping({'identity_conditions': 'both'}).identity_conditions, 'both')
        with self.assertRaises(ValidationError):
            rules.from_mapping({'identity_conditions': 'either'})

    def test_digest_changes_with_values(self):
        self.assertNotEqual(rules.DEFAULT.digest, rules.DEFAULT.replace(window_seconds=600).digest)
        self.assertEqual(rules.DEFAULT.digest, rules.from_mapping(rules.DEFAULT.as_dict()).digest)

    def test_describe_covers_every_parameter(self):
        described = {item['name'] for item in rules.describe(rules.DEFAULT)}
        self.assertEqual(described, set(rules.DEFAULT.as_dict()))


class TunedDetectionTests(unittest.TestCase):
    def test_raising_threshold_drops_bulk_and_correlation(self):
        config = rules.DEFAULT.replace(distinct_file_threshold=200)
        self.assertEqual(found(config), {'AS-001', 'AS-002'})

    def test_narrowing_window_drops_bulk(self):
        self.assertNotIn('AS-003', found(rules.DEFAULT.replace(window_seconds=60)))

    def test_lookback_zero_breaks_correlation_only(self):
        config = rules.DEFAULT.replace(login_lookback_seconds=0)
        self.assertIn('AS-003', found(config))
        self.assertNotIn('AS-004', found(config))

    def test_both_conditions_required_suppresses_approved_byod(self):
        data = sample(NOW)
        login = next(e for e in data['events'] if e['id'] == 'evt-login-review')
        login['approved'] = True  # unmanaged device, but an approved maintenance window
        self.assertIn('AS-002', found(rules.DEFAULT, data))
        self.assertNotIn('AS-002', found(rules.DEFAULT.replace(identity_conditions='both'), data))

    def test_both_conditions_still_catches_the_incident(self):
        self.assertIn('AS-004', found(rules.DEFAULT.replace(identity_conditions='both')))

    def test_sensitive_minimum_can_require_more_labels(self):
        config = rules.DEFAULT.replace(sensitive_file_minimum=100)
        self.assertIn('AS-003', found(config))
        self.assertNotIn('AS-004', found(config))

    def test_findings_carry_the_configuration_that_produced_them(self):
        config = rules.DEFAULT.replace(window_seconds=600)
        for f in analyze(normalized(), config):
            self.assertEqual(f['rule_config_digest'], config.digest)

    def test_cvss_threshold_affects_only_unexposed_priority(self):
        data = sample(NOW)
        data['assets'][0]['internet_exposed'] = False
        base = next(f for f in analyze(normalized(data)) if f['rule'] == 'AS-001')
        tuned = next(f for f in analyze(normalized(data), rules.DEFAULT.replace(cvss_priority_threshold=6.0)) if f['rule'] == 'AS-001')
        self.assertEqual((base['priority'], tuned['priority']), ('P3', 'P2'))


class RuleAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def actions(self, store):
        return [r['action'] for r in store.state()['audit_records']]

    def test_startup_records_the_active_configuration(self):
        store = Store(self.temp.name)
        self.addCleanup(store.close)
        self.assertIn('rules.configured', self.actions(store))

    def test_unchanged_configuration_is_not_recorded_twice(self):
        store = Store(self.temp.name)
        store.close()
        store = Store(self.temp.name)
        self.addCleanup(store.close)
        self.assertEqual(self.actions(store).count('rules.configured'), 1)

    def test_threshold_change_is_recorded_as_evidence(self):
        store = Store(self.temp.name)
        first = store.config.digest
        store.close()
        store = Store(self.temp.name, rules.DEFAULT.replace(distinct_file_threshold=250))
        self.addCleanup(store.close)
        records = [r for r in store.state()['audit_records'] if r['action'] == 'rules.configured']
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]['payload']['previous'], first)
        self.assertEqual(records[0]['payload']['values']['distinct_file_threshold'], 250)

    def test_state_exposes_the_active_configuration(self):
        store = Store(self.temp.name, rules.DEFAULT.replace(window_seconds=600))
        self.addCleanup(store.close)
        state = store.state()
        self.assertEqual(state['rule_config']['values']['window_seconds'], 600)
        self.assertEqual(state['rule_config']['digest'], store.config.digest)


if __name__ == '__main__':
    unittest.main()
