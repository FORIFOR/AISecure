"""Synthetic, offline contract tests for caller-supplied inventory evidence."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch

from aisecure.gateway import GatewayError
from aisecure.posture import assess

NOW = int(datetime(2026, 10, 6, 12, tzinfo=timezone.utc).timestamp())
STAMP = '2026-10-06T12:00:00Z'
CVE = 'CVE-2099-12345'  # Fictional test identifier, not an incident claim.


def inputs(version='1.2'):
    inventory = {'observed_at': STAMP, 'assets': [{
        'id': 'lab-asset', 'vendor': 'Example', 'product': 'LabService',
        'version': version, 'internet_exposed': True,
        'privileged_path': True, 'sensitive_path': True}]}
    advisories = {'observed_at': STAMP, 'advisories': [{
        'vendor': 'Example', 'product': 'LabService', 'cve': CVE,
        'introduced': '1.0', 'fixed': '1.3',
        'source': 'https://vendor.example.invalid/advisory'}]}
    return inventory, advisories, {'dateReleased': STAMP, 'vulnerabilities': []}


def evidence(kind='official_notice', confidence='confirmed'):
    return {'source_kind': kind, 'reference': 'https://vendor.example.invalid/notice#scope',
            'observed_at': STAMP, 'claimed_confidence': confidence}


class PostureEvidenceTests(unittest.TestCase):
    def run_assessment(self, data):
        return assess(*data, now=NOW)

    def contextual(self, version='1.3'):
        data = inputs(version)
        data[0]['assets'][0]['context'] = {
            'provenance': evidence(), 'service_provider': 'Example shared provider',
            'shared_incident_reference': 'https://provider.example.invalid/incidents/synthetic-1',
            'reported_version_applied_at': '2026-09-11'}
        data[1]['advisories'][0]['context'] = {
            'provenance': evidence('vendor_advisory'),
            'published_at': '2026-09-12', 'fix_available_at': '2026-09-10'}
        return data

    def test_legacy_inputs_preserve_version_match_and_priority(self):
        for version, status in [('1.2', 'affected'), ('1.3', 'no_match_in_supplied_ranges'),
                                ('custom-build', 'unknown')]:
            with self.subTest(version=version):
                item = self.run_assessment(inputs(version))['findings'][0]
                self.assertEqual(item['status'], status)
                if version == '1.2':
                    self.assertEqual(item['priority'], 'P1')
                    self.assertEqual(item['matches'][0]['cve'], CVE)

    def test_missing_metadata_is_unknown_not_verified(self):
        item = self.run_assessment(inputs())['findings'][0]
        provenance = item['asset_context']['provenance']
        self.assertEqual(provenance['source_kind'], 'unknown')
        self.assertEqual(provenance['claimed_confidence'], 'unknown')
        self.assertIsNone(provenance['reference'])
        self.assertIsNone(provenance['observed_at'])
        self.assertFalse(provenance['evidence_authenticity_verified'])
        self.assertEqual(item['supplied_timelines'], [])
        self.assertEqual(item['timeline_coverage'], 'not_supplied')
        self.assertIsNone(item['asset_context']['service_provider'])

    def test_empty_and_null_metadata_default_unknown(self):
        for value in [None, {}, {'provenance': None}, {'provenance': {}},
                      {'provenance': {'source_kind': '', 'claimed_confidence': None, 'reference': ''}}]:
            with self.subTest(value=value):
                data = inputs()
                data[0]['assets'][0]['context'] = value
                result = self.run_assessment(data)
                self.assertEqual(result['findings'][0]['asset_context']['provenance']['source_kind'], 'unknown')

    def test_context_survives_nonmatch_without_mutating_inputs(self):
        data = self.contextual()
        original = deepcopy(data)
        report = self.run_assessment(data)
        self.assertEqual(data, original)
        item = report['findings'][0]
        self.assertEqual(item['status'], 'no_match_in_supplied_ranges')
        self.assertEqual(report['advisory_contexts'][0]['published_at'], '2026-09-12')
        self.assertEqual(item['asset_context']['provenance']['reference'], evidence()['reference'])
        self.assertEqual(item['asset_context']['reported_version'], '1.3')
        self.assertEqual(item['supplied_timelines'][0]['reported_version_applied_at'], '2026-09-11')

    def test_declared_official_and_inferred_claims_are_not_authenticated(self):
        for kind, confidence in [('official_notice', 'confirmed'), ('inference', 'inferred')]:
            data = self.contextual()
            data[0]['assets'][0]['context']['provenance'] = evidence(kind, confidence)
            report = self.run_assessment(data)
            provenance = report['findings'][0]['asset_context']['provenance']
            self.assertEqual((provenance['source_kind'], provenance['claimed_confidence']), (kind, confidence))
            self.assertFalse(provenance['evidence_authenticity_verified'])
            for flag in ('live_device_verified', 'intrusion_confirmed', 'negligence_assessed',
                         'shared_incident_links_verified'):
                self.assertFalse(report[flag])

    def test_citations_are_preserved_without_network_access(self):
        data = self.contextual()
        data[0]['assets'][0]['context']['provenance']['reference'] = 'sha256:' + 'a' * 64
        with patch('aisecure.posture.PinnedHTTPS') as https, patch('socket.create_connection') as connection:
            report = self.run_assessment(data)
        https.assert_not_called()
        connection.assert_not_called()
        self.assertFalse(report['source_references_fetched'])
        self.assertEqual(report['findings'][0]['asset_context']['provenance']['reference'], 'sha256:' + 'a' * 64)

    def test_invalid_context_shapes_and_confidence_fail(self):
        values = [[], True, {'extra': 1}, {'provenance': []}, {'provenance': {'extra': 1}},
                  {'provenance': {'source_kind': False}}, {'provenance': {'source_kind': []}},
                  {'provenance': {'claimed_confidence': 0}},
                  {'provenance': {'claimed_confidence': 'verified'}}, {'service_provider': True}]
        for value in values:
            with self.subTest(value=value):
                data = inputs()
                data[0]['assets'][0]['context'] = value
                with self.assertRaises(GatewayError):
                    self.run_assessment(data)

    def test_malformed_or_credentialed_references_fail(self):
        values = [True, [], 'http://example.invalid', 'javascript:alert(1)',
                  'https://user:password@example.invalid', 'https://', 'https://bad host.invalid',
                  'https://example.invalid/\n', 'https://example.invalid/\x00',
                  'https://example.invalid/\x01', 'file:///tmp/notice', 'https://' + 'a' * 2048]
        for value in values:
            with self.subTest(value=value):
                data = self.contextual()
                data[0]['assets'][0]['context']['provenance']['reference'] = value
                with self.assertRaises(GatewayError):
                    self.run_assessment(data)

    def test_date_precision_is_preserved_and_publication_may_follow_fix(self):
        timeline = self.run_assessment(self.contextual())['findings'][0]['supplied_timelines'][0]
        self.assertEqual(timeline['published_at'], '2026-09-12')
        self.assertEqual(timeline['published_vs_fix_available'], 'after')
        self.assertEqual(timeline['status'], 'unknown')
        self.assertEqual(timeline['issues'], [])
        self.assertFalse(timeline['patch_state_verified'])

    def test_supported_instants_compare_without_verifying_patch_state(self):
        data = self.contextual()
        data[0]['assets'][0]['context']['reported_version_applied_at'] = '2026-09-11T10:00:00+09:00'
        data[1]['advisories'][0]['context'].update(published_at='2026-09-12T00:00:00Z',
                                                 fix_available_at='2026-09-10T00:00:00Z')
        timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
        self.assertEqual(timeline['status'], 'no_inconsistency_detected')
        self.assertEqual(timeline['version_application_vs_inventory_observation'], 'before')
        self.assertFalse(timeline['patch_state_verified'])

    def test_mixed_date_and_instant_precision_is_unknown(self):
        data = self.contextual()
        data[1]['advisories'][0]['context']['fix_available_at'] = '2026-09-10T00:00:00Z'
        timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
        self.assertEqual(timeline['version_application_vs_fix_available'], 'unknown')
        self.assertEqual(timeline['status'], 'unknown')

    def test_same_fixed_version_before_availability_is_inconsistent(self):
        data = self.contextual()
        data[0]['assets'][0]['context']['reported_version_applied_at'] = '2026-09-09'
        timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
        self.assertEqual(timeline['status'], 'inconsistent')
        self.assertIn('reported_fixed_version_predates_fix_availability', timeline['issues'])
        self.assertFalse(timeline['causality_assessed'])
        self.assertFalse(timeline['negligence_assessed'])

    def test_older_and_newer_versions_are_not_misbound_to_fixed_release(self):
        for version in ('1.2', '2.0'):
            data = self.contextual(version)
            data[0]['assets'][0]['context']['reported_version_applied_at'] = '2026-09-01'
            timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
            self.assertNotIn('reported_fixed_version_predates_fix_availability', timeline['issues'])
            self.assertEqual(timeline['reported_version'], version)
            self.assertFalse(timeline['patch_state_verified'])

    def test_application_after_inventory_observation_is_inconsistent(self):
        data = self.contextual()
        data[0]['observed_at'] = '2026-10-05T00:00:00Z'
        data[0]['assets'][0]['context']['reported_version_applied_at'] = '2026-10-05T12:00:00Z'
        timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
        self.assertEqual(timeline['status'], 'inconsistent')
        self.assertIn('application_after_inventory_observation', timeline['issues'])

    def test_invalid_or_definitely_future_dates_fail(self):
        values = [True, 123, 'not-a-date', '2026-02-30', '2026-09-01T12:00:00',
                  '2026-10-08', '2026-10-06T13:00:00Z',
                  '2026-10-05\x0000:00:00Z', '2026-10-05T00:00:00.0000009Z',
                  '2026-10-05T00:00:00+00:60', '2026-10-05T00:00:00-02:99']
        for value in values:
            for asset, field in [(True, 'reported_version_applied_at'), (False, 'published_at'),
                                 (False, 'fix_available_at')]:
                with self.subTest(value=value, field=field):
                    data = self.contextual()
                    target = data[0]['assets'][0] if asset else data[1]['advisories'][0]
                    target['context'][field] = value
                    with self.assertRaises(GatewayError):
                        self.run_assessment(data)
        for value in ['2026-10-06', '2026-10-06T13:00:00Z']:
            data = self.contextual()
            data[0]['assets'][0]['context']['provenance']['observed_at'] = value
            with self.assertRaises(GatewayError):
                self.run_assessment(data)

    def test_new_provenance_does_not_refresh_stale_inventory(self):
        data = self.contextual()
        data[0]['observed_at'] = '2026-01-01T00:00:00Z'
        item = self.run_assessment(data)['findings'][0]
        self.assertEqual(item['status'], 'unknown')
        self.assertTrue(any('24時間' in reason for reason in item['reasons']))

    def test_shared_links_do_not_create_incident_counts(self):
        data = self.contextual()
        second = deepcopy(data[0]['assets'][0])
        second['id'] = 'lab-asset-two'
        data[0]['assets'].append(second)
        report = self.run_assessment(data)
        self.assertEqual(len(report['findings']), 2)
        self.assertEqual(report['findings'][0]['asset_context']['shared_incident_reference'],
                         report['findings'][1]['asset_context']['shared_incident_reference'])
        self.assertNotIn('incident_count', report)
        self.assertFalse(report['shared_incident_links_verified'])

    def test_advisory_contexts_are_indexed_and_json_round_trip(self):
        data = self.contextual('1.2')
        second = deepcopy(data[1]['advisories'][0])
        second['cve'] = 'CVE-2099-12346'
        second['context']['provenance'] = evidence('inference', 'inferred')
        data[1]['advisories'].append(second)
        report = self.run_assessment(data)
        self.assertEqual([v['advisory_context_index'] for v in report['findings'][0]['matches']], [0, 1])
        self.assertEqual(report['advisory_contexts'][1]['provenance']['source_kind'], 'inference')
        self.assertEqual(json.loads(json.dumps(report)), report)

    def test_fractional_seconds_are_not_truncated_in_ordering(self):
        data = self.contextual()
        data[0]['observed_at'] = '2026-10-05T00:00:00.100000Z'
        data[0]['assets'][0]['context']['reported_version_applied_at'] = '2026-10-05T00:00:00.900000Z'
        timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
        self.assertIn('application_after_inventory_observation', timeline['issues'])

    def test_date_only_allows_latest_possible_local_date_without_asserting_occurrence(self):
        data = self.contextual()
        data[0]['assets'][0]['context']['reported_version_applied_at'] = '2026-10-07'
        timeline = self.run_assessment(data)['findings'][0]['supplied_timelines'][0]
        self.assertEqual(timeline['reported_version_applied_at'], '2026-10-07')
        self.assertFalse(timeline['patch_state_verified'])

    def test_legacy_contexts_do_not_expand_quadratically(self):
        data = inputs()
        data[0]['assets'] = [dict(data[0]['assets'][0], id=f'lab-{i}') for i in range(50)]
        data[1]['advisories'] *= 100
        report = self.run_assessment(data)
        self.assertEqual(sum(len(f['supplied_timelines']) for f in report['findings']), 0)
        self.assertFalse(report['comparison_budget_exceeded'])

    def test_timeline_budget_reports_omissions_without_changing_matches(self):
        data = self.contextual('1.2')
        data[0]['assets'].append(dict(deepcopy(data[0]['assets'][0]), id='lab-second'))
        with patch('aisecure.posture.MAX_TIMELINE_ROWS', 1):
            report = self.run_assessment(data)
        self.assertEqual(sum(len(f['supplied_timelines']) for f in report['findings']), 1)
        self.assertEqual(report['findings'][1]['timeline_coverage'], 'limited')
        self.assertEqual(report['findings'][1]['timelines_omitted'], 1)
        self.assertEqual(report['findings'][1]['status'], 'affected')

    def test_comparison_budget_cannot_become_a_nonmatch(self):
        data = self.contextual()
        data[0]['assets'].append(dict(deepcopy(data[0]['assets'][0]), id='lab-second'))
        with patch('aisecure.posture.MAX_ADVISORY_COMPARISONS', 1):
            report = self.run_assessment(data)
        item = report['findings'][1]
        self.assertEqual(item['status'], 'unknown')
        self.assertEqual(item['advisories_not_assessed'], 1)
        self.assertEqual(item['timeline_coverage'], 'limited')
        self.assertTrue(report['comparison_budget_exceeded'])


if __name__ == '__main__':
    unittest.main()
