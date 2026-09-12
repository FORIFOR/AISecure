from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock

from aisecure.demo import sample
from aisecure.schema import normalize, ValidationError, canonical, read_json, pseudonym, iso
from aisecure.engine import analyze, coverage
from aisecure.store import Store, ConflictError, IntegrityError
from aisecure.explain import Explainer

NOW = datetime(2026, 9, 12, 3, 0, tzinfo=timezone.utc)
KEY = b'x' * 32


def normalized(data=None):
    return normalize(data or sample(NOW), KEY, source_mode='demo', now=NOW)


def rules(data=None):
    return {f['rule']: f for f in analyze(normalized(data))}


class DetectionTests(unittest.TestCase):
    def test_demo_finds_all_four_rules(self):
        self.assertEqual(set(rules()), {'AS-001', 'AS-002', 'AS-003', 'AS-004'})

    def test_medium_cvss_not_ignored(self):
        f = rules()['AS-001']
        self.assertEqual((f['cvss'], f['priority']), (6.5, 'P1'))

    def test_kev_membership_not_required_for_medium_exposure_path(self):
        data = sample(NOW)
        self.assertFalse(data['assets'][0]['vulnerability']['known_exploited'])
        self.assertEqual(rules(data)['AS-001']['priority'], 'P1')

    def test_low_exposure_medium_is_not_p1(self):
        data = sample(NOW)
        data['assets'][0]['internet_exposed'] = False
        self.assertEqual(rules(data)['AS-001']['priority'], 'P3')
        self.assertNotIn('AS-004', rules(data))

    def test_patch_applied_breaks_chain(self):
        data = sample(NOW)
        data['assets'][0]['patch_state'] = 'applied'
        self.assertNotIn('AS-001', rules(data))
        self.assertNotIn('AS-004', rules(data))
        self.assertIn('AS-003', rules(data))

    def test_unknown_asset_is_visible(self):
        data = sample(NOW)
        data['assets'][0]['internet_exposed'] = None
        self.assertIn('AS-005', rules(data))
        self.assertEqual(coverage(normalized(data))['unknown_asset_fields'], 1)

    def test_stale_asset_is_visible(self):
        data = sample(NOW)
        data['assets'][0]['observed_at'] = iso(NOW - timedelta(days=3))
        self.assertIn('AS-005', rules(data))

    def test_counts_distinct_files_and_sensitive_labels(self):
        f = rules()['AS-004']
        self.assertEqual((f['distinct_files'], f['sensitive_files']), (130, 42))
        self.assertTrue(f['hypothesis'])

    def test_duplicate_event_is_deduplicated(self):
        data = sample(NOW)
        data['events'] += copy.deepcopy(data['events'][-50:])
        n = normalized(data)
        self.assertEqual(len(n['events']), 148)
        self.assertEqual(rules(data)['AS-003']['distinct_files'], 130)

    def test_repeated_same_file_is_not_bulk(self):
        data = sample(NOW)
        for e in data['events']:
            if e['type'] == 'file_access':
                e['file_id'] = 'same-file'
        self.assertNotIn('AS-003', rules(data))
        self.assertNotIn('AS-004', rules(data))

    def test_slow_access_is_not_detected_by_this_rule(self):
        data = sample(NOW)
        for i, e in enumerate(data['events']):
            if e['id'].startswith('evt-review-'):
                e['at'] = iso(NOW - timedelta(seconds=(148-i)*10))
        self.assertNotIn('AS-003', rules(data))

    def test_different_session_does_not_correlate(self):
        data = sample(NOW)
        for e in data['events']:
            if e['id'] == 'evt-login-review':
                e['session'] = 'other-session'
        self.assertNotIn('AS-004', rules(data))
        self.assertIn('AS-003', rules(data))

    def test_different_actor_does_not_correlate(self):
        data = sample(NOW)
        for e in data['events']:
            if e['id'] == 'evt-login-review':
                e['actor'] = 'other-actor'
        self.assertNotIn('AS-004', rules(data))

    def test_failed_login_does_not_correlate(self):
        data = sample(NOW)
        for e in data['events']:
            if e['type'] == 'login':
                e['success'] = False
        self.assertNotIn('AS-002', rules(data))
        self.assertNotIn('AS-004', rules(data))

    def test_trusted_approved_work_not_identity_anomaly(self):
        data = sample(NOW)
        for e in data['events']:
            if e['type'] == 'login':
                e['approved'] = e['device_trusted'] = True
        self.assertNotIn('AS-002', rules(data))
        self.assertNotIn('AS-004', rules(data))
        self.assertIn('AS-003', rules(data))  # A backup may still match the bulk rule.

    def test_unknown_device_not_treated_as_false(self):
        data = sample(NOW)
        for e in data['events']:
            if e['type'] == 'login':
                e['approved'] = e['device_trusted'] = None
        self.assertNotIn('AS-002', rules(data))
        self.assertGreater(coverage(normalized(data))['unknown_login_fields'], 0)

    def test_missing_classification_breaks_sensitive_chain(self):
        data = sample(NOW)
        for e in data['events']:
            if e['type'] == 'file_access':
                e['sensitive'] = None
        self.assertNotIn('AS-004', rules(data))
        self.assertEqual(rules(data)['AS-003']['sensitive_files'], 0)

    def test_99_distinct_files_below_threshold(self):
        data = sample(NOW)
        data['events'] = [e for e in data['events'] if not e['id'].startswith('evt-review-') or int(e['id'][-3:]) < 99]
        self.assertNotIn('AS-003', rules(data))

    def test_100_distinct_files_at_threshold(self):
        data = sample(NOW)
        data['events'] = [e for e in data['events'] if not e['id'].startswith('evt-review-') or int(e['id'][-3:]) < 100]
        self.assertEqual(rules(data)['AS-003']['distinct_files'], 100)

    def test_out_of_order_same_result(self):
        data = sample(NOW)
        expected = analyze(normalized(data))
        data['events'].reverse()
        self.assertEqual(analyze(normalized(data)), expected)

    def test_every_evidence_id_exists(self):
        n = normalized()
        ids = {e['id'] for e in n['events']} | {'asset:' + a['id'] for a in n['assets']}
        for f in analyze(n):
            self.assertTrue(set(f['evidence_ids']) <= ids)

    def test_expired_login_outside_lookback(self):
        data = sample(NOW)
        for e in data['events']:
            if e['type'] == 'login':
                e['at'] = iso(NOW - timedelta(hours=3))
        self.assertNotIn('AS-004', rules(data))

    def test_snapshot_does_not_claim_live_connectivity(self):
        cov = coverage(normalized())
        self.assertEqual(cov['live_connectors'], 0)
        self.assertTrue(cov['snapshot_only'])


class BoundaryTests(unittest.TestCase):
    def test_file_content_rejected(self):
        data = sample(NOW)
        data['events'][-1]['raw_content'] = 'secret text'
        with self.assertRaises(ValidationError): normalized(data)

    def test_unknown_top_level_rejected(self):
        data = sample(NOW)
        data['api_key'] = 'anything'
        with self.assertRaises(ValidationError): normalized(data)

    def test_conflicting_event_id_rejected(self):
        data = sample(NOW)
        duplicate = copy.deepcopy(data['events'][-1]); duplicate['bytes_read'] += 1
        data['events'].append(duplicate)
        with self.assertRaises(ValidationError): normalized(data)

    def test_timezone_required(self):
        data = sample(NOW); data['as_of'] = '2026-09-12T03:00:00'
        with self.assertRaises(ValidationError): normalized(data)

    def test_future_time_rejected(self):
        data = sample(NOW); data['as_of'] = iso(NOW + timedelta(hours=1))
        with self.assertRaises(ValidationError): normalized(data)

    def test_cvss_bool_rejected(self):
        data = sample(NOW); data['assets'][0]['vulnerability']['cvss'] = True
        with self.assertRaises(ValidationError): normalized(data)

    def test_cvss_nan_rejected(self):
        data = sample(NOW); data['assets'][0]['vulnerability']['cvss'] = float('nan')
        with self.assertRaises(ValidationError): normalized(data)

    def test_numeric_boolean_rejected(self):
        data = sample(NOW); data['assets'][0]['internet_exposed'] = 1
        with self.assertRaises(ValidationError): normalized(data)

    def test_missing_asset_reference_rejected(self):
        data = sample(NOW); data['events'][-1]['asset_id'] = 'missing'
        with self.assertRaises(ValidationError): normalized(data)

    def test_event_capacity_limit(self):
        data = sample(NOW); data['events'] = [data['events'][0]] * 5001
        with self.assertRaises(ValidationError): normalized(data)

    def test_json_duplicate_keys_rejected(self):
        with self.assertRaises(ValidationError): read_json(b'{"a":1,"a":2}')

    def test_json_nonfinite_rejected(self):
        with self.assertRaises(ValidationError): read_json(b'{"a":NaN}')

    def test_json_size_limit(self):
        with self.assertRaises(ValidationError): read_json(b' ' * (2*1024*1024+1))

    def test_pseudonym_key_and_namespace_separated(self):
        self.assertEqual(pseudonym('secret-user', KEY, 'actor'), pseudonym('secret-user', KEY, 'actor'))
        self.assertNotEqual(pseudonym('secret-user', KEY, 'actor'), pseudonym('secret-user', b'y'*32, 'actor'))
        self.assertNotEqual(pseudonym('secret-user', KEY, 'actor'), pseudonym('secret-user', KEY, 'file'))

    def test_raw_identifiers_absent_after_normalization(self):
        body = canonical(normalized())
        self.assertNotIn('@example.invalid', body)
        self.assertNotIn('sensitive-document-', body)
        self.assertNotIn('review-session', body)

    def test_asset_identifier_html_rejected(self):
        data = sample(NOW); data['assets'][0]['id'] = '<img src=x onerror=alert(1)>'
        with self.assertRaises(ValidationError): normalized(data)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.sid = self.store.ingest(sample(NOW), 'demo', now=NOW)
        self.finding = self.store.state()['findings'][0]

    def tearDown(self):
        self.store.close(); self.temp.cleanup()

    def plan(self):
        return self.store.propose(self.sid, self.finding['id'])

    def approve(self, pid, **kwargs):
        return self.store.approve_and_simulate(pid, kwargs.get('snapshot', self.sid), kwargs.get('confirmation', 'SIMULATE ONLY'), kwargs.get('reason', '根拠と業務への影響を確認しました。'))

    def test_no_live_actions(self):
        self.assertFalse(self.store.state()['real_actions_enabled'])

    def test_approval_required(self):
        p = self.plan()
        self.assertEqual(self.store.state()['proposals'][0]['status'], 'pending')
        self.assertNotIn('plan.simulated', [r['action'] for r in self.store.state()['audit_records']])

    def test_exact_confirmation_required(self):
        with self.assertRaises(ValidationError): self.approve(self.plan()['proposal_id'], confirmation='approve')

    def test_reason_required(self):
        with self.assertRaises(ValidationError): self.approve(self.plan()['proposal_id'], reason='ok')

    def test_simulation_never_claims_execution(self):
        r = self.approve(self.plan()['proposal_id'])
        self.assertFalse(r['executed'])
        self.assertEqual(r['status'], 'simulated')

    def test_duplicate_approval_rejected(self):
        pid = self.plan()['proposal_id']; self.approve(pid)
        with self.assertRaises(ConflictError): self.approve(pid)

    def test_pending_plan_reused(self):
        self.assertEqual(self.plan()['proposal_id'], self.plan()['proposal_id'])

    def test_snapshot_change_invalidates_approval(self):
        pid = self.plan()['proposal_id']
        data = sample(NOW); data['events'] = data['events'][:1]
        self.store.ingest(data, 'demo', now=NOW)
        with self.assertRaises(ConflictError): self.approve(pid)

    def test_expired_plan_rejected(self):
        pid = self.plan()['proposal_id']
        self.store.db.execute('UPDATE proposals SET expires_at=? WHERE id=?', ('2001-01-01T00:00:00Z', pid))
        with self.assertRaises(ConflictError): self.approve(pid)

    def test_mutated_plan_rejected(self):
        pid = self.plan()['proposal_id']
        self.store.db.execute('UPDATE proposals SET body=? WHERE id=?', ('{"action":"shell"}',pid))
        with self.assertRaises(IntegrityError): self.approve(pid)

    def test_mutated_snapshot_rejected(self):
        self.store.db.execute('UPDATE snapshots SET body=? WHERE id=?', ('{}', self.sid))
        with self.assertRaises(IntegrityError): self.store.snapshot()

    def test_mutated_audit_detected(self):
        self.store.db.execute("UPDATE audit SET action='forged' WHERE seq=1")
        self.assertFalse(self.store.verify_audit()['valid'])
        with self.assertRaises(IntegrityError): self.plan()

    def test_tail_deletion_needs_external_anchor(self):
        self.plan()
        anchor = self.store.verify_audit()
        self.store.db.execute('DELETE FROM audit WHERE seq=?', (anchor['count'],))
        self.assertTrue(self.store.verify_audit()['valid'])
        self.assertFalse(self.store.verify_audit(anchor)['valid'])

    def test_old_external_anchor_valid_after_append(self):
        anchor = self.store.verify_audit()
        self.plan()
        self.assertTrue(self.store.verify_audit(anchor)['valid'])

    def test_secret_identifiers_not_saved_in_db(self):
        raw = (Path(self.temp.name)/'state.sqlite3').read_bytes()
        self.assertNotIn(b'vendor-maintenance@example.invalid', raw)
        self.assertNotIn(b'sensitive-document-', raw)

    def test_plaintext_reason_not_saved(self):
        unique_reason = '秘密の承認理由をここだけに記載しましたXYZ'
        self.approve(self.plan()['proposal_id'], reason=unique_reason)
        self.assertNotIn(unique_reason, canonical(self.store.state()))

    def test_parallel_approval_exactly_once(self):
        pid = self.plan()['proposal_id']; outcomes = []
        def attempt():
            try: outcomes.append(self.approve(pid)['status'])
            except ConflictError: outcomes.append('conflict')
        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertCountEqual(outcomes, ['simulated', 'conflict'])

    def test_key_loss_fails_closed(self):
        (Path(self.temp.name)/'master.key').unlink()
        with self.assertRaises(IntegrityError): Store(self.temp.name)


class ExplanationTests(unittest.TestCase):
    def setUp(self):
        self.finding = rules()['AS-004']

    def fake(self, answer, tool_calls=None):
        e = Explainer('local-test-model')
        message = {'content': json.dumps(answer)}
        if tool_calls: message['tool_calls'] = tool_calls
        response = Mock()
        response.read.return_value = json.dumps({'model':'local-test-model','message':message}).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        e.opener = Mock(); e.opener.open.return_value = response
        return e

    def answer(self):
        return {'summary':'未確認の相関候補です。元ログと照合してください。','checks':['正規作業かを確認する。'],'evidence_ids':self.finding['evidence_ids'][:2]}

    def test_default_truthful_attribution(self):
        r=Explainer().explain(self.finding)
        self.assertFalse(r['llm_used'])
        self.assertEqual(r['actual_provider'], 'deterministic-template')

    def test_unconfigured_model_fallback(self):
        self.assertFalse(Explainer().explain(self.finding, True)['llm_used'])

    def test_cloud_model_rejected(self):
        with self.assertRaises(ValueError): Explainer('some-model:cloud')

    def test_mock_valid_llm_response(self):
        r=self.fake(self.answer()).explain(self.finding, True)
        self.assertTrue(r['llm_used'])
        self.assertFalse(r['verified_facts_only'])
        self.assertEqual(r['actual_provider'], 'ollama/local-test-model')

    def test_forged_evidence_falls_back(self):
        a=self.answer();a['evidence_ids']=['invented']
        self.assertFalse(self.fake(a).explain(self.finding, True)['llm_used'])

    def test_action_field_in_response_rejected(self):
        a=self.answer();a['action']='execute'
        self.assertFalse(self.fake(a).explain(self.finding, True)['llm_used'])

    def test_tools_rejected(self):
        self.assertFalse(self.fake(self.answer(), [{'function':{'name':'execute'}}]).explain(self.finding, True)['llm_used'])

    def test_only_loopback_metadata_sent(self):
        e=self.fake(self.answer());e.explain(self.finding, True)
        req=e.opener.open.call_args.args[0]
        self.assertEqual(req.full_url,'http://127.0.0.1:11434/api/chat')
        data=json.loads(req.data)
        self.assertNotIn('tools',data)
        user_message=data['messages'][1]['content']
        self.assertNotIn('actor-', user_message)
        self.assertNotIn('@example.invalid',user_message)

    def test_connection_failure_not_misreported(self):
        e=Explainer('local-test-model');e.opener=Mock();e.opener.open.side_effect=OSError('unavailable')
        self.assertFalse(e.explain(self.finding,True)['llm_used'])


if __name__=='__main__': unittest.main()
