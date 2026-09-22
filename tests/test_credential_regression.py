"""Synthetic boundary regressions; no live credentials, no network or coverage claims."""
import json
import unittest
from aisecure.preflight import Request, Policy, Grant, evaluate, guarded_call, GuardDenied

DEST = 'https://example.com/v1/test'
POLICY = Policy((Grant('ai.prompt', DEST, ('public',)),))

class CredentialRegressionTests(unittest.TestCase):
    def request(self, text):
        return Request('EV-1', 'ai.prompt', DEST, text, 'public')

    def test_japanese_label_formats(self):
        for label in ('パスワードは ', '秘密鍵：', 'API キー = ', 'アクセストークンは「', '認証トークン: '):
            with self.subTest(label=label):
                decision = evaluate(self.request(label + 'TestOnly12345'), POLICY)
                self.assertEqual(decision.decision, 'block')
                self.assertIn('PG-003', decision.rule_ids)

    def test_prefixed_synthetic_credentials(self):
        for prefix in ('xoxb-', 'xoxp-', 'AIza', 'sk_live_', 'rk_live_', 'sk-proj-', 'github_pat_'):
            with self.subTest(prefix=prefix):
                # ASCII boundaries also work immediately after Japanese text.
                decision = evaluate(self.request('接続キーは' + prefix + 'a' * 32), POLICY)
                self.assertEqual(decision.decision, 'block')

    def test_fullwidth_is_normalized(self):
        self.assertEqual(evaluate(self.request('パスワードは ＴｅｓｔＯｎｌｙ１２３４５'), POLICY).decision, 'block')

    def test_general_advice_remains_allowed(self):
        for text in ('パスワードの管理方法を教えてください。', 'パスワードは長くしてください。',
                     'API キーの保管方法を説明してください。', '来週の会議を準備します。',
                     'sk-proj-', 'xoxb-short'):
            with self.subTest(text=text):
                self.assertEqual(evaluate(self.request(text), POLICY).decision, 'allow')

    def test_values_do_not_enter_report_or_errors(self):
        secret = 'TestOnly12345'
        request = self.request('パスワードは ' + secret)
        report = json.dumps(evaluate(request, POLICY).report(), ensure_ascii=False)
        self.assertNotIn(secret, report)
        calls = []
        with self.assertRaises(GuardDenied) as caught:
            guarded_call(request, POLICY, lambda req: calls.append(req))
        self.assertEqual(calls, [])
        self.assertNotIn(secret, str(caught.exception))

    def test_existing_credentials_and_personal_data_are_preserved(self):
        for text in ('password=TestOnly12345', '-----BEGIN PRIVATE KEY-----', 'AKIA' + 'A' * 16):
            self.assertEqual(evaluate(self.request(text), POLICY).decision, 'block')
        self.assertEqual(evaluate(self.request('user@example.com'), POLICY).decision, 'review')

    def test_unknown_classification_is_not_upgraded(self):
        request = Request('EV-2', 'ai.prompt', DEST, '一般的なメモ')
        self.assertEqual(evaluate(request, POLICY).decision, 'review')

if __name__ == '__main__':
    unittest.main()
