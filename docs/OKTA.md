# Okta連携（限定的な実対応）

AISecureには、明示承認された `revoke_session` をOktaへ送る限定アダプターがあります。対象は、承認者がOkta管理画面で確認して指定した **OktaユーザーID（`00u...`）** だけです。AISecure内部の仮名化されたactorやメールアドレスから対象を推測しません。

`DELETE /api/v1/users/{userId}/sessions?oauthTokens=false` が成功しただけでは完了とせず、Okta System Logに同じユーザーを対象とする `user.session.clear` が現れた場合だけ `verified` と記録します。検証時間内に確認できなければ `failed` です。Oktaのこの操作はユーザーのIdPセッションをすべて消すため、業務影響と復旧担当を事前に確認してください。

## 必要な設定

- Okta org URL（`https://...okta.com` または利用中のOktaドメイン）
- 外部のSecret Managerから実行時だけ渡すアクセストークン
- OAuth 2.0の場合は最小権限として `okta.logs.read` と `okta.users.lifecycle.clearSessions` を検討する
- API tokenを使う場合は `--auth-scheme SSWS` を指定し、トークンの保管・ローテーションをOkta側の運用に従う

トークンは環境変数から読み、SQLite、スナップショット、監査ペイロード、標準出力には保存しません。共有シェル履歴やCIログへトークンを残さないでください。

## 監視

Okta System Logの直近30分（既定）をHTTPSで取得し、`user.session.start` の成功・失敗だけをログインイベントとして取り込みます。前回の境界をまたぐ重複はイベントIDで扱い、取得した原文は保存しません。資産台帳は引き続きローカルの読み取り専用CSVで指定します。

```bash
OKTA_ACCESS_TOKEN="$TOKEN_FROM_SECRET_MANAGER" \
python3 -m aisecure --data-dir ./private-state watch-okta \
  --asset-source generic-asset-csv=assets.csv \
  --source generic-file-access-jsonl=access.jsonl \
  --okta-domain https://example.okta.com
```

`--source` は任意で、既存のファイル参照ログをOktaのログインと同じスナップショットへ結合します。`--once` で一回だけ取得できます。取得エラー、時刻不整合、必須項目欠落は安全側に読み飛ばし、品質レポートに残します。Okta APIの読み取りには `okta.logs.read` が必要です。

## 実行

```bash
OKTA_ACCESS_TOKEN="$TOKEN_FROM_SECRET_MANAGER" \
python3 -m aisecure --data-dir ./private-state execute-okta \
  --proposal-id P-... \
  --snapshot-id S-... \
  --provider-target 00u1234567890abcdef \
  --okta-domain https://example.okta.com \
  --primary-operator operator-a \
  --secondary-operator operator-b \
  --reason '検知根拠と業務影響を確認し、失効後の復旧担当を決めた' \
  --confirm 'EXECUTE REAL ACTION' \
  --second-confirm 'SECOND APPROVER CONFIRMED'
```

API tokenを使う場合は `--auth-scheme SSWS` を追加します。検証待ち時間は `--verification-timeout`（既定5秒）で設定できます。タイムアウト、権限不足、対象ID不正、System Logの検証失敗は成功扱いになりません。

これは自動遮断ではありません。計画・スナップショットの一致、5分の期限、二者の明示確認、対象ID指定が必要です。現行CLIの承認者名は二つの異なるラベルであることを確認するだけなので、本番ではSSO/RBACで認証済みの本人性と職務分離を実装・検証してください。

参考: [Okta System Log query](https://developer.okta.com/docs/reference/system-log-query/)、[Okta OAuth scopes](https://developer.okta.com/docs/api/oauth2)、[Clear user sessions](https://developer.okta.com/docs/guides/keep-me-signed-in/main/)。
