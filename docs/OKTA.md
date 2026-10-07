# Okta連携（限定的な実対応）

AISecureには、明示承認された `revoke_session` をOktaへ送る限定アダプターがあります。対象は、承認者がOkta管理画面で確認して指定した **OktaユーザーID（`00u...`）** だけです。AISecure内部の仮名化されたactorやメールアドレスから対象を推測しません。

`DELETE /api/v1/users/{userId}/sessions?oauthTokens=false` の受付だけでは完了としません。応答の `X-Okta-Request-Id` とログの `debugContext.debugData.requestId`、対象ユーザー、`user.session.clear`、`outcome.result=SUCCESS`、実行時刻のすべてが一致した場合だけ `verified` と記録します。ログ時刻は要求の2秒前からその照会開始までを許容し、要求ID照合の代わりには使いません。遅延ログは照会を繰り返して確認します。

要求ID不足、空ログ、古い／失敗ログ、照会の403・429・タイムアウト・ページ上限などは、受付後の結果を `delivery_unknown`、`executed=null` として残します。「実行されなかった」とは断定しません。再送はせず、同じ未確認操作の別計画による実行も拒否します。ログ遅延を含む未確認結果の照合・解除を行う運用機能は未実装です。DBを直接書き換えて解除せず、導入ゲートとして扱ってください。

この証拠が示すのは今回の要求に対応するIdPセッション消去イベントだけです。OAuthアクセストークン／リフレッシュトークンの失効、各アプリのセッション終了、ネットワーク遮断は確認していません。結果は `verification_scope=okta_idp_sessions_only`、`containment_verified=false` を明示します。業務影響と復旧担当を事前に確認してください。CLIは未確認・失敗結果のJSONを出力した後、終了コード2を返します。

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

これは自動遮断ではありません。計画・スナップショットの一致、5分の期限、二者の明示確認、対象ID指定が必要です。必要なら `--emergency-stop-file ./STOP` を追加してください。ファイルが存在する、または確認できない場合はOkta APIへ送信しません。現行CLIの承認者名は二つの異なるラベルであることを確認するだけなので、本番ではSSO/RBACで認証済みの本人性と職務分離を実装・検証してください。

### 検証と移行

Python APIの `clear_user_sessions` は時刻だけでなく `SessionClearReceipt` を返し、`verify_session_clear` はその受付証拠を要求します。旧時刻だけの呼出しを検証成功として扱いません。署名付き承認は[対象・実行先を含むschema2](APPROVALS.md)の再発行が必要です。

テストは合成値とローカル受信器を使います。実際のOkta orgでのヘッダーとログの対応、ログ遅延、エンジン差、アプリ側の失効は未検証です。該当フィールドが出ない環境では安全側に未確認となり、その環境向けの明示的な検証設計が必要です。

参考（2026-10-06確認）: [Okta System Log query](https://developer.okta.com/docs/reference/system-log-query/)、[Request IDの対応](https://support.okta.com/help/s/article/how-to-find-x-okta-request-id)、[セッションとトークン失効の区別](https://developer.okta.com/docs/guides/revoke-tokens/-/main/)、[アプリ側Universal Logoutの範囲](https://developer.okta.com/docs/guides/oin-universal-logout-overview/)。
