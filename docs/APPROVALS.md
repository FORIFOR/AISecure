# 認証済み二者承認

CLIの`--primary-operator`と`--secondary-operator`だけでは、本人性を証明できません。これは信頼済みローカル呼び出し元向けの互換経路であり、企業向け認可境界ではありません。本番ではSSO/RBACゲートウェイを別に運用し、各承認者が認証済みの状態でEd25519署名付き承認文書を発行し、実行側で`--require-attested-approvals`を必須にしてください。実行者がこのオプションを外せるCLI／ホスト権限そのものを、企業向けのアクセス制御として公開しないでください。

この検証契約はexperimentalです。署名形式は**schema_version=2のみ**を受け付けます。旧形式からの移行は後述の再発行が必要です。

## 実行側

二者の署名の短い方と計画自体の期限の最小値を保存し、実送信直前にも確認します。プロセス再起動後も期限は延長しません。対象・実行先・署名期限が保存されていない過去の署名付き承認は実行せず、新しい計画と承認の発行が必要です。

承認文書には、対象の計画・スナップショット・操作、実際の`provider_target`、実行先の`audience`、承認者ID、役割、決定、発行時刻、有効期限、nonceを含めます。AISecureは、外部公開鍵レジストリで署名を検証し、次を確認します。

- `primary` と `secondary` の役割が各1件あること
- 承認者IDとEd25519公開鍵の両方が異なること。同じ鍵を別名で登録しても二者承認にはなりません
- 計画ID、スナップショットID、操作が一致すること
- 両方の署名が同じ`provider_target`と`audience`を含み、今回の実行設定と完全に一致すること
- 発行が過去5分以内／未来2分以内で、有効期限が発行より後かつ15分以内、現在時刻より後であること
- `decision` が`approve`であること
- 承認時に確認されたプロバイダー対象IDと実行先が、後の実行時にも一致すること。署名付き承認では不明なレスポンダーを拒否します

`provider_target`には防御側で確認した対象IDをそのまま指定します。仮名化された検知のactorやメールアドレスから対象IDを推測しません。`audience`は表示名やアダプター名ではなく、構築されたレスポンダーの接続設定から取得する特定のURLです。

- Okta: 組織のorigin。`https://Example.Okta.com:443/`は`https://example.okta.com`になります
- Webhook: パスを含む完全なURL。`https://Example.invalid:443/contain`は`https://example.invalid/contain`になります。パス省略時は`/`です
- schemeとホストの大文字小文字、既定ポートのみを正規化します。Webhookのパスの大文字小文字、パーセントエスケープ、末尾の`/`、非既定ポートは区別します
- 認証情報・クエリ・フラグメント付きURLや曖昧な空白は拒否します。HTTPは明示的なループバック試験先だけに使えます

承認発行側も`aisecure.approvals.canonical_responder_audience(url, origin_only=True)`（Okta）または同関数の既定値（Webhook）と同じ正規化を適用してください。署名済みの`audience`を書き換えて合わせることはできません。

```bash
python3 -m aisecure --data-dir ./private-state execute-okta \
  --proposal-id P-... --snapshot-id S-... \
  --provider-target 00u1234567890abcdef \
  --okta-domain https://example.okta.com \
  --primary-operator alice --secondary-operator bob \
  --approval-keys ./approver-public-keys.json \
  --primary-approval ./approval-alice.json \
  --secondary-approval ./approval-bob.json \
  --require-attested-approvals \
  --reason '証拠と業務影響を確認し、復旧担当を決めた' \
  --confirm 'EXECUTE REAL ACTION' \
  --second-confirm 'SECOND APPROVER CONFIRMED'
```

`execute`と`execute-okta`は結果JSONを標準出力に書き、`status=verified`かつ`executed=true`の場合だけ正常終了します。`failed`や`delivery_unknown`を含む未検証結果は終了コード2です。`delivery_unknown`は未実行の証明ではありません。自動再試行せず、防御側で照合してください。引数・署名検証などの例外は通常終了コード1です。

`approver-public-keys.json` は承認者IDからパディングなしbase64url形式の32バイトEd25519公開鍵への対応表です。承認者ごとに異なる鍵を登録します。秘密鍵はSSO/RBAC側だけに保持し、リポジトリ、AISecureのデータディレクトリ、コマンド引数には置きません。

承認文書の最小形式は次のとおりです。例の時刻は説明用です。発行時には現在の有効な時刻を使ってください。`signature`は`payload`のcanonical JSON全体に対するEd25519署名のパディングなしbase64url値です。canonical JSONはUTF-8、キーをソート、`ensure_ascii=False`、`separators=(",", ":")`、`allow_nan=False`で生成します。必須フィールドの欠落や未定義フィールドは拒否します。

```json
{
  "payload": {
    "schema_version": 2,
    "proposal_id": "P-...",
    "snapshot_id": "S-...",
    "action": "revoke_session",
    "provider_target": "00u1234567890abcdef",
    "audience": "https://example.okta.com",
    "approver": "alice",
    "role": "primary",
    "decision": "approve",
    "issued_at": "2026-09-15T10:00:00Z",
    "expires_at": "2026-09-15T10:05:00Z",
    "nonce": "ランダムな16文字以上"
  },
  "signature": "base64url..."
}
```

## schema1からの移行

schema1は署名に実際の対象IDと実行先を含めていなかったため、署名が正しくても認証済み承認として受け付けません。バージョン番号やフィールドを追記する自動アップグレード、署名失敗時の互換経路へのフォールバックはありません。

1. 発行側をschema2と正規化済み`audience`に対応させ、異なる2つの承認者鍵を登録します
2. 現在のスナップショットと対象ID、実行先、操作、業務影響を両者が確認します
3. 未実行の旧承認は使わず、新しい計画に対して各承認者がschema2文書を再発行します
4. 実行側を更新し、`--require-attested-approvals`を付けて新しい2文書を検証します

## 信頼境界と残る運用要件

`verify_pair`には現在の`expected_provider_target`と`expected_audience`を必須キーワード引数として渡します。返されたpayloadをStoreへ渡すコードは信頼済み呼び出し元です。`Store.approve_for_execution`は受け取った辞書の署名を独立して検証しません。未検証JSONを`approval_assertions`として渡すAPIを公開したり、`identity_attested`監査フィールドだけを認証の証拠にしたりしないでください。Storeの対象・実行先の再照合は、この署名検証を置き換えません。

これはSSO/RBACそのものではなく、認証・職務分離を担う外部ゲートウェイとの検証境界です。異なる鍵を使っていることだけでは別人であることは証明できません。本人認証と役割の許可、公開鍵レジストリの保護・配布・ローテーション、承認画面、監査保管、失効、時計同期は導入先で検証してください。nonceの全組織横断の使用済み管理は実装していません。ローカル計画の状態遷移と短い有効期間による制限を超える失効・再利用防止が必要なら、外部ゲートウェイで実装してください。暗号化保管を使う場合は、承認証明の鍵と`AISECURE_MASTER_KEY`を分離してください。
