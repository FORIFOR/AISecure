# 認証済み二者承認

CLIの`--primary-operator`と`--secondary-operator`だけでは、本人性を証明できません。これはローカル試験用の互換経路です。本番ではSSO/RBACゲートウェイを別に運用し、各承認者が認証済みの状態でEd25519署名付き承認文書を発行してください。

## 実行側

承認文書には、対象の計画・スナップショット・操作、承認者ID、役割、決定、発行時刻、有効期限、nonceを含めます。AISecureは、外部公開鍵レジストリで署名を検証し、次を確認します。

- `primary` と `secondary` の役割が各1件あること
- 承認者IDが異なること
- 計画ID、スナップショットID、操作が一致すること
- 発行時刻と有効期限が短い許容範囲にあること
- `decision` が`approve`であること
- 承認時に確認されたプロバイダー対象IDと、後の実行対象IDが一致すること

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

`approval-public-keys.json` は承認者IDからbase64url形式の32バイトEd25519公開鍵への対応表です。秘密鍵はSSO/RBAC側だけに保持し、リポジトリ、AISecureのデータディレクトリ、コマンド引数には置きません。

承認文書の最小形式は次のとおりです。`signature`は`payload`のcanonical JSON全体に対するEd25519署名のbase64url値です。

```json
{
  "payload": {
    "schema_version": 1,
    "proposal_id": "P-...",
    "snapshot_id": "S-...",
    "action": "revoke_session",
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

これはSSO/RBACそのものではなく、認証・職務分離を担う外部ゲートウェイとの検証境界です。公開鍵の配布・ローテーション、承認画面、監査保管、失効、時計同期は導入先で検証してください。暗号化保管を使う場合は、承認証明の鍵と`AISECURE_MASTER_KEY`を分離してください。
