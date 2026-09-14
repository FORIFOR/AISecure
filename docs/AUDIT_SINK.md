# 独立監査チェックポイント

ローカルの監査チェーンは、DBと監査鍵を同じホストで管理すると末尾削除を検出できません。`publish-checkpoint` は、現在の監査件数とチェーン先端だけを、別に運用するHTTPS保管先へ送ります。監査本文・ログ・ユーザー名・対象IDは送信しません。

## 送信側

本番では `cryptography` を含むオプションを導入し、専用のSecret Managerから監査送信鍵を実行時に渡します。Okta用トークン、Webhook鍵、保管暗号鍵と同じ鍵を使わないでください。

```bash
export AISECURE_AUDIT_SINK_SECRET="32バイト以上の専用シークレット"
python3 -m aisecure \
  --data-dir ./private-state \
  publish-checkpoint \
  --url https://audit-vault.example/checkpoints
```

送信先はHTTP 2xxだけでは受理しません。次のJSONを返し、`count`と`tip`を完全一致させる必要があります。

```json
{"status":"accepted","count":123,"tip":"64文字の小文字hex"}
```

成功後、AISecureはローカル監査へ`audit.checkpoint_published`を記録します。これは送信したチェックポイントの後に追加される記録なので、CLI出力の`published`を独立保管した値として扱ってください。

## 受信側の契約

送信は`POST`で、ボディはcanonical JSONです。`X-AISecure-Checkpoint-Signature`は、ボディ全体に対するHMAC-SHA256を`sha256=`付きで示します。`X-AISecure-Checkpoint-Tip`は照合用の先端値です。

受信側は、HTTPS、署名、`schema_version`、`count`、`tip`、保持ポリシー、重複送信を検証し、受理した値を別権限・別保管領域へ保存してください。受信側がWORM・透明性ログ・バックアップを提供しない限り、末尾削除への耐性を保証できません。

これは外部保管の接続プロトコルであり、AISecureリポジトリには保管サーバーを同梱していません。送信先が停止・改ざん・鍵を失った場合は、成功扱いにせず運用上のインシデントとして扱います。
