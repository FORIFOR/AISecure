# 入力契約 v1

すべての検知は、認証済みのローカル管理者が手動入力したスナップショットに依存します。ログの発生源・電子署名・機器バージョンを自動検証しません。検証段階では合成データまたは適切に処理した許可済みデータを使用してください。

## スナップショット

```json
{
  "schema_version": 1,
  "as_of": "2026-09-12T00:00:00Z",
  "assets": [],
  "events": []
}
```

`assets` は1〜200件、`events` は0〜5,000件、JSON全体は2 MiB以下。日時はタイムゾーン付きISO 8601。スナップショット時刻が処理時刻から5分以上未来なら拒否。各イベント・資産の時刻もスナップショット時刻から5分以上未来なら拒否します。過去の履歴の分析は可能ですが、現在の状態を表しません。

未定義フィールドを拒否します。JSONの重複キー・非有限数、同じイベントIDに対する異なる内容を拒否します。同一ID・同一内容の再送は重複を除外します。本文・添付ファイル・秘密鍵・認証トークン・個人情報の全文を入れてはいけません。

## 資産

```json
{
  "id": "edge-vpn-01",
  "kind": "vpn",
  "internet_exposed": true,
  "privileged_path": true,
  "sensitive_path": true,
  "patch_state": "pending",
  "observed_at": "2026-09-11T23:55:00Z",
  "vulnerability": {
    "reference": "DEMO-ADV-001",
    "cvss": 6.5,
    "known_exploited": false
  }
}
```

`id` と `reference` は80文字以内の英数字・`_ . : -`。個人名や秘密を入れず、機器の不透明な管理IDを使います。

`kind`: `vpn | server | saas | endpoint`

`patch_state`: `pending | applied | unknown | not_applicable`

`internet_exposed`, `privileged_path`, `sensitive_path`: `true | false | null`。不明は必ず `null` にします。`false` で代用しません。

`vulnerability`: 脆弱性登録なしなら `null`。`pending` では参照情報必須。`cvss` は0〜10の有限数または `null`。`known_exploited` は `true | false | null`。悪用リストの取得時刻・署名・出典の強制検証は本版にはありません。したがって「未掲載」ではなく「入力値」として扱います。

この最小スキーマでは資産あたり脆弱性1件に限定。複数CVE、影響バージョンの区間、対策の優先度を本番で扱うにはスキーマ拡張が必要です。

## ログイン

```json
{
  "id": "evt-login-001",
  "type": "login",
  "at": "2026-09-11T23:56:00Z",
  "actor": "opaque-actor-001",
  "session": "opaque-session-001",
  "gateway_id": "edge-vpn-01",
  "success": true,
  "privileged": true,
  "device_trusted": false,
  "approved": false
}
```

`success` は明示的な真偽値。`privileged`, `device_trusted`, `approved` は真偽値または `null`。承認状態・端末信頼度は信頼できる管理データとの照合が必要であり、ユーザーが自己申告した真偽値を本番で信頼してはいけません。

## ファイル参照

```json
{
  "id": "evt-read-001",
  "type": "file_access",
  "at": "2026-09-11T23:57:00Z",
  "actor": "opaque-actor-001",
  "session": "opaque-session-001",
  "asset_id": "documents-01",
  "file_id": "opaque-file-001",
  "sensitive": true,
  "bytes_read": 4096
}
```

`file_id` は同じファイルの識別子を一貫させます。本文や実ファイルパスではなく不透明IDを推奨します。`bytes_read` は0〜1兆の整数。転送先への送信バイト数ではありません。読み取り記録は漏えいの証拠と同一ではありません。

`actor`, `session`, `file_id` は256文字以内。正規化時にドメイン分離したHMAC-SHA256の先頭96bitへ変換します。キーが同じなら同一性が保たれます。衝突可能性はゼロではなく、巨大規模では識別子長を見直してください。秘密・パスワードを入れてはいけません。仮名化後もアクセス行動に関わる機微な情報です。

## 相関契約と限界

相関は `actor + session + asset_id` を軸にして、同一セッションの直前30分以内の成功ログインを関連付けます。異なるIdP・VPN・ファイルサーバーでセッションIDが揃わない場合、現状のスキーマでは相関しません。無理にIDを一致させず、本番用コネクタ側で信頼できるセッション対応付けを実装してください。

大量参照は同じユーザー・同じセッション・同じ保存先について、連続300秒窓内に100個以上の異なるファイルがある場合。バッチ単位の重複だけでなく同一ファイル再参照も個数から除きます。最も多い窓を選ぶ簡易方式で、すべてのエピソードを別事案として抽出するものではありません。長期間・複数サーバー・複数セッションに分散した持ち出しは対象外です。正常なバックアップでもAS-003は検知し得ます。
