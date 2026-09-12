# 入力契約 v1

すべての検知は、認証済みのローカル管理者が手動入力したスナップショットに依存します。ログの発生源・電子署名・機器バージョンを自動検証しません。検証段階では合成データまたは適切に処理した許可済みデータを使用してください。

## スナップショット

```json
{
  "schema_version": 1,
  "as_of": "2026-09-12T00:00:00Z",
  "provenance": [],
  "assets": [],
  "events": []
}
```

HTTP経由（画面の「JSONを読み込む」・`/api/ingest`）では `assets` は1〜200件、`events` は0〜5,000件、JSON全体は2 MiB以下。CLI（`aisecure import` / `analyze`）は同じ検証をより大きな上限（資産20,000件、イベント2,000,000件）で行います。実ログの取り込みはCLIを使ってください。日時はタイムゾーン付きISO 8601。スナップショット時刻が処理時刻から5分以上未来なら拒否。各イベント・資産の時刻もスナップショット時刻から5分以上未来なら拒否します。過去の履歴の分析は可能ですが、現在の状態を表しません。

`provenance` は任意です。取り込み元ファイルの `label`（パスを含まない名称）、`sha256`、`rows_read`、`rows_imported`、`connector` のみを保持します。ファイル内容・絶対パスは保持しません。`aisecure import` が自動で付与します。

正規化後は各要素に `verified` が付きます。**この値は入力からは指定できません。** 実際にファイルを読んで計算した実行（`aisecure import --ingest`）だけが `true` になり、JSONに書かれただけの出所は `false` になります。画面と監査記録は両者を区別して表示します。

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

`kind`: `vpn | server | saas | endpoint | unknown`。`unknown` は、ログにだけ現れて台帳にない資産（シャドー資産）に使います。

`patch_state`: `pending | applied | unknown | not_applicable`

`internet_exposed`, `privileged_path`, `sensitive_path`: `true | false | null`。不明は必ず `null` にします。`false` で代用しません。

`vulnerability`: 脆弱性登録なしなら `null`。`patch_state` が `pending` でも `vulnerability` は省略できます（実際の台帳には「未適用」だけが記録されていることがあるため）。その場合 AS-001 は「脆弱性参照が登録されていません」という理由を付けて検知します。`cvss` は0〜10の有限数または `null`。`known_exploited` は `true | false | null`。悪用リストの取得時刻・署名・出典の強制検証は本版にはありません。したがって「未掲載」ではなく「入力値」として扱います。

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

`file_id` は同じファイルの識別子を一貫させます。本文や実ファイルパスではなく不透明IDを推奨します。`bytes_read` は0〜1兆の整数、または不明な場合は `null`。多くのファイルサーバー監査ログはサイズを記録しないため、`0` で代用せず `null` にします。転送先への送信バイト数ではありません。読み取り記録は漏えいの証拠と同一ではありません。

`actor`, `session`, `file_id` は256文字以内。正規化時にドメイン分離したHMAC-SHA256の先頭96bitへ変換します。キーが同じなら同一性が保たれます。衝突可能性はゼロではなく、巨大規模では識別子長を見直してください。秘密・パスワードを入れてはいけません。仮名化後もアクセス行動に関わる機微な情報です。

## 相関契約と限界

相関は `actor + session + asset_id` を軸にして、同一セッションの直前30分以内の成功ログインを関連付けます。異なるIdP・VPN・ファイルサーバーでセッションIDが揃わない場合、現状のスキーマでは相関しません。無理にIDを一致させず、本番用コネクタ側で信頼できるセッション対応付けを実装してください。

大量参照は同じユーザー・同じセッション・同じ保存先について、連続300秒窓内に100個以上の異なるファイルがある場合。バッチ単位の重複だけでなく同一ファイル再参照も個数から除きます。最も多い窓を選ぶ簡易方式で、すべてのエピソードを別事案として抽出するものではありません。長期間・複数サーバー・複数セッションに分散した持ち出しは対象外です。正常なバックアップでもAS-003は検知し得ます。実際、同梱の合成ベースラインでは AS-003 の大半が正常業務でした（`docs/TUNING.md`）。

## 閾値は入力ではなく設定です

300秒・100ファイル・30分といった数値は `aisecure/rules.py` の既定値であり、`--rules` で変更できます。変更した設定はハッシュ化され、起動時に監査チェーンへ記録され、各検知結果にも `rule_config_digest` として付きます。設定項目と測り方は `docs/TUNING.md` を参照してください。
