# 運用・実環境受入手順

この文書は手順であり、実環境を検証した記録ではありません。許可された検証機器・テストアカウントのみで実施します。

## 1. 対象と権限

管理対象アプリ、送信プロバイダー、OS、DLP製品、VPN機器/版数、復旧責任者を記録します。
生データ・秘密・実ネットワーク情報は公開Issueへ掲載しません。SSO本人性、職務分離、端末管理者権限は製品外の構成を含めて確認します。
説明AIにポリシーや実行権限を渡さず、ユーザーの自己申告ラベルを信頼しません。

## 2. 送信と迂回

まず `bash deployment/check-egress.sh` で合成データの隔離ラボを実行します。
ラボは専用のDockerネットワーク/コンテナだけを作り、既存のファイアウォール設定を変更しません。
利用アプリから独立受信器への直接TCPが通らないこと、ガード経由の許可本文だけが1件届くこと、
ゲートウェイ停止後に通常送信へフォールバックしないことを確認します。
この結果は当該ラボの結果であり、ユーザーPC・企業ネットワークの防御実績ではありません。

実環境では、承認したAI APIを使用する最小アプリで同じ受入試験を繰り返します。
ブラウザ/別プロセス/Proxy/再試行/ゲートウェイ停止/本文改変/添付/誤った分類証明/期限切れを確認します。
外部APIは利用料金が発生し、検証用の公開済み・合成データだけを送ります。

## 3. DLP接続と少量持ち出し

`POST /api/ingest` は収集器専用トークンを使用し、次の正規化メタデータだけを受け付けます。

```json
{"event_id":"evt-0001","source":"endpoint-dlp","at":1789550000,"actor":"opaque-actor-id","operation":"upload","tenant":"personal","data_class":"confidential","bytes":100,"outcome":"blocked"}
```

`at` は実際のUNIX秒に置き換えます。30日より古い/60秒より先のイベント、余分な項目、本文やパスは拒否します。
actorは保管前に鍵付きハッシュ化。同じsource/event_idの重複を抑止し、内容の異なる重複は拒否します。
収集器の`blocked`は「収集器がそう報告した」証拠で、独立した制御確認ではありません。
DLP-001は単一の機密持ち出し、DLP-002は24時間以内の複数持ち出しを確認候補にします。
悪意・漏えいを断定せず、実業務の誤検知評価が必要です。

既存端末DLP製品のAPI/エクスポートからこの契約へ変換する接続と、USB/同期アプリ/個人テナント制御は
導入先の製品・管理設定ごとの実装と試験が必要です。AISecure単体はUSBを無効化しません。

## 4. VPN読み取り・脆弱性照合

FortiOSの固定GET `monitor/system/status` の読み取り専用コレクターを用意しています。
機器設定を書き換えるAPIは持ちません。TLS証明書を検証し、リダイレクト/Proxy/URL内トークンは使いません。

```sh
# 専用読み取りトークンはSecret Manager等から環境変数で供給
python -m aisecure.providers.fortios_inventory --host MANAGED_VPN_HOST \
  --asset-id vpn-01 --ca-file APPROVED_CA_FILE --output inventory.json
python -m aisecure.posture refresh-kev kev.json
python -m aisecure.posture assess inventory.json vendor-advisories.json kev.json
```

Fortinet公式の経路根拠:
https://community.fortinet.com/fortigate-3/technical-tip-api-error-404-after-upgrading-to-7-4-4-183322

実機の対応版/権限は未検証です。ホスト名・シリアル・取得原文は出力しません。公開面/特権/機密到達性は取得できないのでnullです。
`vendor-advisories.json` は管理者が一次資料から作る製品名・導入版・修正版・CVE・出典URLの台帳。
数値のドット版数だけ比較し、独自ビルドや対応のない製品はunknown。KEVに無いことを安全とは扱いません。
自動の全ベンダーアドバイザリ解析や脆弱性修正は未実装です。

```sh
python -m aisecure.workbench --demo --inventory inventory.json \
  --advisories vendor-advisories.json --kev kev.json
```

上の画面は台帳を再読込して表示できますが、デモでは外部AIへ送信しません。実機の接続制限や隔離は別工程です。

### 任意の根拠・委託先・日時の申告（オフライン）

既存の資産・勧告の必須項目はそのまま使えます。各レコードへ任意の `context` を追加すると、
`aisecure.posture assess` と既存の読み取り専用評価JSONに根拠が残ります。
下記は追加部分だけを示した架空例です。実際の事故・製品・CVEとの対応を主張するものではありません。

資産の `context`:

```json
{
  "provenance": {
    "source_kind": "authenticated_export",
    "reference": "https://evidence.example.invalid/inventory/synthetic-1",
    "observed_at": "2026-10-06T12:00:00Z",
    "claimed_confidence": "confirmed"
  },
  "service_provider": "Example shared provider",
  "shared_incident_reference": "https://provider.example.invalid/incidents/synthetic-1",
  "reported_version_applied_at": "2026-09-11"
}
```

勧告の `context`:

```json
{
  "provenance": {
    "source_kind": "vendor_advisory",
    "reference": "https://vendor.example.invalid/advisory/synthetic-1",
    "observed_at": "2026-10-06T12:00:00Z",
    "claimed_confidence": "confirmed"
  },
  "published_at": "2026-09-12",
  "fix_available_at": "2026-09-10"
}
```

- `source_kind`: `official_notice` / `vendor_advisory` / `authenticated_export` / `sbom` /
  `package_manifest` / `user_supplied` / `inference` / `unknown`
- `claimed_confidence`: `confirmed` / `inferred` / `unknown`。入力者の申告です。
  `official_notice` や `confirmed` を指定しても、AISecureが真正性を確認した意味にはなりません。
- 未入力・null・空文字の種類/確度は `unknown`、参照/日時/委託先はnull。
  不明な版数は従来どおり `unknown` で、製品名や委託先から推測しません。
- `reference` と `shared_incident_reference` はHTTPS参照または `sha256:` + 小文字64桁の識別子。
  認証情報付きURL、制御文字、空白、不正な形式は拒否します。参照先を取得・検証する処理はありません。
  HTTPSであることは出典の正しさを保証しません。
- `service_provider` と `shared_incident_reference` は申告を保存するだけです。
  委託先の関与を検証せず、同じ事故リンクから事故件数を集計したり因果関係を判定したりしません。
- `reported_version_applied_at` はその資産の `version` を適用したという申告日時です。
  全CVEへの修正適用日や実機の修正済み証明として扱いません。

任意日時は `YYYY-MM-DD`、または `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` / `±HH:MM` 形式です。
小数は1〜6桁で、超過精度を丸めません。`provenance.observed_at` はタイムゾーン付き日時が必要です。
不正な日付・型・制御文字・タイムゾーンなし日時は拒否します。
現在より60秒を超える未来の日時、現在のUTC+14の日付より先の申告日も拒否します。
日付だけでは観測した時刻・タイムゾーンや既に発生した事実を確定できません。
日付と日時の混在は `unknown` とし、午前0時やタイムゾーンを補完しません。
元の精度を保存し、新しい根拠日時を付けても台帳全体の古さをリセットしません。

出力の `evidence_schema` は `aisecure.posture-evidence.v1`。
各 `asset_context` と共通 `advisory_contexts` に申告値を保存し、照合したCVEと時系列は
`advisory_context_index` で勧告へ対応付けます。版数範囲に一致しない場合も根拠を残します。
追加のJSON項目を許容する利用側で試してください。画面上の専用入力・表示や新しい収集器は追加していません。

`supplied_timelines` は「適用申告が台帳の観測後」「申告版数が修正版そのものなのに公開修正の提供前」
という矛盾候補を `inconsistent` として示します。修正提供より後の勧告公開は矛盾としません。
不明な日時や比較できない精度は `unknown`。比較できた項目に矛盾がない場合の
`no_inconsistency_detected` も、修正済み・侵入なし・適切な管理の証明にはなりません。
先行提供などの背景を一次資料で確認してください。侵入の原因や更新怠慢は判定しません。
`evidence_authenticity_verified` / `patch_state_verified` / `causality_assessed` /
`negligence_assessed` などの検証フラグはfalseのままです。

出力膨張を防ぐため時系列は合計1,000行まで。省略件数と `timeline_coverage: limited` を明記します。
版数範囲の比較は合計100,000件までで、上限により未評価の資産は `unknown`、
`advisories_not_assessed` に未評価件数を出します。入力を分割して評価してください。
根拠未入力の旧台帳から大量の空時系列を作りません。これらはローカルの申告情報照合であり、
ホストの指紋収集・自動スキャン・参照URLへの接続・実機の変更は行いません。

## 5. 封じ込めと復旧

既存の[二者承認](../APPROVALS.md)、[レスポンダー](../RESPONDER.md)、[Okta](../OKTA.md)の経路を使います。
実操作では本人性を持つ署名付き承認を必須にし、対象・作用・期限・復旧手順・業務影響を先に固定してください。
VPNの接続制限/更新/隔離に対応するベンダー別レスポンダーは未実装です。汎用シェルコマンドで代替しません。
検証機器で「通信が止まった」「正常業務を復旧できた」の両方を独立した観測から確認します。
Oktaのモック成功を実組織でのセッション失効・復旧実績と同一視しません。

## 6. 緊急停止・保管・復旧

ゲートウェイの専用保存先に `STOP` ファイルがあれば、次の送信を拒否します。既に出た通信を取り消す機能ではありません。
監査・バックアップは暗号化済みですが、同じホストで鍵も奪われる攻撃は対象外です。

```sh
python -m aisecure.gateway_admin checkpoint --data-dir private-state > checkpoint.json
python -m aisecure.gateway_admin backup --data-dir private-state --output backup.sqlite3
python -m aisecure.gateway_admin prune --data-dir private-state --retain-days 30 --checkpoint-file checkpoint.json
```

バックアップ先は既存ファイルなら拒否します。checkpointとバックアップを別権限の保管先へ移してから削除を行います。
CLIは「別権限へ移したか」を独立検証しません。チェックポイント後の末尾削除は次の独立保管まで検出できません。
復旧はサービスを停止し、バックアップコピーを新しい700権限ディレクトリへ置き、同じ外部鍵でcheckpointを照合します。
暗号鍵のインプレース自動ローテーションは未実装です。鍵を単に変えると起動を拒否します。
鍵の交換は監査の継続性・旧バックアップ・旧キーの失効を含む移行設計と復旧演習が必要です。

## 7. 質・提供判定・問い合わせ

`python tools/run_full_tests.py` は1件でもスキップがあれば失敗します。標準の依存なしテストと区別してください。
`managed-quality.yml` で暗号化/署名、Chromium/WebKit画面、隔離ラボを継続検証します。
`public-site-smoke.yml` はPages公開後に公開URLの動画・リンク・画面を確認し、実問い合わせは送信しません。
WebKit試験はSafari/iPhone実機の試験ではありません。フォームの保存先・担当者の受信・重複・90日削除は別途テストが必要です。
運営者がテスト問い合わせを送る際はテスト表記と合成情報を使い、受付から削除までのバックエンド記録を確認します。

`python tools/release_gate.py docs/operations/validation.example.json` は必ず不足を報告します。
実環境と独立レビューの証拠を別途保管し、そのハッシュ・担当・日時を持つ台帳で判定してください。
このゲートは書類の完全性だけを検査し、証拠の真正性・本番安全性を認証しません。
`environment` が文字列でない、空白だけ、不正な制御文字を含む場合は入力エラーです。
`demo` / `synthetic` / `mock` / `unknown` は大小文字・前後空白の違いがあっても
実環境の証拠には数えません。任意の環境名を記入するだけで証拠の真正性が証明される
わけではありません。担当者が参照元を照合する必要があります。
署名付き配布物は `package-artifacts.yml` の成功と実attestationを確認し、コード追加だけで「署名済み」と主張しません。
