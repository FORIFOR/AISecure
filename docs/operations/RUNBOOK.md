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
署名付き配布物は `package-artifacts.yml` の成功と実attestationを確認し、コード追加だけで「署名済み」と主張しません。
