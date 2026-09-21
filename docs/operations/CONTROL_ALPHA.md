# AISecure 統合保護・VPN・高度分析：追加実装（検証用）

**VPN対策と高度な分析を後回しにしない追加実装です。すべての本番要件が完了した製品ではありません。**

対象の元コミット: `dce7804ee6a25237ea16819fe72738dae2813988`。
この変更は取得した同コミットのGitHub Actionsソース配布物を基に作成しました。
GitHubへのpush、PR作成、公開サイト変更、企業端末へのインストール、実機への設定変更は実施していません。
実装の受入条件は `CONTROL_SCOPE.md` と `CONTROL_VALIDATION.json` に分けて記載します。

## 起動

Python 3.11以降。新しい仮想環境を使用してください。

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[control]'
python -m aisecure.control --demo
```

表示される `http://127.0.0.1:8878/#token=...` を開きます。トークンは画面が読み取った後にURLから消し、永続化しません。
初回は [資料を検査してJSONを保存する手順](../FIRST_PROOF.md) を試してください。
再読み込み時は画面の再接続欄に起動URLのトークンを入力します。本文・トークンはブラウザに永続化しません。
組み込み用途は [公開契約](DOCUMENT_CONTRACT.md) を参照してください。

「関連する操作」→「架空のVPN・ファイル操作を読み込む」で、VPNのリスク、同じセッションでの機密ファイル操作、
少量反復の外部送信を確認できます。`LabVPN` と `CVE-2099-99999` は架空です。
デモは外部AIへの送信・実機変更をしません。終了時に一時的な鍵とデータを削除します。

一般の利用者がアップロードしたファイルを自動的に「公開情報」とする機能はありません。
未分類は保留します。検出なしは、安全性や送信許可の証明ではありません。

### 保存が必要な管理モード（外部AIキー不要）

Secret Manager等から `AISECURE_GATEWAY_KEY`（32バイト・16進数64文字）、
`AISECURE_GATEWAY_TOKEN`、必要に応じて別の `AISECURE_COLLECTOR_TOKEN` を供給します。
認証トークンは32文字以上の十分にランダムな専用値です。鍵をGitやシェル履歴へ貼らないでください。

```sh
mkdir -m 700 private-state
python -m aisecure.control --managed --data-dir private-state \
  --organization company --source security-collector
```

このモードで、資料検査、VPN台帳、分析、監査を利用できます。外部AIの送信機能は無効です。
サーバーはloopbackのみで、公開サーバー化、トンネル、リバースプロキシ、多人数・多テナント運用を保証しません。

## 資料検査

対応する解析対象は `.xlsx` / `.pptx` のXML部分全体と、PDFの抽出可能な文字・構造です。
非表示シート・行列、ノート、コメント、属性、外部参照、埋め込み内容も検査範囲・未検査として扱います。
数式・マクロ・埋め込みプログラムは実行せず、外部参照も取得しません。
認証情報・個人情報・機密表記・指示注入は小さな明示的パターン検査です。意味理解による完全な分類ではありません。

制限はファイル合計16MiB・最大4件、展開合計64MiB・各要素8MiB・最大2048要素、文字抽出2MiB/件、PDF最大200ページです。
時間・メモリ・出力サイズにも上限があります。上限超過や解析失敗を検出なしに変換しません。
OCR、画像の意味理解、ウイルスエンジン、旧Office、完全な暗号化ファイル復号はありません。
画像や未対応内容はpartial/unreadableのため、分類署名があっても元ファイル送信は保留します。

### 解析の隔離

通常のローカル評価は、APIキーを継承しない子プロセスでタイムアウトと資源制限を設けます。
**子プロセス化は、OSによるネットワーク隔離ではありません。** Windowsの同等な資源制約も別途必要です。
信頼できないファイルの本番処理にはネットワーク分離された解析基盤を使用してください。

```sh
# 依存関係をレビューしてビルドする。ビルド時にはパッケージ取得が必要。
podman build -f deploy/control/Containerfile -t aisecure-worker .
# 検証したイメージの不変のrepo digestを用意する。以下のIMAGEはその値を指定する。
python -m aisecure.control --managed --data-dir private-state \
  --worker-image 'IMAGE@sha256:DIGEST'
```

実行時はネットワークなし、ホストマウントなし、読み取り専用、能力削除、非root、CPU・メモリ・プロセス数制限です。
イメージの実ビルド、署名検証、OS別Podman配布、侵入試験は今回未実施です。

### 外部AIへの添付送信

明示liveモードは固定OpenAI Responses APIのみです。管理側のモデル設定、公開鍵、APIキー、ネットワーク分離解析イメージ、
管理送信経路の確認が必要です。任意URL、file_id、外部ファイルURL、会話履歴ID、ツール、追加ヘッダーは受付けません。
分類証明は質問・全添付・モデル・送信先・組織・ポリシー・解析器バージョン・期限と結びつきます。
送信側は検査したものと同じバイト列を送信し、送信予約を先に永続記録します。
同じ要求の自動再送はしません。通信エラーを「未送信」とは表示せず、結果不明とします。

```sh
python -m aisecure.control --live --data-dir private-state --organization company \
  --worker-image 'IMAGE@sha256:DIGEST' --ack-managed-egress
```

必要な環境変数は既存workbenchと同じ `AISECURE_GATEWAY_KEY`、`AISECURE_GATEWAY_TOKEN`、
`AISECURE_LABEL_PUBLIC_KEY`、`OPENAI_API_KEY`、`AISECURE_OPENAI_MODEL` です。
`--ack-managed-egress` は確認であり、端末の直接通信を自動で防止する機能ではありません。
`store=false` は全種別の保持ゼロの保証ではありません。実プロジェクトでの送信・不達・保持条件は別途確認が必要です。

管理者専用環境では、質問・files・request_idだけを含む最終要求JSONについて次で署名できます。
`files`の各要素は `{"format":"xlsx","base64":"..."}` です。分類は管理者が最終内容を確認したpublicに限ります。

```sh
# AISECURE_LABEL_PRIVATE_KEYは管理者環境だけに供給する。サービスには置かない。
python -m aisecure.control.admin label final-request.json \
  --model AUTHORIZED_MODEL --organization company --output classification.json
```

分類証明は持出禁止や未検査を上書きしません。有効期限は5分です。
テキストの伏せ字案は、明示操作で表示する**非可逆・非忠実な文字列の抜粋**です。元のOffice/PDFを編集したコピーではありません。
画像、数式、レイアウト等が失われ得るため、別途確認・再分類が必要です。機密区分を自動的に引き下げません。

## VPN：情報取得、姿勢評価、承認付き対応

既存の `aisecure.providers.fortios_inventory` を利用して、管理対象FortiOSの状態をTLSで読み取り専用取得できます。
公開面・到達性・MFAは自動推測しません。認可された収集器が確認した台帳・設定条件を入力します。
KEVには固定公開フィードの取得処理を追加し、公開日時と成功した取得日時を分離しました。版数照合は供給した数値範囲に限定します。
KEVに載っていないことや、見つかったルールの少なさを、安全の証明にしません。

```sh
python -m aisecure.providers.fortios_inventory \
  --host MANAGED_DEVICE --asset-id vpn-01 --output inventory.json
python -m aisecure.control.admin vpn-assess vpn-input.json --output vpn-assessment.json
```

`vpn-input.json`は `inventory, advisories, kev, controls` の4キーです。
前3項目は既存postureと同じ。controlsは各資産の `{asset_id, observed_at, mfa_required, admin_public, supported}`。
`observed_at`はUnix秒、未確認のboolはnull。外部へのポートスキャン・侵入テストを自動実施しません。

### 狭い実機操作経路

追加したFortiOSアダプターは、**事前登録した単一のacceptルールのstatus変更だけ**です。
対象ホスト、ポリシーID、VDOM、UUIDを管理者設定で固定します。任意コマンド・任意ターゲットは受付けません。
設定例の `deployment_verified` と `single_writer_verified` は既定falseにし、実環境で確認した担当者だけが更新してください。
フラグ自体が実機の検証を行うものではありません。

```json
{
  "target": {
    "id": "vpn-policy-01", "host": "vpn.example.invalid", "policy_id": 42,
    "vdom": "root", "port": 443,
    "expected_uuid": "12345678-1234-1234-1234-123456789012"
  },
  "deployment_verified": false,
  "single_writer_verified": false
}
```

実機操作はUIからは提供しません。`AISECURE_FORTIOS_WRITE_TOKEN`は実行プロセスの管理者環境だけに供給します。
計画の作成は読み取りを行います。権限・バックアップ・接続元の認可を確認してから利用します。

```sh
python -m aisecure.control.admin plan --config device.json \
  --operation disable_registered_rule --output proposal.json
# 独立した各承認者が自分のAISECURE_APPROVAL_PRIVATE_KEYを使う。
python -m aisecure.control.admin approve proposal.json --approver operator-a \
  --role primary --output approval-a.json
python -m aisecure.control.admin approve proposal.json --approver operator-b \
  --role secondary --output approval-b.json
# public-keys.json は承認者ID→32バイトEd25519公開鍵の16進表記。秘密鍵ではない。
python -m aisecure.control.admin execute proposal.json --config device.json \
  --approval approval-a.json --approval approval-b.json --public-keys public-keys.json \
  --data-dir private-state --confirm 'EXECUTE REGISTERED VPN RULE CHANGE' --output result.json
```

承認は異なるIDだけでなく**異なる公開鍵**でなければ通りません。状態・対象・操作・期限の変更で無効になります。
実行直前に状態を再読し、変更されていれば止めます。別の管理者による同時設定変更まで原子的に防げるAPIではないため、
単一の変更経路/メンテナンス窓が必要です。STOPファイル、再送防止、実行後再読を備えます。
復旧操作 `restore_registered_rule` にも新しい計画・二者承認が必要です。

**status変更の確認は、VPNの封じ込め成功ではありません。**
後続ルールへのフォールスルー、既存セッション、IPv6、HA、VPNリスナーへの到達性、管理接続の維持を別途試験してください。
ファームウェア更新、ゼロデイの完全防御、他ベンダー制御、実際の侵入の断定は実装済みとは扱いません。

## 高度な分析

認証済み収集器から `/api/events` に正規化前の許可メタデータをPOSTします。
組織・sourceは管理者が起動時に固定します。利用者のトークンは取り込み操作には使えません。
actor/session/asset/targetは、保存前に組織と用途で分離したHMAC識別値へ置き換えます。
異なるログで同じ利用者を結ぶためのID対応は収集器側の明示的契約が必要です。

```json
{"id":"event-001","at":2000000000,"kind":"vpn_login","actor":"example-user",
 "session":"example-session","asset":"vpn-01","result":"success","channel":"vpn",
 "privileged":true,"mfa":false,"device_trusted":false}
```

この時刻は形式例であり、実投入時には観測したUnix秒が必要です。未来/古すぎる時刻・余分な項目・boolの件数は拒否します。
種別: vpn_login / idp_login / file_read / egress / privilege_change / collector_heartbeat。
認証・ファイルアクセス・機密送信の相関、単発の機密送信、24時間の少量反復、認証失敗後の成功を検査します。
同じ組織・利用者・セッションと時間順序を要求し、別人のログを結んで侵入と断定しません。
遮断済みと実送信/不明も区別します。分類は収集元の正確性に依存します。

確認済み14〜365日分の基準送信量を用意すると、中央値/MADを使う逸脱条件も利用できます。
`--baseline-file` は管理者だけが読み書きできるJSONで、`[{actor, until, samples:[日次byte量,...]}]`。
評価期間より前に終了した固定データを使用します。事故データを自動で「正常」に学習させません。
基準未設定はnot_configured。これらはルール/統計的検出であり、不正行為の確率推定ではありません。

## 小さな監査ログ

新しい監査メタデータは1イベント2KiB以内（暗号化・SQLite等の保管時の追加分を除く）。
ファイル名・全文・秘密値・API応答本文を監査へ残しません。認証済み画面とJSONLで確認します。
暗号化された既存SQLiteとHMAC監査チェーンを再利用し、要求/結果・読み取り範囲・理由IDを残します。
収集メタデータは認証された監査チェーンを分析の正とし、索引テーブルの削除で観測が消える構成にしません。
UI履歴100件、export最大1000件（API実装の上限）。これはすべての履歴を表示する保証ではありません。
容量上限で黙って記録を捨てず、新規処理を拒否します。記録上限や分析に伴う遅延は本番負荷で測定してください。

```sh
python -m aisecure.control.admin audit-export --data-dir private-state --output audit.jsonl
```

保持削除は独立保管チェックポイントとバックアップを先に確保し、停止中に既存Evidence.pruneまたはEventStore.pruneを実施します。
ログ末尾の切り詰め検知、WORM運用、鍵ローテーション、保存媒体からの完全消去はコード単体で保証しません。
JSONLの書き出しは平文です。資料を復元/完全再判定するための原本保管機能ではありません。

## ブラウザ連携の実装範囲

`browser/aisecure` はChrome/Edge用Native Messagingの**明示的な送信前検査ツール**です。
ユーザーが拡張機能で資料/文章を選択して検査します。ネイティブホストにはAPIキー、任意パス、コマンド、署名権限を渡しません。
許可originとメッセージを検証し、秘密本文は監査に残しません。

```sh
python tools/install_control_native.py --extension-id YOUR_EXTENSION_ID \
  --state-dir /ABSOLUTE/PRIVATE/STATE --output /NEW/PRIVATE/HOST_OUTPUT
```

生成するのは登録用ファイルです。ブラウザ/OS別NativeMessagingHostsへの登録、外部管理鍵の供給、拡張機能の配布が別途必要です。
Windows登録、iOS/Safari版は今回未実装です。Chromeが管理する企業DLPコネクターとの連携も未実装です。
**ChatGPT/Claude/Geminiの送信を自動的に横取り・遮断する機能ではありません。**
サイトの資料選択・自動アップロード・貼り付け・会話送信を実際に止めることは、この拡張機能では保証しません。
「保護済み」を誤表示しないようbrowser_enforcement / release_authorizedはfalseです。
この最も重要な未完了項目を、仕様文書だけで対応済みにしません。

## テストと一次資料

```sh
python -m pip install '.[control]' httpx
python -m unittest discover -s tests/control -t . -v
node --test browser/aisecure/protocol.test.js
```

今回の実行環境はPython 3.13.5、pypdf 5.9.0、defusedxml 0.7.1、cryptography 46.0.4、uvicorn 0.48.0です。
新しいcontrol依存条件はpypdf>=6.19,<7です。実行環境のネットワーク制約で更新できず、**この宣言版での再試験は未実施**です。
同梱CIはその依存条件で再試験する設定ですが、GitHubにpushしていないため今回のCI実行結果はありません。
実行ログと基準コミットの既存回帰テストの除外/skip理由を検証記録に含めています。

- OWASP file uploads: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OpenAI file inputs: https://developers.openai.com/api/docs/guides/file-inputs
- Chrome Native Messaging: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- Chrome webRequest boundaries: https://developer.chrome.com/docs/extensions/reference/api/webRequest
- Chrome Content Analysis SDK (not integrated): https://github.com/chromium/content_analysis_sdk
- Fortinet firewall-policy contract: https://docs.ansible.com/projects/ansible/latest/collections/fortinet/fortios/fortios_firewall_policy_module.html
- CISA KEV source: https://github.com/cisagov/kev-data
