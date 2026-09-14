# AI Secure / AIセキュア

**Evidence before action. 判断の根拠は手元に、操作の権限は人に。**

[Reachmade Labの製品ページ](https://reachmade.com/products/#aisecure) ・ [English README](README.md) ・ [サイト（日本語）](https://forifor.github.io/AISecure/index.ja.html) ・ [Site (EN)](https://forifor.github.io/AISecure/) ・ [閾値の決め方](docs/TUNING.md) ・ [Okta実対応手順](docs/OKTA.md) ・ [防御側連携プロトコル](docs/RESPONDER.md) ・ [セキュリティ検証](docs/SECURITY_REVIEW.md)

![AI Secure デモ](docs/media/screendemo.gif)

> 画面は英語・日本語に完全対応（右上で切替）。検知内容・計画・パラメータ説明も言語が切り替わります。

外部に公開された機器・特権ログイン・大量ファイル参照を結びつけ、「なぜ優先的に確認すべきか」「何を調べるか」「対応すると何が止まるか」までを一画面で示し、承認済みの対応要求を別プロセスの防御側へ渡せる、ローカル完結のセキュリティ統合プロトタイプです。

> **v0.3.0 は本番接続前のローカル統合版です。** `watch` によるCSV/JSONL書き出しの継続監視と、二者承認後に別プロセスの防御側へ署名付き対応要求を送る経路を実装しています。Oktaの直接経路だけは、実行時に環境変数からトークンを受け取り、限定したSystem Log取得とユーザーセッション失効を行います（トークンは保存しません）。VPN・ファイルサーバー等の資格情報は保持せず、その他の実環境操作は接続先のレスポンダーが検証して実行します。標準動作は決定論的ルールとテンプレート説明であり、生成AIは使用しません。
>
> **v0.2 で追加したのは、機能ではなく測定です。** 実ログファイルを読み取り専用で取り込む仕組みと、正常な業務でどれだけ誤検知するかを測る仕組みを入れました。検知ロジックそのものは v0.1 と同じです。

## 🧪 テストに協力してください（2分）

これは初期段階のプロトタイプで、**いま一番ありがたいのは、第三者の目です。** セキュリティの専門知識はいりません。

**インストール不要 → [▶ ブラウザでそのまま試す](https://forifor.github.io/AISecure/try.html)**（合成データ上の実際の画面。書き込みは無効）。触ってみて、「点＝深刻度スコアではなく、経路で見る」という考え方が伝わるかどうかだけ教えてください。それが一番の助けになります。→ [2分フィードバック](https://github.com/FORIFOR/AISecure/issues/new?template=tester-feedback.md)

もう一歩踏み込めるなら、この2つが本当に前進につながります。
- **[取り込みは、あなたのログ形式で動きますか？](https://github.com/FORIFOR/AISecure/issues/3)** — VPN / IdP / ファイルサーバのログ
- **[誤検知ベースラインに、抜けている正常業務はありますか？](https://github.com/FORIFOR/AISecure/issues/4)** — この数字を誠実にしている部分です

デモと分析は手元・オフラインで動きます。アカウントもテレメトリーもなく、データは端末の外に出ません。任意の `execute` 経路だけは、設定したレスポンダーへプロトコルに記載した署名付きメタデータを送信します。

## 実環境へつなぐ防御経路

ログ書き出しを継続的に監視し、変更があれば新しい証跡スナップショットを取り込みます。

```bash
python3 -m aisecure watch \
  --source generic-asset-csv=assets.csv \
  --source generic-auth-csv=auth.csv \
  --source generic-file-access-jsonl=access.jsonl
```

対応計画を確認した後、二者承認で、別に運用するVPN・IdP・ファイアウォール等のレスポンダーへ署名付き要求を送れます。レスポンダーが実操作後に `status: verified` を返した場合だけ成功として記録します。プロトコルは [docs/RESPONDER.md](docs/RESPONDER.md) を参照してください。

Oktaについては、`execute-okta` で承認済みの1ユーザー（`00u...`）のセッションを失効できます。失効APIの成功だけでなく、同じユーザーの `user.session.clear` がSystem Logで確認できた場合だけ成功と記録します。設定と手順は [docs/OKTA.md](docs/OKTA.md) を参照してください。

また、`watch-okta` でOkta System Logのログイン情報をHTTPS経由で直接取得し、ローカルの資産台帳・ファイル参照ログと結合できます。取り込むのは許可したメタデータだけで、取得原文は保存しません。

## すぐに動かす

必要環境は **Python 3.11以上**。ランタイムの外部Pythonパッケージ、APIキー、クラウド契約は不要です。ローカルLLMを使わない標準モードの説明です。

リポジトリを取得し、`AISecure` ディレクトリで実行します。

```bash
git clone https://github.com/FORIFOR/AISecure.git && cd AISecure
python3 -m aisecure serve --demo
```

Windowsでは、Pythonの導入方法に応じて `py -m aisecure serve --demo` または `python -m aisecure serve --demo` を使用してください。

起動時に表示される `Open:` のURLをブラウザで開きます。トークンはURLフラグメントからブラウザのメモリに取り込まれ、直後にアドレス欄から削除されます。再読み込み後に認証画面が表示された場合は、起動時のAPI tokenを入力してください。トークンを共有・公開しないでください。

`127.0.0.1` のみで待ち受けます。`localhost` やLANのIPでの接続はHost検証で拒否します。公開トンネル、ポート転送、リバースプロキシによる一般公開には使用しないでください。

停止は `Ctrl+C`。標準保存先は `~/.ai-secure-demo/` です。共有・クラウド同期フォルダには保存しないでください。

```bash
# 専用の保存場所・ポートを指定する場合。共通オプションはサブコマンドの前。
python3 -m aisecure --data-dir ./private-state serve --demo --port 8765

# テスト（標準ライブラリのみ）
python3 -m unittest discover -s tests -v
```

## 最初に試す操作

1. 概要の「保守アカウントに、関連する3つの兆候。」と、根拠のイベントIDを確認します。
2. 「対応計画を確認する」から、業務影響、事前確認、実運用時の復旧方針を読みます。
3. 承認理由を10文字以上入力し、`SIMULATE ONLY` と入力し、確認欄をチェックします。「承認してシミュレーション」を押すと、実操作なしの結果を監査記録に残します。

シミュレーション後も検知候補は消しません。実際に封じ込められた証拠がないためです。実際のアカウントや機器は変更しません。

同梱デモは **3資産・148イベント**、大量参照 **130個**、そのうち機密ラベル付き **42個** の合成データです。GSSの実ログや実際の攻撃の再現ではありません。`DEMO-ADV-001` とCVSS 6.5も説明用の架空設定であり、GSSで悪用された実際のCVEや数値を示しません。

## v0.3 で追加したもの

```bash
# 実ログを読み取り専用で取り込む（ソースには書き込みません）
python3 -m aisecure profiles
python3 -m aisecure import \
  --source generic-asset-csv=examples/logs/assets.csv \
  --source generic-auth-csv=examples/logs/auth.csv \
  --source generic-file-access-jsonl=examples/logs/file-access.jsonl \
  --out snapshot.json --quality quality.json

# 正常業務でどれだけ誤検知するかを測り、閾値を探索する
python3 -m aisecure baseline --days 5 --users 40 --out normal.json
python3 -m aisecure baseline --days 5 --users 40 --attack --out incident.json
python3 -m aisecure evaluate normal.json incident.json --sweep --out report.md

# 決めた閾値で起動する（設定は監査記録に残ります）
python3 -m aisecure --rules rules.json serve
```

同梱の合成データ（40ユーザー×5日×4シナリオ、85,509イベント）で測った結果、既定の閾値では **単体の大量参照ルール（AS-003）は103件中102件が正常業務**でした。一方、**相関ルール（AS-004）は誤検知0件**で事案を検知しています。閾値を上げて誤検知を0にすると、事案も検知できなくなります。測定手順と全数値は [docs/TUNING.md](docs/TUNING.md)、生の出力は [docs/evaluation/](docs/evaluation/) にあります。

取り込みの仕組みと独自ログ形式への対応は [docs/CONNECTORS.md](docs/CONNECTORS.md) を参照してください。

## 実装済み / 未実装

| 項目 | v0.3の状態 |
|---|---|
| 日本語ダッシュボード、資産、対応計画、監査記録 | 実装済み。スマートフォン幅にも対応 |
| JSONスナップショット入力 | 実装済み。2 MiB、200資産、5,000イベントまで |
| 公開・特権・機密への到達性による優先判定 | 実装済み。値は入力台帳の申告であり、経路自動探索ではない |
| 5分間の大量参照と同一セッションの相関 | 実装済み。閾値は設定で変更可・限定スキーマ |
| CSV / JSON Lines ログの読み取り専用取り込み | 実装済み。マッピングプロファイル方式。SIEM・VPN・ファイルサーバーへの接続はなし |
| 変更されたログ書き出しの継続監視 | 実装済み。`watch` が同じ読み取り専用取り込みを一定間隔で実行 |
| Okta System Logの直接監視 | 実装済み。`watch-okta` が直近のログイン情報をHTTPS取得。実Okta組織でのE2Eは未実施 |
| 誤検知評価と閾値スイープ | 実装済み。合成データで測定済み。実ログでの測定は導入先ごとに必要 |
| 検知設定の外部化・監査記録 | 実装済み。設定ハッシュを起動時と各検知結果に記録 |
| ユーザー・セッション・ファイル識別子の仮名化 | 実装済み。匿名化ではなく、秘密のない集計情報にも変わらない |
| 対応計画、承認期限、二重承認・古い入力の拒否 | 実装済み。実操作は署名付きレスポンダー経由 |
| 署名付き実対応要求と実行後検証 | 実装済み。HTTPSの別プロセスへ限定メタデータを送信。プロバイダー別レスポンダーは別途必要 |
| HMAC監査チェーン・外部チェックポイント検証 | 実装済み。外部保管先は未接続 |
| ルール説明 | 実装済み。LLM未使用と明示 |
| Ollama補助説明 | アダプター実装・モックテスト済み。実モデルは未検証 |
| VPN / ファイルサーバーへの直接自動収集 | 未実装。Okta以外は読み取り専用のCSV/JSONL書き出しを監視 |
| KEV / JVN / ベンダー情報の自動同期・影響バージョン判定 | 未実装。悪用有無・CVSSは入力値 |
| 本番SSO、RBAC、複数テナント、二者承認 | 未実装 |
| Oktaユーザーのセッション失効 | 実装済み。`execute-okta` が失効後の `user.session.clear` を検証。実Okta環境でのE2Eは未実施 |
| その他の実機操作・復旧 | 未実装。プロバイダー別レスポンダーと復旧演習が必要 |
| 保管時暗号化、独立監査保管、鍵管理基盤 | 未実装。標準SQLiteは平文で、OS権限のみ |
| 実環境の正常ログでの誤検知率、検知率 | 未測定。合成データでの測定のみ |
| 本番負荷、長期運用、大規模ログ | 未測定 |

## 入力・CLI

```bash
# 組み込みの取り込みプロファイルを一覧
python3 -m aisecure profiles

# 実ログを取り込む（読み取り専用。--ingest でDBにも取り込み）
python3 -m aisecure import --source generic-auth-csv=auth.csv --out snapshot.json

# 誤検知評価用の合成トラフィックを作る
python3 -m aisecure baseline --days 5 --users 40 --attack --out incident.json

# 検知・誤検知を数え、閾値をスイープする
python3 -m aisecure evaluate normal.json incident.json --sweep --out report.md

# 入力用の架空データを新しく生成
python3 -m aisecure sample > snapshot.json

# JSONを分析。シェルからの入力は常に「手動入力」と表示
python3 -m aisecure analyze snapshot.json

# 監査チェーンの内部整合を検証
python3 -m aisecure verify-audit

# 独立した場所に保管するチェックポイントを出力
python3 -m aisecure checkpoint > checkpoint.json

# 以前、独立保管したチェックポイントと照合
python3 -m aisecure verify-audit --anchor checkpoint.json
```

`checkpoint.json` を同じホストに置くだけでは独立保管になりません。承認された別権限の保管先へ移す運用が必要です。チェックポイントより後に追加された記録の末尾削除までは検出できません。

HTTP経由の入力は2 MiB・200資産・5,000イベントまでです。それより大きい実ログは `import --ingest` か `analyze` を使ってください（CLIは同じ検証をより大きな上限で行います）。

入力契約は [docs/INPUT_SCHEMA.md](docs/INPUT_SCHEMA.md) を参照してください。原文、ファイル本文、パスワード、トークン等を含む未定義フィールドは拒否します。認証情報を既存の識別子フィールドに誤って入れないことも必要です。入力されたメタデータ自体が信頼できるとは限りません。

## 任意のローカル生成AI

既にOllamaへインストールした、クラウドではないローカルモデルを使う場合だけ指定します。

```bash
python3 -m aisecure serve --demo --ollama-model YOUR_INSTALLED_LOCAL_MODEL
```

`YOUR_INSTALLED_LOCAL_MODEL` は実際のローカルモデル名に置き換えます。モデルのダウンロードやOllamaの導入はこのアプリでは行いません。既定の説明で操作確認するだけなら不要です。

本アプリが呼び出すのは固定の `http://127.0.0.1:11434/api/chat` のみです。HTTPプロキシとリダイレクトを使用せず、`cloud` を含むモデル名を拒否します。ただし **ローカルOllama側の設定による外向き通信まで保証するものではありません**。ローカルモデルであること、Ollama側のクラウド機能無効化、必要なネットワーク制限を運用側で確認してください。

モデルに渡すのは生成済みの短い事実と限定された参照IDのみです。原文ログ・ユーザーの文字列・ファイル本文を渡しません。モデルにツールを与えません。説明の参照IDは照合しますが、文章の正しさを証明する検証器ではありません。失敗時は「ルール説明」に戻り、実際の処理経路を表示します。

## 構成

```text
実ログ(CSV/JSONL) → connectors/読み取り専用取り込み ┐
                                                    ├→ schema/検証・仮名化 → engine/検知 ← rules/閾値設定
metadata JSON ──────────────────────────────────────┘                         ├→ explain/説明（権限なし）
                                                                              └→ policy/対応計画 → 人の承認 → simulation
                                              store/スナップショット + 監査チェーン
                                                      └→ local HTTP UI

baseline/正常業務の合成 → evaluate/誤検知測定・閾値スイープ → rules
```

- `aisecure/schema.py`: 厳密な入力検証と仮名化
- `aisecure/rules.py`: 検知閾値の設定・検証・ハッシュ化
- `aisecure/connectors/`: 読み取り専用のログ取り込みとマッピングプロファイル
- `aisecure/baseline.py`: 正常業務の合成トラフィック生成
- `aisecure/evaluate.py`: 検知・誤検知の測定と閾値スイープ
- `aisecure/engine.py`: 決定論的検知・相関・観測範囲
- `aisecure/policy.py`: 許可された対応計画とシミュレーター
- `aisecure/explain.py`: テンプレート説明・任意のローカルモデル
- `aisecure/store.py`: ローカル保存・計画状態・監査
- `aisecure/server.py`: ループバック限定の開発用HTTP API
- `web/`: 外部CDN・フォント・トラッキングなしの画面

Python標準HTTPサーバーは本番用途ではありません。これは依存関係なく体験・ルール検証を始めるための技術選択です。バックエンドのHTTP層は、本番化の際に認証・権限・運用基盤とともに置き換えてください。[S5]

## 設計と製品化

詳しい内容は [製品設計書](docs/PRODUCT_SPEC.md)、[脅威モデル](SECURITY.md)、[セキュリティ検証](docs/SECURITY_REVIEW.md)、[取り込み](docs/CONNECTORS.md)、[閾値の決め方](docs/TUNING.md)、[テスト結果](docs/TEST_REPORT.md)、[変更履歴](CHANGELOG.md)、[情報源](docs/SOURCES.md) を参照してください。GitHub公開、既存Astraリポジトリの変更、クラウドデプロイはこの成果物では実施していません。

同梱ファイルの整合性は `shasum -a 256 -c SHA256SUMS.txt`（Linuxでは `sha256sum -c`）で確認できます。これは配布物が壊れていないことの確認であり、署名による発行元証明ではありません。

MITライセンス。公開前に名称・商標と採用する外部コネクタのライセンスを別途確認してください。
