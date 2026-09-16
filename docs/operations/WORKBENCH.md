# Managed text workbench / 送信前チェック

状態: **0.4.0a1・管理されたローカル環境向けの開発版**。端末全体のDLP・VPN制御製品ではありません。

## まず動かす（外部AI・APIキーは不要）

```sh
git clone https://github.com/FORIFOR/AISecure.git
cd AISecure
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[workbench]'
python -m aisecure.workbench --demo
```

Windowsは `.venv\Scripts\activate` を使用します。表示された `http://127.0.0.1:8877/#token=...` を開きます。
トークンは読み取り後にURLから消去され、localStorageやCookieへ保存されません。再読込には起動URLを使います。
デモの分類は固定サンプルについてサーバー側で付与され、任意入力は未分類のままです。

「機密情報」を検査→拒否理由を確認→「公開済み情報」を検査→送信確認欄に同意→デモ受信を確認→履歴から説明を開けます。
デモ受信は同じプロセスのテスト受信器で、外部モデルではありません。終了すると一時監査DBと一時暗号鍵を削除します。

従来のログ相関画面は `python -m aisecure serve --demo` です。新しい画面と同じコマンドではありません。

## 実OpenAIへの接続（明示的に有効化する場合だけ）

対象は **OpenAI Responses APIの単一テキスト入力**。添付、画像、会話ID、ツール、任意ヘッダー、任意送信先を受け付けません。
APIキーとモデル名はサーバーの管理者設定に限定し、API呼出し元や説明AIから変更できません。
`store=false` はAPIレスポンス保管の設定であり、全種別のデータ保持ゼロを保証しません。提供元との契約・プロジェクト設定を確認してください。

導入先のSecret Manager等から次をプロセス環境に供給します。シェル履歴・Git・共有画面へ貼らないでください。

| 変数 | 内容 |
|---|---|
| `AISECURE_GATEWAY_KEY` | 32バイトの外部管理鍵・16進数64文字。監査暗号化とMAC用に用途別鍵を導出 |
| `AISECURE_LABEL_PUBLIC_KEY` | 管理者のEd25519公開鍵・16進数64文字。秘密鍵はゲートウェイへ置かない |
| `AISECURE_GATEWAY_TOKEN` | 利用者API専用の十分な長さのランダムトークン |
| `OPENAI_API_KEY` | 管理対象のOpenAIプロジェクト専用キー |
| `AISECURE_OPENAI_MODEL` | 利用権限を確認した実モデルID。モデル名を本製品が推測しない |
| `AISECURE_COLLECTOR_TOKEN` | 任意。DLP収集器専用。利用者トークンと同値は拒否 |

```sh
mkdir -m 700 private-state
python -m aisecure.workbench --live --data-dir private-state --ack-managed-egress
```

`--ack-managed-egress` は運用者の確認であり、ネットワーク制限を自動設定・検証するフラグではありません。
実データを扱う前に、対象アプリの直接送信・他プロセス・外部ブラウザ・管理者権限の経路を環境側で制限してください。
このASGIサーバーも `127.0.0.1` だけにバインドします。一般公開、トンネル、リバースプロキシへの転用は未対応です。

### 管理者による本文分類

画面が表示するリクエストIDを使い、管理者専用環境で正確な最終本文を確認します。端末の改行や末尾空白も署名対象です。
管理者の `AISECURE_LABEL_PRIVATE_KEY` はEd25519秘密鍵（32バイト、16進数）で、ゲートウェイの公開鍵と対応させます。

```sh
# text.txtは権限を制限した一時ファイル。stdoutの証明も機密扱いし、作業後に削除。
python -m aisecure.gateway_admin label --request-id APPROPRIATE_32_HEX_ID \
  --model YOUR_AUTHORIZED_MODEL --class public < text.txt
```

生成した証明を画面の「管理者の分類証明」に入れます。本文・ID・モデル・送信先・ポリシーが変わると無効、期限は5分です。
`public` は「一般公開済みと管理者が確認した情報」に限ります。分類証明は持ち出しを無条件で許可するものではなく、
認証情報のパターンや禁止分類に対する検査は常に実施します。一般利用者向けの分類変更・承認APIはありません。
組織SSOとの接続、承認者GUI、鍵の配布・失効は導入先に合わせた追加実装が必要です。

### 実行状態

| 状態 | 意味 |
|---|---|
| `not_executed` | 検査のみ。送信要求はしていない |
| `prevented_in_gateway` | このゲートウェイは送信処理を呼ばなかった |
| `dispatch_pending` | 送信予約を記録した。処理中または再起動前の結果が未確認 |
| `demo_received` | デモ受信器に渡った。外部モデルではない |
| `provider_completed` | 固定プロバイダーから処理完了の応答を受けた |
| `delivery_unknown` | エラー等で結果未確認。本文が届いていないとは断定しない |

同じID・本文・分類の再要求は記録を返し、自動再送しません。送信予約はSQLiteへ先に記録します。
異なるIDで意図的に再送することまで禁止する機能ではありません。未確認時に新IDでやり直す前に送信先で確認してください。
レスポンス本文は最初の応答で一度表示し、監査DBへ保存しません。秘密の本文・分類証明も保存しません。

## 説明・監査・入力上限

`--ollama-model INSTALLED_LOCAL_MODEL` は既存のローカル説明機能を使います。最小化した固定理由と参照IDのみ渡し、
生本文・モデル出力・秘密情報・実行ツールを渡しません。文章の正しさを保証せず、失敗時はルール説明へ戻ります。
ローカルモデル自体の外向き通信制限は運用側で確認してください。

HTTP入力1MiB、本文256KiB、利用者/収集器それぞれ毎分60要求、監査20,000レコード、画面履歴100件です。
DLP相関は直近10,000監査レコード中のDLP観測を対象とし、保持・欠損・観測範囲に依存します。大規模運用の性能保証ではありません。
監査容量が不足した場合は送信を拒否します。クライアントが切断しても、送信開始後の処理は既存の予約に対応して継続し得ます。

## 根拠となる一次資料

- OpenAI Responses API: https://developers.openai.com/api/reference/cli/resources/responses/methods/create
- Python HTTPS: https://docs.python.org/3/library/http.client.html
- 運用手順: [RUNBOOK.md](RUNBOOK.md)
- 全残タスクの扱い: [TASK_MATRIX.md](TASK_MATRIX.md)

## 架空の台帳も同じ画面で試す

```sh
python tools/make_workbench_examples.py /tmp/aisecure-synthetic
python -m aisecure.workbench --demo \
  --inventory /tmp/aisecure-synthetic/inventory.json \
  --advisories /tmp/aisecure-synthetic/advisories.json \
  --kev /tmp/aisecure-synthetic/kev.json
python -m aisecure.posture tools /tmp/aisecure-synthetic/current-tools.json /tmp/aisecure-synthetic/approved-tools.json
```

出力先は未使用のディレクトリを指定します。`CVE-2099-99999` と `LabVPN` は架空で、実際の事件・機器の脆弱性ではありません。実機の検証は実際のベンダー情報・認可された収集器で別に実施してください。
