# ブラウザ内の送信前停止（評価版）

追加日: 2026-09-22。対象: `browser/aisecure` 拡張 0.2.0 + `aisecure.control.native`。
状態: **best effort の停止。完全な遮断ではない。**

`docs/security/THREAT_MODEL.md` の入口④（検査画面を開かずAIサイトへ直接貼る）を
塞ぐための最小実装である。攻撃者クラス A1・A2（不注意／手順省略）に対する対策であり、
A3（悪意ある内部者）・A4（侵害端末）には**有効ではない**。

## 何をするか

1. 対象ホストのページで、`window.fetch` をページ自身のスクリプトより先に包む。
2. POST/PUT/PATCH のうち、本文をテキストとして読めるものから文字列を取り出す。
3. 40文字未満は送らない。それ以上は端末内の Native Messaging ホストへ渡し、
   既存の `SECRET` / `PERSONAL` パターンで検査する（外部送信なし）。
4. 判定に応じて止める。

| 判定 | 画面 | 上書き |
|---|---|---|
| `block`（秘密情報パターン一致） | 停止。値は表示しない | **不可** |
| `review`（個人情報など） | 確認ダイアログ | 可（明示操作） |
| 本文を読めない（添付・バイナリ・ストリーム） | 「検査していない」と明示して確認 | 可（明示操作） |
| 検査サービスに接続できない | 停止 | **不可**（fail closed） |
| `no_findings` | 素通し | — |

`no_findings` は「安全」ではない。画面にも API にもその表現は出さない。

## 対象ホスト

`chatgpt.com` / `chat.openai.com` / `claude.ai` / `gemini.google.com`。
ホスト名は完全一致で判定する（`chatgpt.com.evil.test` は対象外）。
`manifest.json` の注入先と `enforce.js` の判定リストがずれると
`enforce.test.js` が落ちる。

ベンダーがエンドポイントのパスを変更しても検査は継続する。既知パスは監査記録の
ラベルに使うだけで、検査の条件にしていない（リネームで穴が空かないため）。

## 導入

```sh
python -m pip install '.[control]'
# 1. 拡張を chrome://extensions で「パッケージ化されていない拡張機能を読み込む」
#    → browser/aisecure を選択し、表示された拡張IDを控える
# 2. Native Messaging ホストを登録（拡張IDを指定）
python -m aisecure.control.native --extension-id <32文字のID> --state-dir ~/.aisecure-state
```

ホストマニフェストの配置は OS ごとに異なる。登録が完了していない場合、
対象サイトでの送信は**すべて停止する**（fail closed）。これは意図した挙動である。

## 確認済みの動作（2026-09-22、Chromium）

`content.js` と `inject.js` を document_start で読み込んだ実ページに対する実測。
判定は固定値でスタブし、遮断機構そのものを確認した。

| 条件 | 結果 | ネットワークへ到達したPOST |
|---|---|---|
| `block` | 確認画面表示 → Enterで取消 → fetch が AbortError | **0** |
| `review` → 明示的に許可 | 送信成功 | 1 |
| `no_findings` | 素通し（画面に何も出ない） | 1 |
| ブリッジ応答なし | AbortError | **0** |

判定ロジックは `enforce.test.js`（13件）、ネイティブホストは Python 側の
既存スイートが担当する。

## 防げないこと

以下は設計上の非目標であり、「防げる」と書いてはいけない。

- **拡張の無効化・別ブラウザ・別端末・スマートフォンアプリ。**
- **XMLHttpRequest・sendBeacon・WebSocket・Service Worker 経由の送信。**
  現状 `window.fetch` のみを包んでいる。
- **クロスオリジン iframe 内の送信。** 最上位フレームにのみ注入している。
- **ページによる回避。** ラッパーはページと同じ MAIN world に存在する。
  新しい iframe から素の `fetch` を取り出せば回避できる。技術的に避けられない。
- **検知そのものの回避。** ゼロ幅文字の挿入や符号化で通る
  （`docs/security/THREAT_MODEL.md` §5 の実測を参照）。
- **添付ファイルの中身。** multipart は「読めなかった」として扱う。OCRもない。

## 企業として迂回不能にする場合

ブラウザ内の拡張は利用者が外せる。管理下で外せなくするには、
Chrome Enterprise の Content Analysis Connector（管理ポリシーで配布される
ローカルエージェント）に接続する必要がある。これは本実装の範囲外であり、
プロトコル実装・管理配布・Windows 対応を伴う別作業である。

現状でこの拡張を「企業のDLP」と呼んではいけない。
