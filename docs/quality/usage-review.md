# GUIの使い方の見直し — 2026-09-19

対象は未コミットのローカル変更。revisionとファイルハッシュは evidence/2026-09-19-usage/source.json。
導入済み outcome-first-ux と world-class-ui を適用。今回は実装担当による追加確認で、人間の初見評価・新規独立評価ではない。

変更前：質問欄が要約依頼に見え、保留が操作失敗に見えやすい。保存を必須のように案内していた。
変更後：送信前の検査という目的、質問も検査対象であること、検査完了と送信判定の違い、原本の修正→再選択→再検査を説明。画面内の使い方を追加し、JSON保存は必要時だけと明記。FIRST_PROOFもGUI利用を先頭にした。
初回目視で説明追加による縦長化を認め、重複する案内を削減して再検証した。既存の色・部品・レイアウトを維持。

- PASS：U1の初画面・サンプル保留・次の操作を起動中のCodex内ブラウザで操作確認。
- PASS：既存ブラウザ回帰試験。360/390/768/1440px、保存JSONと監査記録の照合、入力変更、失敗からの復帰。詳細の各判定・環境は evidence/2026-09-19-usage/browser.json。外部リクエスト・JSエラーなし。
- PASS：初期desktopと結果mobileのスクリーンショットを実際に開いて確認。結果・保存・復帰の試験は画像とは別に実行。
- PASS：node --check aisecure/control/web/app.js と git diff --check、exit code 0。
- NOT_APPLICABLE：今回の案内文変更に対するPython再ビルド・全件再試験。実行層の変更なし。以前の結果を今回の再実行とは扱わない。
- BLOCKED：人間の初見成功率、ネイティブIME、実ブラウザ200%ズーム、スクリーンリーダー。CSS拡大や合成イベントで代用してPASSにしない。

再現コマンド（exit code 0、2回実行、証拠は最終実行）：

```sh
NODE_PATH=/Users/shuhei/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules node tools/check_control_browser.cjs docs/quality/evidence/2026-09-19-usage
```

stdoutは同フォルダ browser.log、スクリーンショット・録画・保存JSONも同フォルダ。
公開・push・外部AI送信なし。ユーザー用のdemoは起動状態で残した。
