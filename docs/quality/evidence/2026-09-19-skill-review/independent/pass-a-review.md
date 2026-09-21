# Independent Pass A

Task: 架空の資料を外部送信せずに検査し、結果を理解して手元に保存する。

Environment: pass-a-environment.json. Product unchanged by verifier. Browser Playwright with Chromium; local demo server on port 19890. No external transmission, publication or payment performed.

|id|method|expected|observed|status|evidence|environment|
|---|---|---|---|---|---|---|
|A01|Hints-free AI UI exploration|Find inspection, understand and save result|Sample inspected; review/unsent/coverage shown; JSON saved and parsed; execution_state=not_executed, release_authorized=false, no input body/question|PASS|pass-a-main.png; pass-a-result.png; pass-a-result.json|1440x1000|
|A02|Clear sample, click inspect|Local actionable error|Validation blocks invalid input; error outside card below unrelated disclosures while action area still asks to inspect again|FAIL|pass-a-empty.png; pass-a-narrow.png|1440x1000 and 390x844|
|A03|Change input method after A02|Remove obsolete error|Sample-length error persists after selecting own document|FAIL|Observed DOM, same error area as A02|1440x1000|
|A04|Upload synthetic non-PDF as fictional.pdf|Fail closed|Denied, unreadable coverage, DOC-FORMAT-MISMATCH|PASS|pass-a-invalid-pdf.png|1440x1000|
|A05|Browser offline then reconnect|Keep input and recover|Disconnected guidance; same sample retained; retry succeeds|PASS|pass-a-disconnected.png|1440x1000|
|A06|Edit after success|Do not export stale result|Save disabled|PASS|Observed button disabled state|1440x1000|
|A07|Visual main/result/failure/narrow image review|Readable layout and no horizontal overflow|All first four images opened; no horizontal overflow; clear typography. First inspection button below fold, especially narrow, is suggestion not blocker|PASS|pass-a-main.png; pass-a-result.png; pass-a-empty.png; pass-a-narrow.png|1440x1000 and 390x844|

P2: local validation and connection errors appear far from action/field, and stale validation persists across input mode changes. Place actionable error near relevant control and clear/update after edits.

Suggestion: initial status says 確認結果を更新しました despite no inspection; clarify it is application state or omit. Initial CTA is below viewport (about y=1117 desktop, y=1440 narrow); reducing instructional/form density could speed first action.

Not yet tested: native screen reader, actual Japanese IME, mobile hardware, OS-level network capture. No claims about real users or competitor superiority. Pass B/C pending implementation completion notice.
