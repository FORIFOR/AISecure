# Document preflight acceptance — 0.4.0a3.dev0 local improvement

Fixed before implementation, 2026-09-19. The existing `docs/site/ACCEPTANCE.md`
covers the public marketing site; this document covers the local control app.

## Task and boundary

A first-time evaluator inspects an editable synthetic spreadsheet, understands why
it needs review, and saves a machine-readable report without sending to an AI.
Input: a question and 1–4 xlsx/pptx/pdf files, or an editable synthetic xlsx.
Outcome: decision, evidence rules, inspected/uninspected coverage, no-send state,
and a JSON report associated with the inspected bytes. A review/block result is a
successful inspection, not successful delivery. No findings is not authorization.

Existing claims: document inspection and encrypted metadata storage are implemented;
DemoTransport is a local simulation; browser-wide enforcement, OCR, VPN containment
and live deployment are not proven. See ../operations/CONTROL_SCOPE.md for all gates.

## Fixed checks

Environment: local macOS, Python 3.14, installed control dependencies, real loopback
ASGI server, available Chromium/WebKit engines. Record exact versions and revision
in verification.md. Commands, exit codes and artifacts go under a dated evidence
folder. Do not label an unexecuted check PASS.

| ID | Expected result / measurement | Verification and evidence |
| --- | --- | --- |
| A1 | Fresh first screen offers editable synthetic data, no account/key/provider required; at most 2 clicks from connected screen to report | Browser run against real server; report and screenshot |
| A2 | Sample with confidential marker gives review; synthetic secret gives block; both say no external send; readable rule explanation and next action | Browser + SDK tests, downloaded JSON matches returned report |
| A3 | Unsupported/malformed input stays review/block; invalid input retains edits; corrected input can be checked | Browser failure/recovery and core tests |
| A4 | Edits invalidate old results and downloads; processing is visible; repeat clicks cannot overlap; unknown send is not automatically retried | Browser delayed/error response tests + existing reservation tests |
| A5 | Reload/401 provides token recovery without token persistence; request body and token do not enter artifacts/audit | Browser reload/auth recovery; audit payload assertions |
| A6 | Report saves valid JSON, includes schema/scanner and byte identity, omits source text/question/token; CLI does not overwrite existing output | Compare browser/CLI/SDK artifacts; subprocess tests |
| A7 | Same scanner implements GUI, SDK, CLI; limits, errors, enums, experimental compatibility, permissions documented | Contract tests + independent code review |
| A8 | 390px mobile and desktop: no horizontal overflow, keyboard operation and visible focus; long Japanese input and composition events; 200% zoom and reduced motion | Real browser checks with screenshots. Native OS IME and human assistive-tech evaluation separately recorded |
| A9 | Full required tests, JS syntax, package wheel, release-gate self-test, tracked + newly authored file manifest consistency | Commands and exit codes; do not weaken tests |
| A10 | No outside requests during primary task; demo leaves no state after shutdown; saved artifact survives shutdown | Browser request log, filesystem inspection |

Comparison protocol: use this same synthetic xlsx and review/save task with a
candidate established document inspection product. Measure setup prerequisites,
clicks, result correctness, recovery without re-entry, and portable report output.
No competing product is installed/authorized here: comparative timing and real
beginner success rate remain BLOCKED, not an AI quality score. The two-click target
is a local acceptance criterion, not a measured claim of superiority.

Native browser extension installation, OS enforcement, real provider delivery,
FortiOS actions, human usability evaluation and Windows execution require separate
environments/permissions and remain BLOCKED. No changes to their completion claims.

## Skill-guided follow-up (fixed before follow-up implementation)

Retain A1–A10. Scope: same document inspection task and local authorization.
Evidence lives under `evidence/2026-09-19-skill-review/`; earlier results are historical.

| ID | Expected result | Method / evidence |
| --- | --- | --- |
| S1 | SDK/CLI and GUI report shapes have packaged Draft 2020-12 schemas; current real output and prior report fixture validate; unknown schema/unsafe approval flag rejected | Standard JSON Schema validator, wheel resource smoke, negative fixtures |
| S2 | CLI output appears only after complete write; existing/symlink target unchanged; injected write/publish failure leaves no partial result; POSIX mode 0600 | Failure injection, concurrency and real CLI tests |
| S3 | Current result and save action are adjacent; errors visible beside main operation and focus moves to invalid field; startup does not claim a check completed | Browser assertions, first-use independent exploration, before/after images |
| S4 | Initial task is operable at 360/390/768/1440, long Japanese, keyboard and reduced motion; synthetic composition cannot submit | Real server/browser; native IME/zoom/human evaluation remain separately BLOCKED |
| S5 | New skills are byte-identical to reviewed local kit and do not replace existing instructions | Kit checksums, installation log, version/provenance record |
| S6 | Separate reviewer receives task/startup only before implementation details, then reviews source/contracts and saved artifact | AI first-use exploration record, not a human success rate |

## U1 — GUIの使い方の見直し（追加）

測定環境：ローカルdemo、macOSのブラウザ、架空の初期サンプル。
期待：初画面で外部AIの回答を生成しないと分かり、検査ボタンへ進める。
検査後は処理完了と送信判定を区別し、保存または原本修正の次の操作が分かる。
方法：動作中のGUIで初期表示・サンプル検査・保留結果を確認。既存のブラウザ回帰試験で保存・入力変更・復帰を検証。
証拠：docs/quality/evidence/2026-09-19-usage/ および docs/quality/usage-review.md。人間の初見成功率は別途BLOCKED。
