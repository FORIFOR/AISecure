# Local verification — 2026-09-19 (first pass)

For the later Skill-guided revision, see [skill-review.md](skill-review.md).
The measurements below describe the earlier working tree.

Target: base `26002d840130e52b07f35dd9c9ea8189d8913ee2` + uncommitted
0.4.0a3.dev0 working tree. No commit, push, merge, publication or deployment.
Exact tested source hashes and environment: [source.json](evidence/2026-09-19/source.json).
Final repository file integrity is recorded by root `SHA256SUMS.txt` (excluding
itself); this is an integrity manifest, not a security certification.

Environment: macOS 26.6.2 arm64 / Darwin 25.6.0, Python 3.14.6,
pypdf 6.19.0, cryptography 46.0.7, defusedxml 0.7.1, uvicorn 0.53.0,
httpx 0.28.1, Node 26.5.0, Playwright 1.62.1, Chromium 151.0.7922.34.
The dependency-free suite used a separate Homebrew Python 3.14.6.
Build used the existing bundled Python with setuptools 84.0.0, without downloads.

## Acceptance results

| Criterion | Status | Observation / evidence |
| --- | --- | --- |
| A1 first success | PASS | Default editable confidential xlsx → real scanner → review in one check activation; second activation saves JSON. No keys/provider setup. Browser script is an automated proxy, not a beginner study. |
| A2 meaningful outcome | PASS | DOC-CLASS review, DOC-SECRET block, no-send state; rule explanations; exact downloaded report/request ID matches persisted audit metadata. |
| A3 failure recovery | PASS | Empty question retains sample; corrected question works; malformed PDF unreadable; network failure then explicit recheck succeeds. |
| A4 state and duplicate effects | PASS | Edits invalidate result; inputs disabled while running; independent lost-send probe makes only one send attempt and locks further sends; existing durable replay tests pass. |
| A5 authentication/privacy | PASS | Hash stripped, local/session storage empty, reload prompts token recovery; same-page reconnect preserves input. Raw sample, question and token absent from report/audit. Full reload does not preserve drafts. |
| A6 artifact/CLI | PASS | JSON parse + SHA-256 + audit identity checked, file remains after server shutdown; installed wheel CLI returns review exit 3 with JSON; overwrite denied. |
| A7 shared contract | PASS | GUI/CLI/SDK use Scanner; HTTP and SDK metadata match; boundaries/errors/permissions/versioning documented. CLI no-findings does not authorize sending. |
| A8 responsive/accessibility subset | PASS | 390px/1440px, keyboard activation/focus, long Japanese, synthetic composition events, reduced motion and CSS 200% reflow; no horizontal overflow or JS errors. |
| A8 native validation | BLOCKED | Native Japanese IME composition and browser toolbar 200% zoom were not operated; synthetic DOM events and CSS zoom are explicitly insufficient. Screen-reader/human usability testing not performed. |
| A9 required test suite | PASS | 461 tests, 0 failures, 0 errors, 0 skips. Release gate rejects empty production evidence. Seven browser protocol tests pass. |
| A9 build/syntax | PASS | Python compile, JS syntax, 0.4.0a3.dev0 wheel, installed console entry point outside repository. |
| A9 integrity | PASS | SHA256SUMS.txt matches all 286 tracked/intent-to-add files; new source, tests and evidence included. |
| A9 static typecheck | NOT_APPLICABLE | Existing Python/plain-JS project has no configured typechecker/TypeScript build; syntax checks are not called typechecks. |
| A9 dependency-free compatibility | PASS | 334 tests, 0 failures/errors, 47 intentional optional-feature skips; kept distinct from required no-skip suite. |
| A10 network/lifetime | PASS | Browser observed 0 external requests (external requests blocked by harness), 0 JS errors; demo directory removed after SIGINT, downloaded reports remain. This is not an OS egress isolation proof. |
| Native extension / Windows | BLOCKED | No OS/native host installation or Windows environment; web testing is not substituted. |
| Live provider/VPN/isolation | BLOCKED | No external send/device/deployment authorization, configured appliances or Podman isolation image; production_ready remains false. |
| Competitor / real beginners | BLOCKED | No authorized comparative product environment or human participants. No comparative superiority or human success-rate claim. |
| Cancel external execution | NOT_APPLICABLE | No cancellation API was introduced; preflight has no external side effect. Lost send responses remain unknown and are not automatically retried. |

## Evidence and commands

[commands.json](evidence/2026-09-19/commands.json) records actual argv, exit codes
and log locations. Every final automated command returned 0. Main commands:

```sh
.venv/bin/python tools/run_full_tests.py --report docs/quality/evidence/2026-09-19/full-tests.json
.venv/bin/python tools/release_gate.py --self-test
node --test browser/aisecure/protocol.test.js
.venv/bin/python -m compileall -q aisecure/control examples/control
node --check aisecure/control/web/app.js
NODE_PATH=/Users/shuhei/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules node tools/check_control_browser.cjs docs/quality/evidence/2026-09-19
/Users/shuhei/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3 -c "from setuptools.build_meta import build_wheel; print(build_wheel('/tmp/aisecure-quality-wheels'))"
.venv/bin/python -m tools.check_control_package /tmp/aisecure-quality-wheels/ai_secure_local_prototype-0.4.0a3.dev0-py3-none-any.whl
/opt/homebrew/bin/python3 -m unittest discover -s tests -q
```

- [Full test results](evidence/2026-09-19/full-tests.json), [full log](evidence/2026-09-19/full-tests.log)
- [Browser observations](evidence/2026-09-19/browser.json), [actual downloaded JSON](evidence/2026-09-19/report-390.json)
- [Mobile screenshot](evidence/2026-09-19/control-390.png), [desktop](evidence/2026-09-19/control-1440.png), [CSS 200%](evidence/2026-09-19/control-390-css-200.png)
- [Independent review](evidence/2026-09-19/independent-review.md): separate agent context, own real-server probes; not third-party security certification.

Only synthetic data is stored in these artifacts. Tokens/server startup URLs were
not recorded. Historical CONTROL_VALIDATION.json still describes the released
0.4.0a2, not new CI execution: CI has not run on these local modifications.

## Improvement rounds and failures retained

1. Audit/acceptance and first implementation: identified missing sample/artifact,
   stale result/input races, reload lockout, hidden destination, and independently
   reproduced split-run preview disclosure. Added regression tests and withheld
   entire secret/PII-bearing text rather than claiming complete redaction.
2. Browser/contract validation: fixed an initial JS missing parenthesis (syntax
   exit 1) before browser execution. Initial
   `.venv/bin/python -m pip wheel . --no-deps --no-build-isolation -w /tmp/aisecure-quality-wheels`
   exited 2 because setuptools.build_meta was absent. Used preinstalled bundled
   build backend (exit 0), then installed and exercised the wheel offline.
   Clarified repeated scanner match counts, corrected request-ID contract to
   32 lowercase hexadecimal characters, marked version 0.4.0a3.dev0 as unreleased.
   Independent post-change browser and targeted unknown-send/metadata probes passed.

No expected test results were relaxed, no production gates were cleared, and no
real-user evaluation was replaced with an AI score. Remaining BLOCKED conditions
are acceptance gaps, not reasons to label the product production-ready.
