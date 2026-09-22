# Skill-guided local improvement — 2026-09-19

Scope: existing document preflight task, **0.4.0a3.dev0, unreleased**. Base commit
`26002d840130e52b07f35dd9c9ea8189d8913ee2` plus preserved first-pass changes and this
follow-up. No commit/push/merge/deployment or provider/VPN operation. Existing
first-pass results remain historical under `evidence/2026-09-19/`.

## Skills actually installed and used

User-supplied `oss-quality-kit` **2.0.0-draft** was reviewed and installed with its
local installer (`--tool codex --apply`) into `.agents/skills/`. Its checksums and
validator passed; all 13 installed files match the supplied source bytes.
No AGENTS.md/CLAUDE.md was overwritten. The kit contains no separate LICENSE;
installation is user-authorized local use, not a redistribution-license assertion.
Skills are not packaged in the product wheel. The master prompt was reference
material and did not grant additional publication or sending authority.

Applied in order: `oss-standard-audit`, `outcome-first-ux`, `world-class-ui`
(focused existing-UI design), `contract-first-build`, `world-class-ui` (actual
screen review/refinement). `independent-product-verification` ran in a separate
agent context with task and safe startup information only before source review.
`skill-installer` guided installation; the reviewed kit's offline installer handled
the local source. [Installation identities](evidence/2026-09-19-skill-review/skills-installation.json).

## Audit and adopted boundaries

Product adoption and contract adoption are **not established** by this work.
No independent adopter or beginner success-rate study is claimed. The goal is a
verifiable local task and a consumable experimental report boundary.

References checked 2026-09-19 (public read-only requests, no repository content sent):

- [JSON Schema validation Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation), dated specification: existing vocabulary for types, required fields and constraints. Adopted directly for report schemas; no new schema language or runtime network validation.
- [Gitleaks v8.24.3 README](https://github.com/gitleaks/gitleaks/blob/v8.24.3/README.md) and [CLI source at that tag](https://raw.githubusercontent.com/gitleaks/gitleaks/v8.24.3/cmd/root.go): explicit report output options and exit-code behavior. Adopted the principle of scriptable outcomes, not its file/secret scanning protocol. Static source comparison only; no speed/detection superiority claim or same-task competitor benchmark.

Boundary classification: JSON/HTTP/SHA-256 and Draft 2020-12 are reused; Scanner
remains the shared engine; schema loading and CLI publication are thin wrappers.
AISecure-specific decision/coverage metadata remains explicitly experimental.
No SARIF/MCP/OpenAPI stack or additional runtime service was introduced.

| Priority | Before / evidence level | Change and measured effect | Remaining boundary |
| --- | --- | --- | --- |
| P1 integration | Report fields defined in prose, no machine contract (static review) | Packaged document/bundle schemas; real outputs and earlier fixture validate, unknown schema/unsafe flags fail | Structure validation is not permission to send; independently deployed clients not measured |
| P1 output integrity | Exclusive-create output could remain partial after write failure (static risk) | Temporary 0600 file + fsync + atomic no-clobber publication; short-write/fsync/link failure, concurrent and symlink tests pass | Filesystem hard-link support required; crash can leave private temp; power-loss directory durability not guaranteed |
| P2 task feedback | Independent first-use observer found remote error placement and stale error after source switch (executed FAIL) | Inline feedback, correct field focus/ARIA association, edit clears old errors; result and save adjacent | Native assistive-tech evaluation still pending |

The existing MIT project license, SECURITY/CONTRIBUTING and experimental contract
were reviewed. SECURITY now distinguishes older triage limitations from the
control extension. No new disclosure channel or external adoption claim was made.

## UI direction and before/after

Preserved the light/navy local workbench and native controls. Desktop now shows
source and evidence side by side; narrow screens retain input→inspect→result→save
DOM order. Review/block use a colored rule plus explicit text; neither implies
external safety. No fonts, images, decorative animation or framework were added.
The main action is now visible in the measured 1440×1000 initial viewport.

[Design source](../site/DESIGN.md) records tokens and the focused choice over a
modal wizard or broader dashboard. This was refinement of an existing screen,
not a full new-brand concept exercise. Primary, result, error and narrow images
were actually opened during review; static screenshots are not motion evidence.
The accelerated browser recording documents operations, not real-user
speed or an animation-quality score.

- Before: [independent first-use report](evidence/2026-09-19-skill-review/independent/pass-a-review.md)
- After: [initial desktop](evidence/2026-09-19-skill-review/initial-1440.png), [result](evidence/2026-09-19-skill-review/control-1440.png), [inline error](evidence/2026-09-19-skill-review/error-390.png)
- [Recorded primary flow](evidence/2026-09-19-skill-review/primary-flow.webm), [actual saved JSON](evidence/2026-09-19-skill-review/report-390.json)

## Verification

Environment: macOS 26.6.2 arm64 / Darwin 25.6.0, Python 3.14.6, Node 26.5.0,
Chromium 151.0.7922.34, Playwright 1.62.1, jsonschema 4.26.0. Fresh local servers per
viewport. Control runtime versions and fresh-install packages are recorded below.
JSON Schema validation is a **test-only** dependency; the control/runtime dependency
set is unchanged. Package acquisition used PyPI/cache; no document/repository
payload was uploaded. Browser task traffic was loopback only.

| Acceptance | Status | Measured observation / evidence |
| --- | --- | --- |
| S1 schema/compatibility | PASS | Standard Draft202012Validator validates current SDK/GUI and prior report; wrong schema and unsafe approval reject; both schemas load from installed wheel |
| S2 file safety | PASS | Private complete file; no clobber including dangling symlink/concurrent writers; injected short write, fsync and publish failures leave no final partial output |
| S3 feedback/result | PASS | Initial state says connected, not inspection complete; errors adjacent to check and field-focused; source/input edits clear errors; save immediately follows result |
| S4 web subset | PASS | 360/390/768/1440; keyboard/focus, long Japanese, synthetic composition Enter does not submit, reduced motion, CSS 200% reflow, authentication/network recovery; 30 browser checks |
| S5 installation | PASS | Parent agent compared all 13 files with reviewed kit. Separate product reviewer did not repeat installer audit |
| S6 independent process | PASS | Task-only AI exploration before code/README; first-use defects reproduced, then separate post-change technical/visual validation |
| Required Python suite | PASS | 467 tests, 0 failures, 0 errors, 0 skips |
| Protocol / release gate | PASS | Seven Node protocol tests; empty production evidence cannot pass release gate |
| Build / actual wheel | PASS | Wheel built; installed entry point and bundled schemas exercised outside repository |
| Clean installation | PASS | Fresh venv with no system-site-packages, wheel[control] dependency acquisition, real CLI inspection (expected review exit 3), control --help and schema loading; 3.82s observed including cached package acquisition, not a network-cold benchmark |
| Dependency-free compatibility | PASS | 334 tests, 47 intentional optional skips, 0 failures/errors; distinct from required no-skip suite |
| Manifest | PASS | All 390 tracked/intent-to-add files match SHA256SUMS.txt, including installed Skills and evidence |
| Syntax | PASS | Python compilation and JS syntax checks |
| Static typecheck | NOT_APPLICABLE | No configured typed-language/typechecker pipeline; compilation is not called typechecking |
| GitHub CI execution | BLOCKED | Control browser runner added to required workflow; no push was authorized, so this revision has not run on GitHub |
| Native IME/zoom/assistive tech | BLOCKED | Synthetic composition/CSS zoom and ARIA inspection are not native Japanese input, toolbar zoom or screen-reader testing |
| Windows/native enforcement/live provider/VPN | BLOCKED | No corresponding platform, installed host/appliance or external-operation authorization |
| Human/competitor comparison | BLOCKED | No real-user sample or matched same-task competitor run; no superiority or human-success-rate assertion |

Commands, exit codes and logs: [commands.json](evidence/2026-09-19-skill-review/commands.json).
Exact source identities: [source.json](evidence/2026-09-19-skill-review/source.json).
[Full tests](evidence/2026-09-19-skill-review/full-tests.json),
[browser results](evidence/2026-09-19-skill-review/browser.json),
[clean install command/package/output record](evidence/2026-09-19-skill-review/cold-install.json)
and [original probe source](evidence/2026-09-19-skill-review/cold-install-probe.py).
[Independent Pass B/C](evidence/2026-09-19-skill-review/independent/pass-bc-review.md)
contains its own commands, exit codes, images and probes. This is a separate AI
context, not an external human security audit.

## Iteration and retained failures

1. Skill audit/contract + initial UI revision: independent first-use P2 failures
   retained; schema and atomic-save regression checks added without weakening any
   existing expected behavior.
2. Real-screen/testing refinement: compacted excessive input height; checked
   result/error images; corrected browser harness isolation. Four viewports had
   shared one rate-limited server (test failed on the third); a harness shutdown
   timer then incorrectly targeted a later process. Both failed results are kept
   in browser-round1-failure.json and browser-harness-cleanup-failure.json. Fixed
   the harness, not the server rate limit or acceptance. Finally separated live
   feedback from the busy result region and associated errors with their fields.

Remaining BLOCKED items remain open. Reports are metadata, not anonymized: hashes
can identify files. No blanket DLP, certified protection or production readiness is
claimed. Changes are local and reviewable; previous user changes were retained.
