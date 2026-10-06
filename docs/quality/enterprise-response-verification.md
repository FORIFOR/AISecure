# Response-boundary verification, 2026-10-06

Inspected baseline: `a65ecbc7b8ab1288f2499c395f3d3afc58da5b29`.
Scope: local legacy approval/response path and Okta evidence verification.
No real provider call, customer scan, production deployment, credential change,
or external account action was performed. This is a regression evidence record,
not enterprise certification.

## Reproduced before the patch

- Signed assertions without target/audience authorized different synthetic
  provider targets in copies of the same proposal/store
- Two operator names using one key were accepted; this lacked the intended
  independent-key boundary, without proving anything about human identities
- Matching Okta eventType/target was marked verified with FAILURE, a year-2000
  timestamp, or missing outcome/time
- Accepted but unverified response was reported as failed/not executed
- Snapshot refresh rewrote known verified execution into failed/not executed

## Fixed acceptance boundaries

| ID | Expected | Method | Result |
| --- | --- | --- | --- |
| R1 | Schema2 requires exact target and actual configured responder audience; substitutions dispatch zero times | Signed negative fixtures, CLI and Store tests, reopen checks | PASS |
| R2 | Old schema, malformed fields, signature tampering, duplicate keys and expiry reject | Signed fixtures and persisted shorter-expiry test | PASS |
| R3 | Okta needs target, SUCCESS, bounded time and exact request correlation | Offline event cases plus local HTTP receiver | PASS |
| R4 | Missing header/evidence, read failure and malformed results remain unknown | Failure injection; report and store assertions | PASS |
| R5 | Unknown persists; preapproved siblings, in-flight duplicates and refreshed-snapshot retries cannot dispatch | Store/restart tests and call-count assertions | PASS |
| R6 | Known verified execution survives snapshot refresh; original evidence identity remains | Background-ingest simulation, persisted audit assertion | PASS |
| R7 | Non-verified CLI result is JSON plus exit 2; no resend | CLI mocks with closed-store and one-call assertions | PASS |
| R8 | Output does not repeat provider request ID, synthetic error contents or signing secrets | Metadata/output assertions | PASS for named cases |
| R9 | Declared-dependency no-skip aggregate suite passes | Existing strict runner | BLOCKED locally; optional control dependency unavailable |
| R10 | Actual organization/provider/IdP/restore and independent human review complete | Not run | BLOCKED |

A separate-session automated review reproduced and retested the changed
boundaries. It identified sibling/snapshot retry holes and missing persisted
signature expiry during implementation; those cases were fixed and retested.
This is not a human penetration test or independent third-party certification.

## Commands and observed environment

Linux, Python 3.12.14. Existing installed cryptography 50.0.0 and pypdf 6.10.0 are
outside declared ranges `cryptography>=43,<47` and `pypdf>=6.19,<7`; defusedxml is
absent. No dependency declarations or test expectations were weakened to hide
this. An attempted isolated dependency installation was not completed.

- `PYTHONPATH=tests python -m unittest test_approvals test_response_boundaries test_okta test_responder test_core -v`: 124 tests, no failures/errors/skips, exit 0
- Separate automated boundary review: 11 checks, exit 0; repository approval and response focused checks: 41 tests, exit 0
- `node --test browser/aisecure/protocol.test.js browser/aisecure/enforce.test.js`: 20 tests, no failures/skips, exit 0. These are unit checks, not a browser/device containment run
- `python -m compileall -q aisecure`: exit 0; syntax only, not a typecheck
- `git diff --check`: exit 0
- `python tools/release_gate.py --self-test`: exit 0; confirms empty evidence cannot pass, not actual production verification
- `python tools/run_full_tests.py --report /tmp/aisecure-tests.json`: 372 discovered tests, 0 failures, 0 errors, 1 skipped optional control module; exit 1 as required by the no-skip gate. This is BLOCKED, not a full pass
- `python tools/update_manifest.py --check`: 444 tracked files matched, exit 0

The final aggregate result and manifest result are recorded in the PR against
its exact commit. Any nonzero strict-suite exit or skipped security module
remains a release blocker. GitHub CI must be inspected for that same commit;
prior green runs do not apply to this change.

## Compatibility and residual risks

Signed approvals must be reissued as schema2; stored attestations missing
provider audience or expiry cannot dispatch. Unknown result uses null rather
than false for executed and exits 2 in CLI. Downstream consumers must support
this state without treating null as a confirmed non-execution. No automated
reconciliation override is supplied. Trusted in-process callers and unsigned
local compatibility paths are not SSO/RBAC boundaries. Separate stores/other
clients can still perform actions independently. Actual Okta request/log mapping
and all production deployment gates remain unverified.

## Follow-on: synthetic pilot evidence (same PR)

Baseline commit `447736113e1ca70d91d0086e379c2b612d77e4cd` reproduced two false
passes: `tools/check_control.py` returned success after the entire control suite
was skipped; the release gate accepted null/boolean/numeric/blank environments
and case variants of synthetic labels as real-environment evidence.

The local checker now consumes explicit test counts/status, rejects skipped,
empty, missing and inconsistent evidence, and checks Node TAP counts too. A
separate review caught an unexpected-success regression in the new structured
runner; preserving unittest's `wasSuccessful()` and explicit expected/unexpected
counts closes that case. Subprocesses inherit only a small OS/locale/temp
environment, with no provider credentials or arbitrary Python/Node options.
The runner has fixed synthetic suites, no live/installation option, repository
root provenance, and atomic private reports that cannot replace prior evidence.

Local observation: actual checker now exits 1 with `BLOCKED` and
`local_checks_passed=false` when the control dependency is absent; its separate
Node protocol stage still records 7 passed. New dependency-free regressions
cover malformed evidence, placeholders, CLI statuses, credential-environment
removal, report races/symlinks and unchanged supported success cases. The
configured managed-quality workflow also runs this same safe pilot command and
retains the resulting report. Exact final counts and CI links are in the PR.

This improves the trustworthiness of a synthetic pilot result. It adds no
provider enforcement, no evidence-authenticity assertion, and no production
certification. Real deployment gates remain open.

## Follow-on: document coverage boundaries (same PR)

Baseline `ceccf23033c58b9c506e200c1b6b97adf44df318` was inspected for unsupported,
encrypted, truncated and partial extraction. Existing negative tests already
covered encrypted/blank/image PDFs, unsupported extensions and worker failures.
The uncovered cases were raw Office ZIP bytes omitted by member iteration,
discarded XML comments/PIs, and reachable PDF streams omitted from extraction.
When the scanner incorrectly returned complete coverage, a public-signed bundle
could be authorized; the bundle already correctly denied explicit partial input.

Local reproduction used actual stdlib ZIP behavior and an explicitly substituted
XML parser, plus a mocked PDF reader. It is control-flow evidence, not validation
against the declared parsers. The new ZIP envelope function was separately
exercised with real stdlib ZIP/zlib data: supported stored/deflated packages and
ordinary descriptors remain accepted; omitted envelope cases are rejected.

`tests/control/test_partial_coverage.py` adds generated xlsx/pptx/PDF fixtures,
real-worker assertions, the public metadata report, and signed-bundle capture
transports. It tests comments, extra fields, unreferenced content, concatenation,
truncation, DEFLATE tails, directory payloads, UTF-8/UTF-16 XML, DTDs, PDF metadata
and custom streams, as well as supported-file positives. No customer file or
external provider is used. Declared-parser results must be taken from the final
exact-revision CI record in the PR, not the local substituted-parser checks.
