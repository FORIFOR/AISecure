# Contributing

Thanks for looking. Two kinds of contribution are worth far more than a star here.

## 1. A real log format that the connectors mangle

The importer handles CSV and JSON Lines through a mapping profile ([docs/CONNECTORS.md](docs/CONNECTORS.md)). It has only been tested against synthetic logs. If your VPN, IdP, or file server emits something the built-in profiles get wrong, that is the most useful issue you can open — use the "Log format" template and paste a **de-identified** sample line.

## 2. A normal business pattern the false-positive baseline is missing

`aisecure baseline` generates synthetic normal traffic: nightly backups, analyst bursts, a migration day, approved vendor maintenance. Real environments have more — eDiscovery sweeps, antivirus full scans, indexing services, batch ETL. Every pattern the baseline is missing makes the measured false-positive rate ([docs/TUNING.md](docs/TUNING.md)) optimistic. Describe one and it can be added to `aisecure/baseline.py`.

## Ground rules

- **Never paste real logs, credentials, or personal data** into an issue or PR. De-identify first; the whole point of this project is that unknown is never treated as safe.
- The dependency-free suite uses `python3 -m unittest discover -s tests -v` and deliberately skips optional features. For changes to control or managed security, install `.[test]` and run `python tools/run_full_tests.py`; skipped tests fail this required suite. Add regression coverage for behavioral changes.
- Claims about detection must stay honest. "These files were read" is not "this data was exfiltrated," and synthetic measurements are not real-world rates. Wording that blurs that line will be asked to change.

## Development

```bash
python3 -m aisecure serve --demo          # run the UI
python3 -m unittest discover -s tests -v  # dependency-free suite
node tools/dom-check.mjs                   # UI renders in EN and JA without a runtime error
```

## Control document flow

[Acceptance](docs/quality/acceptance.md) is fixed before implementation; record
PASS / FAIL / BLOCKED / NOT_APPLICABLE and preserve failures in the evidence.
[Integration contract](docs/operations/DOCUMENT_CONTRACT.md) defines the experimental
report API. Never convert review/unreadable into no findings to make a test pass.

```sh
python -m pip install '.[test]'
python tools/run_full_tests.py --report /tmp/aisecure-tests.json
python tools/release_gate.py --self-test
node --check aisecure/control/web/app.js
node --test browser/aisecure/protocol.test.js
```

Real control-browser checks use Node + Playwright (verified with 1.62.1 and
Chromium 151). With Playwright available through Node module resolution, run:

```sh
AISECURE_PYTHON=.venv/bin/python node tools/check_control_browser.cjs /tmp/aisecure-control-qa
```

Use `NODE_PATH` for an existing external installation. `AISECURE_TEST_PORT` avoids
port conflicts; `AISECURE_CHROMIUM` optionally selects an installed executable.
The script starts its own local demo, blocks external browser requests, saves real
JSON downloads and screenshots, then checks temporary-state cleanup. Synthetic
composition and CSS 200% checks are not native IME/browser-toolbar zoom certification.
The project has no configured static type checker: syntax checks are not typechecks.

Build a wheel using the project build backend, then run the offline installation
smoke check: `python -m tools.check_control_package /absolute/path/to/package.whl`.
Before a commit, register new source files with git and run
`python tools/update_manifest.py`, then `python tools/update_manifest.py --check`.
The manifest intentionally covers git-tracked paths, not arbitrary local files.

The test extra includes `jsonschema` only for validating the packaged document
report contracts. The runtime/control extras do not depend on a validator.
User-supplied project Skills are in `.agents/skills/`; their provenance and local
installation verification are recorded in `docs/quality/skill-review.md`.
