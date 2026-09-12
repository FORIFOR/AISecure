# Contributing

Thanks for looking. Two kinds of contribution are worth far more than a star here.

## 1. A real log format that the connectors mangle

The importer handles CSV and JSON Lines through a mapping profile ([docs/CONNECTORS.md](docs/CONNECTORS.md)). It has only been tested against synthetic logs. If your VPN, IdP, or file server emits something the built-in profiles get wrong, that is the most useful issue you can open — use the "Log format" template and paste a **de-identified** sample line.

## 2. A normal business pattern the false-positive baseline is missing

`aisecure baseline` generates synthetic normal traffic: nightly backups, analyst bursts, a migration day, approved vendor maintenance. Real environments have more — eDiscovery sweeps, antivirus full scans, indexing services, batch ETL. Every pattern the baseline is missing makes the measured false-positive rate ([docs/TUNING.md](docs/TUNING.md)) optimistic. Describe one and it can be added to `aisecure/baseline.py`.

## Ground rules

- **Never paste real logs, credentials, or personal data** into an issue or PR. De-identify first; the whole point of this project is that unknown is never treated as safe.
- Tests are standard-library only: `python3 -m unittest discover -s tests -v`. Keep them green; add one for any behaviour change.
- Claims about detection must stay honest. "These files were read" is not "this data was exfiltrated," and synthetic measurements are not real-world rates. Wording that blurs that line will be asked to change.

## Development

```bash
python3 -m aisecure serve --demo          # run the UI
python3 -m unittest discover -s tests -v  # 177 tests
node tools/dom-check.mjs                   # UI renders in EN and JA without a runtime error
```
