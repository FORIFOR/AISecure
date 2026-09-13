# Detection metrics (synthetic data)

Precision, recall, F1 and false positives per day for each detection rule, measured with the bundled evaluator on **labeled synthetic scenarios**. These are **not real-world rates**. They are a rehearsal you re-run on your own logs before you trust a threshold. The most important open milestone is exactly this measurement on one organisation's real, anonymised logs — see [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md).

## What was measured

- **Corpus:** 4 labeled scenarios — 1 with a planted incident, 3 clean (one of them with an unpatched gateway but no incident).
- **Scale:** ~75 scenario-days, 332,268 synthetic events.
- **Rule version:** `2026-09-12.2`, default thresholds (`distinct_file_threshold=100`, `window_seconds=300`, `login_lookback_seconds=1800`, `sensitive_file_minimum=1`, `cvss_priority_threshold=7.0`).

## Results

| Rule | What it fires on | Precision | Recall | F1 | FP/day |
|---|---|--:|--:|--:|--:|
| **AS-002** | Privileged login that fails its conditions | 0.027 | 1.00 | 0.053 | 0.48 |
| **AS-003** | Bulk file access on its own | 0.003 | 1.00 | 0.006 | 4.73 |
| **AS-004** | Exposure **+** privileged login **+** bulk access (correlation) | **1.000** | **1.00** | **1.000** | **0.00** |

- **Precision** = incidents correctly flagged ÷ (that + false alerts across all scenarios).
- **Recall** = incidents detected ÷ incidents present.
- **FP/day** = false alerts ÷ scenario-days.

The single-signal rules (AS-002, AS-003) detect the incident but bury it: AS-003 raised **356 alerts, 355 of them false** across the corpus. The correlation rule AS-004 raised **one alert, zero false**, at the same recall. That asymmetry — same detection, three orders of magnitude fewer false positives — is the product thesis, now as numbers.

## Honest limitations

- **Synthetic.** The traffic is generated (nightly backups, analyst bursts, a migration day, indexing, antivirus sweeps, eDiscovery, batch ETL, approved vendor maintenance). It is realistic in *shape*, but it is not your environment. Real logs will move these numbers.
- **Single incident.** `Recall = 1.00` rests on **one** planted incident per attack scenario, so it means "the incident was detected," not a statistically estimated recall. Do not read it as a guarantee.
- **Seeds matter.** Counts vary a little by RNG seed; the *asymmetry* between correlated and single-signal rules is the stable finding, not any single count.
- **In scope only.** AS-004 targets the exposure→privilege→bulk-read shape. Slow, distributed or multi-stage exfiltration, lateral movement and impossible-travel are **out of scope** for the current rules — see [SCENARIOS.md](SCENARIOS.md).

## Reproduce it

```bash
# 1 incident + 3 clean baselines (~19 days each, 40 users)
python3 -m aisecure baseline --name incident  --seed 7  --days 19 --users 40 --attack            --out incident.json
python3 -m aisecure baseline --name normal-a  --seed 11 --days 19 --users 40                     --out normal-a.json
python3 -m aisecure baseline --name normal-b  --seed 23 --days 19 --users 40                     --out normal-b.json
python3 -m aisecure baseline --name normal-gw --seed 31 --days 19 --users 40 --unpatched-gateway --out normal-gw.json

# Per-rule TP/FP, plus an optional threshold sweep
python3 -m aisecure evaluate incident.json normal-a.json normal-b.json normal-gw.json \
  --format json --out eval.json
python3 -m aisecure evaluate incident.json normal-a.json normal-b.json normal-gw.json \
  --sweep --out sweep.md
```

`eval.json` carries the per-rule `alerts`/`tp`/`fp` and the recorded `rule_config.digest`, so a changed threshold is visible. The sweep shows that every threshold configuration which drives AS-003's false positives to zero also stops it detecting the incident — the reason correlation, not a higher threshold, is the answer. Method and raw sweep: [TUNING.md](TUNING.md).
