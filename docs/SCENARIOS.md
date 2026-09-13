# Scenario catalogue — what the rules do, and do not, catch

A map of security scenarios against the current detection rules, so a reader can see the coverage boundary directly — including the attacks it does **not** detect. Behaviour is **by rule design** and, where noted, confirmed on the bundled **synthetic** baseline. It is not a claim about real-world detection.

**The rules**

| Rule | Fires on | Role |
|---|---|---|
| AS-001 | An exposed, unpatched device in the ledger | Hygiene (input-driven) |
| AS-002 | A privileged login that fails its conditions (unapproved change **or** unmanaged device) | Signal |
| AS-003 | ≥100 distinct file reads in a 300 s window, same user/session/target | Signal |
| **AS-004** | Exposed unpatched gateway **+** failing privileged login **+** bulk access, same user & session | **Correlated case (P1)** |
| AS-005 | Missing or stale asset data | Coverage (input-driven) |

**Outcomes:** 🎯 raised as a P1 correlated case · 🔸 surfaced as a lower-priority signal · ✅ correctly quiet (no case) · ⛔ out of scope (not detected).

## Suspicious / attack-shaped scenarios

| # | Scenario | Rule(s) | Outcome |
|---|---|---|---|
| 1 | Exposed VPN/gateway vuln → privileged login → bulk sensitive read (same session) | AS-004 (+001/002/003) | 🎯 the flagship case |
| 2 | Maintenance/service-account misuse after a failing privileged login | AS-002 (+004 if exposure present) | 🎯/🔸 |
| 3 | Single bulk read burst of sensitive files | AS-003 | 🔸 signal (case only if correlated) |
| 4 | Admin login from an unmanaged device / without an approved change | AS-002 | 🔸 signal |
| 5 | Internet-exposed device left unpatched (KEV/CVSS in input) | AS-001 | 🔸 hygiene, input-driven |
| 6 | Bulk read from a stale/unknown asset (ledger gap hides exposure) | AS-005 (+003) | 🔸 coverage gap surfaced, not hidden |

## Benign scenarios — the false positives the case layer must avoid

These all generate volume that a naive "100 files in 5 minutes" rule flags. AS-003 may fire on them; **AS-004 stays quiet**, because none carry the exposure + failing-privileged-login correlation. Present in the synthetic baseline (`aisecure baseline`).

| # | Scenario | AS-003 | AS-004 |
|---|---|---|---|
| 7 | Nightly backup job | may fire 🔸 | ✅ quiet |
| 8 | Search-indexing service | may fire 🔸 | ✅ quiet |
| 9 | Weekly antivirus sweep | may fire 🔸 | ✅ quiet |
| 10 | eDiscovery / legal-hold pull | may fire 🔸 | ✅ quiet |
| 11 | Batch ETL job | may fire 🔸 | ✅ quiet |
| 12 | Legitimate analyst burst | may fire 🔸 | ✅ quiet |
| 13 | Migration day (bulk moves) | may fire 🔸 | ✅ quiet |
| 14 | Approved vendor maintenance on a personal laptop | — | ✅ quiet (change is approved) |
| 15 | Privileged login, managed device, approved change | — | ✅ quiet (AS-002 quiet) |
| 16 | Exposed device that is patched | — | ✅ quiet (AS-001 quiet) |
| 17 | Normal low-volume file access | — | ✅ quiet |
| 18 | Missing/stale asset fields | AS-005 🔸 | ✅ not treated as safe |

This is the whole point: at the **case** layer, 7–18 stay quiet while scenario 1 is raised. The measured asymmetry is in [METRICS.md](METRICS.md) (AS-004: precision 1.00, 0 FP/day on ~75 synthetic days; AS-003 alone: 355 false alerts).

## Out of scope — attacks the current rules do NOT detect

Stated plainly, because a security tool that hides its blind spots cannot be trusted.

| # | Scenario | Why not detected |
|---|---|---|
| 19 | Slow exfiltration spread over days | AS-003 needs ≥100 files in a 300 s window; slow reads never trip it |
| 20 | Distributed exfiltration across many sessions/servers | Bulk detection is per user/session/target; cross-session spread is not aggregated |
| 21 | Lateral movement (host → host) | No host-to-host graph is modelled |
| 22 | Impossible travel / geo-velocity | No geo/IP is in the input schema |
| 23 | Credential stuffing / brute force | No failed-login-rate rule; AS-002 is about a privileged login's conditions, not volume |
| 24 | Privilege escalation as such | Not modelled as a distinct rule |
| 25 | Exfiltration with no file-read logs | Nothing to correlate; "read" ≠ "left the network" is kept explicit |

These are candidates for future rules, not silent gaps. The current thesis is deliberately narrow: make the exposure→privilege→bulk-read shape legible with near-zero false positives, and say clearly what it does not cover.

## Reproduce

```bash
# The flagship incident + a clean baseline
python3 -m aisecure baseline --name incident --seed 7 --days 19 --users 40 --attack --out incident.json
python3 -m aisecure baseline --name normal   --seed 11 --days 19 --users 40           --out normal.json
python3 -m aisecure evaluate incident.json normal.json --format json --out eval.json
```

`eval.json` lists per-rule `alerts`/`tp`/`fp` for AS-002/003/004. The benign scenarios 7–13 are the synthetic normal traffic; scenarios 19–25 are documented gaps, not generated (there is nothing to detect). See [METRICS.md](METRICS.md) and [TUNING.md](TUNING.md).
