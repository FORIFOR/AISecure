# Enterprise readiness: bounded controls, explicit gaps

Assessment date: 2026-10-06. Inspected baseline:
`a65ecbc7b8ab1288f2499c395f3d3afc58da5b29`. This assessment accompanies the
response-boundary hardening change; it is not a certification or a production
approval. Pin and revalidate the final reviewed revision before evaluation.

## Decision

**NO-GO for unattended enterprise response or a whole-enterprise protection claim.**
A bounded, owner-authorized, synthetic-data evaluation is the next supported
step. Deployment to a real organization needs its administrator's authorization,
data-handling agreement, explicitly selected environment, and the gates below.
No customer system was scanned, no real IdP operation was performed, and no
service was deployed for this assessment.

The actual product is a local document preflight tool, fixed-destination managed
AI gateway, supplied-log correlation tool, and narrowly approved response path.
It is not a website vulnerability scanner, EDR, backup platform, IAM service,
network firewall, or multi-tenant SaaS. Use:

> Local AI data preflight, controlled AI transmission, and evidence-based incident triage.

Do not claim “all attacks blocked,” “no leak possible,” or “enterprise certified.”
A matching heuristic is an observation, and no finding is only a result within
submitted inputs and supported extraction. The existing 60-case detection
measurement remains historical; this patch does not change or remeasure it.
Secret-pattern PR #32 is separate and was not merged into this change.

## Current mechanisms and evidence boundaries

- Submitted xlsx/pptx/pdf inspection records partial/unreadable coverage, findings,
  and no-OCR/no-antivirus limitations. Local subprocesses are not network
  sandboxes; the live bundle path requires the separately prepared isolated worker
- Managed AI delivery binds classification to exact outgoing bytes, model,
  destination and policy. Its fixed HTTPS transport already rejects non-public
  DNS answers, pins a checked address, and does not follow redirects. It does not
  control other clients, accounts or device traffic
- This patch binds signed response approvals to the actual provider target,
  responder audience and shorter signature expiry; the old schema requires
  reissuance. Distinct registered keys do not independently prove two human
  identities or the security of the external identity issuer
- Okta verification now requires a current successful target event correlated to
  the accepted request ID. It observes an IdP event, not downstream application
  containment. Missing/failed evidence stays unknown. OAuth revocation is still
  explicitly disabled in this narrow operation
- Unknown dispatch reservations survive restart and prevent same-finding or
  same-action/target/audience sibling retries. A snapshot refresh cannot erase a
  known execution. This is a single-store control, not cross-system idempotency
- The service is local/single-owner. Organization SSO, multi-tenant authorization,
  identity lifecycle, and production segregation are not delivered by this patch

See [verification](../quality/enterprise-response-verification.md),
[approval migration](../APPROVALS.md), [Okta scope](../OKTA.md), and
[existing threat model](THREAT_MODEL.md).

## Recent incidents mapped to this product

The reports below describe different incidents and research findings. Inclusion
is not a claim that AISecure detects or prevents them. “Integration required”
means relevant telemetry and environment-specific policy are missing, not a pass.

| Pattern and primary evidence | AISecure boundary | Required external control / remaining gap |
| --- | --- | --- |
| Device-code/token phishing, EvilTokens (September 2026): [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/) | Supplied sign-in evidence may support triage; no direct phishing prevention | Identity policy, phishing-resistant authentication where applicable, sign-in/email telemetry, token/session investigation |
| Voice phishing and malicious connected-app consent, UNC6040 (2025): [Google](https://cloud.google.com/blog/topics/threat-intelligence/voice-phishing-data-extortion) | Local preflight does not control SaaS consent elsewhere | Approved-app controls, scope review, independent helpdesk verification |
| Integration OAuth token theft, Salesloft Drift (August 2025): [Google](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift) | Current IdP session operation does not revoke all integration tokens | Integration inventory, scoped grants, revocation and downstream secret rotation |
| Exposed AI-service database, DeepSeek (January 2025): [Wiz primary research](https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak) | Preflight can only reduce sensitive submission through its own path | Database authentication, least privilege, cloud exposure review; disclosure confirms exposure, not criminal theft |
| Malicious dependency/install scripts, Shai-Hulud (September 2025): [GitHub](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/) | Document classification is not a dependency-supply-chain control | Reviewed dependencies/provenance, isolated builds, minimal build secrets, publishing controls |
| Internet-facing SharePoint exploitation and ransomware (July 2025): [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/) | Supplied inventory/advisories are triage inputs; current FortiOS connector does not assess SharePoint | Patching, key rotation, endpoint investigation; no clean-host inference from a clean sample |
| Cloud privilege abuse and ransomware, Storm-0501 (August 2025): [Microsoft](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/) | No cloud control-plane enforcement or backup protection | Privileged-access isolation, cloud audit monitoring, independently protected restore capability |
| MCP cross-customer authorization flaw (June 2025; later filing): [Asana filing, p.55](https://asana.gcs-web.com/static-files/1f676ceb-c8a7-4682-ae78-ff972213ae9f) | Local single-owner design is not proof of future tenant isolation | Server-side ownership checks for every object/job/export/cache before any shared-service rollout; confirmed flaw, not confirmed mass theft |
| Bribed support-agent data access (May 2025): [Coinbase](https://www.coinbase.com/blog/protecting-our-customers-standing-up-to-extortionists) | Gateway controls only one possible disclosure channel | Least privilege, masking, access analytics, contractor controls |
| Prompt injection/exfiltration research (March 2026): [OpenAI](https://openai.com/index/designing-agents-to-resist-prompt-injection/) | Fixed destinations and deterministic permissions reduce impact; text patterns cannot certify prompt safety | Keep external content as data, constrain tools/egress, verify every action; research tests are not enterprise breach-rate statistics |

## Adoption gates and next actions

1. **Reproducible release checks:** install the declared test extra in an approved
   isolated environment, run the no-skip suite, manifest checks and existing CI on
   the exact candidate commit. Local availability of incompatible dependency
   versions is not a release pass
2. **Read-only synthetic pilot:** one owner, one environment, no external delivery,
   no provider credentials. Inspect representative supported/unsupported files
   and logs. Track unknown/partial rates, false positives, missed labelled cases,
   operator review time, and evidence leakage. Agree acceptance thresholds before
   evaluation; never optimize them afterward to call it a pass
3. **Identity and approval:** validate external SSO/RBAC, two independently
   authenticated approvers, policy ownership, schema2 issuance, key rotation,
   revocation and signed-expiry behavior. The unsigned local compatibility path
   is not enterprise authorization
4. **Real adapter evidence:** in a separately authorized sandbox, verify actual
   Okta header/log correlation, delayed logs, rate limits, failure states and
   engine differences. Verify FortiOS/egress/restore behavior separately. A passing
   mock is not device or provider evidence
5. **Unknown-outcome reconciliation:** implement and review an authenticated,
   auditable reconciliation workflow before real response. The current patch
   deliberately leaves unresolved actions blocked; no database-edit workaround
6. **Operations and independent assessment:** audit retention/backup/restore,
   secret handling, dependency supply chain, incident response, emergency stop,
   normal-business evaluation and external security review. Real-data precision,
   recall, device containment and SLA remain unmeasured

The [production evidence manifest](../quality/enterprise-response-gates.json)
contains no fabricated live evidence. Run:

```sh
python tools/release_gate.py docs/quality/enterprise-response-gates.json
```

Expected result: exit 2 with missing gates. Completing the manifest itself is
still not proof of authentic evidence or security certification. Do not grant
new permissions, send real documents, disable accounts, merge or deploy solely
because this document exists.
