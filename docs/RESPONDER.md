# Signed responder protocol

AISecure separates analysis from authority. The `watch` command reads exported
CSV/JSONL logs and updates the evidence store. The `execute` command is the
only path that can send a real response request, and it sends that request to a
separately operated responder. The responder owns the VPN, IdP, firewall, or
SOAR credentials.

This boundary is intentional: a process that analyses untrusted logs should
not also hold credentials that can disable accounts or block traffic.

## Request

The request is a JSON document containing only metadata:

```json
{
  "schema_version": 1,
  "request_id": "random-id",
  "proposal_id": "P-...",
  "snapshot_id": "S-...",
  "finding_id": "F-...",
  "action": "revoke_session",
  "target": "provider-session-42",
  "evidence_ids": ["asset:...", "evt-..."],
  "requested_at": 1789416380
}
```

Raw logs, file paths, approval reasons, provider tokens, and secret values are
not sent. The `target` is the one exception: the approving operator explicitly
supplies the provider-side target after checking it in the provider console.
Use an opaque provider ID rather than an email address where possible. AISecure
never infers this target from its pseudonymized finding. The request body is
canonical JSON. Headers are:

- `X-AISecure-Timestamp`: the Unix timestamp in the body
- `X-AISecure-Request`: the request ID
- `X-AISecure-Idempotency-Key`: the proposal ID
- `X-AISecure-Signature`: `sha256=` followed by HMAC-SHA256 of
  `timestamp + "." + body` using the shared secret

The responder must verify the signature in constant time, reject timestamps
outside its replay window, reject a reused idempotency key unless it returns
the same final result, and enforce its own action and target allowlists.

## Response

The responder must perform the provider-specific operation and then verify the
result before returning one of these JSON responses:

```json
{"status": "verified", "provider": "example-idp", "request_id": "random-id", "proposal_id": "P-..."}
```

or:

```json
{"status": "failed", "provider": "example-idp", "request_id": "random-id", "proposal_id": "P-..."}
```

The response must echo the request and proposal IDs. An HTTP success without
`status: verified` and those matching IDs is not treated as containment. A
timeout, malformed response, provider error, or incomplete verification leaves
the proposal `delivery_unknown` with `executed: null`; this is not proof that
the action did not happen. Only an explicit responder result of `failed` with
`executed: false` is a confirmed failure in the local adapter contract. The
webhook's `status: failed` therefore must mean positive non-execution, not a
timeout or missing post-action evidence.

The store reserves execution before calling the responder. An executing/unknown
action blocks sibling proposals for the same finding across snapshots, and
dispatch for the same action/provider target/audience. Unsigned audiences are
handled conservatively. Restart does not clear the reservation. There is no
automatic resend or implemented reconciliation override: deployments must close
that operator workflow before using real response. Never edit the database to
make an unknown action retryable. This is not a general distributed idempotency
guarantee across independent stores or other tools.

A background snapshot refresh does not rewrite a verified action as failed or
not executed. The result retains its original snapshot ID in the audit and
reports `snapshot_current: false`. The CLI prints non-verified results but exits
2, so a successful process exit cannot silently represent unknown delivery.

## Operator requirements

The CLI requires two distinct approval labels and two exact confirmation
strings. This is a local control boundary, not proof of identity. For a real
deployment, [schema2 signed approvals](APPROVALS.md) bind the actual provider
target and responder audience. The responder must bind both approvals to authenticated users in
SSO/RBAC, apply least-privilege provider credentials, provide emergency stop
and recovery procedures, and independently retain audit records.

The endpoint must use HTTPS. Plain HTTP is accepted only for a loopback test
responder. The signing secret should come from a secret manager and be at
least 32 bytes; it must never be committed to the repository or printed in
logs. Pass `--emergency-stop-file ./STOP` to the CLI when an operator-managed
kill switch is required. Presence of the file, or an error while checking it,
fails closed before the request is sent.
