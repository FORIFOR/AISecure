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
timeout, malformed response, provider error, or verification failure marks the
proposal as failed and never claims that the environment changed.

## Operator requirements

The CLI requires two distinct approval labels and two exact confirmation
strings. This is a local control boundary, not proof of identity. For a real
deployment, the responder must bind both approvals to authenticated users in
SSO/RBAC, apply least-privilege provider credentials, provide emergency stop
and recovery procedures, and independently retain audit records.

The endpoint must use HTTPS. Plain HTTP is accepted only for a loopback test
responder. The signing secret should come from a secret manager and be at
least 32 bytes; it must never be committed to the repository or printed in
logs. Pass `--emergency-stop-file ./STOP` to the CLI when an operator-managed
kill switch is required. Presence of the file, or an error while checking it,
fails closed before the request is sent.
