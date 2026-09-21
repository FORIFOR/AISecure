# Document preflight integration contract

Target: 0.4.0a3.dev0 (unreleased), based on 0.4.0a2, with the local improvements described in
[verification](../quality/verification.md). **Experimental** API: pin an exact
reviewed commit or wheel hash. This unreleased working tree is not a new published
package. Python >=3.11; install `.[control]`. Linux/macOS worker resource limits
vary; Windows isolation and native browser extensions are not certified.

## One engine, three callers

`documents.Scanner` owns bounded worker execution. `Inspection.report()` owns
scanner metadata. `bundles.BundleGateway` adds question policy, administrator
classification, audit and fixed-destination delivery. `service.App` authenticates
loopback HTTP and delegates; the browser displays results and downloads metadata.
`inspection.inspect_document` and `inspect_file` wrap the same scanner for local
SDK/CLI use without storage or delivery. `DemoTransport` is a simulation;
`OpenAITransport` is the external adapter. No UI-side verdict grants permission.

## Python / CLI

```python
from aisecure.control.inspection import inspect_document
from aisecure.control.common import ControlError

# Caller owns bounded file reads; see examples/control/inspect_document.py.
report = inspect_document(data, "xlsx")  # bytes, 1..16MiB
if report["verdict"] != "no_findings":
    pass  # request review or stop; never treat this as delivery approval
```

```sh
python -m aisecure.control.inspect_file sample.xlsx --output report.json
# Installed entry point: aisecure-inspect sample.xlsx --output report.json
# JSON stdout is available when --output is omitted.
python -m examples.control.inspect_document sample.xlsx
```

CLI exit codes: `0` completed with no findings; `3` completed requiring review;
`4` completed with a block; `2` invalid input, read/write error or existing output.
Codes 3/4 still produce JSON. Existing files and symlink destinations are never overwritten. A complete report
is first written and fsynced in a private temporary file, then published through
a same-filesystem no-clobber hard link. POSIX permissions are 0600. Unsupported
filesystems return exit 2 without an unsafe fallback. A process crash can leave
a private `.aisecure-report-*` temporary file; directory-entry durability across
power loss is not guaranteed. Output is plaintext: use a private directory.
No retries, network delivery, raw filenames, extracted text or credentials are
included in the report. The fingerprint can correlate files: it is metadata,
not anonymization. SDK raises `ControlError` (a ValueError subclass) for invalid
bytes/format/size; OS/runtime exceptions outside scanner execution are not hidden.
Parser failures/timeouts return `unreadable` and a non-success verdict.

`report_schema = aisecure.document-report.v1`: `input_sha256` (hex SHA-256 of exact
input bytes), `format`, `coverage`, `verdict`, `findings` (rule, level, count,
locations), `units`, `bytes_scanned`, `scanner`, `ocr_performed`,
`malware_scan_performed`, `network_isolation_verified`, `release_authorized`.
Machine-readable producer schemas (JSON Schema Draft 2020-12) ship in the wheel:
`from aisecure.control.inspection import report_schema`; call `report_schema()`
for SDK/CLI or `report_schema("bundle")` for HTTP/browser checks. They are loaded
locally with no validator dependency or network request. A standard validator
(e.g. jsonschema in the test extra) can validate them. These describe inspection
reports, not `/api/send` responses. Document report fields are closed; bundle
metadata permits additive fields but rejects raw question/text/token fields.
Pin/review schema changes alongside scanner upgrades. Previous working-tree report
fixtures remain contract-tested.

The last field is always false for standalone inspection. Verdict is
`no_findings | review | block`; coverage is
`supported_text_complete | partial | unreadable`. Supported text complete never
means complete semantic, image or malware coverage. Unknown future verdicts,
schemas or coverage values must fail closed; consumers may ignore additive fields.
Do not depend on counts staying constant across scanner upgrades.

## Local HTTP / browser

Only `127.0.0.1:PORT`; no proxy, public server or multi-tenant contract. Use
`Authorization: Bearer TOKEN`; the URL fragment is consumed in memory then removed.
Do not use query tokens. Reload requires re-authentication; no token or draft is
persisted in browser storage. Same-page failed operations retain input; full page
reload discards drafts and reports. The UI shows a token recovery form.

- `POST /api/sample` with `{text: string}` produces a deterministic one-cell xlsx
  as `{format, base64}`. UTF-8 text is 1..8192 bytes, no XML control characters.
  Requires user token, does not write audit state. It is synthetic input, not a mock scanner.
- `POST /api/check`: `{question, files:[{format,base64}], request_id, label?}`.
  1–4 files totaling <=16MiB; HTTP <=24MiB; question is nonblank UTF-8 <=262144 bytes. Formats xlsx/pptx/pdf only. Request
  identifiers are exactly 32 lowercase hexadecimal characters (gateway.valid_text).
  `label` is the existing signed bundle classification, never issued by the UI.
  Returns `aisecure.bundle-report.v1` plus existing decision/coverage/classification,
  `execution_state: not_executed`, `documents` with SHA-256 fingerprints, and rules.
  Unclassified input stays review even when standalone scanning reports no findings.
  Each explicit check writes encrypted metadata; it is not a send and is not deduplicated.
- `POST /api/preview`: `{files,consent:true}`. Lossy local text only; no approval,
  no original modification. If secret/PII is detected the **entire affected document
  text is withheld**, including styled-run cases where regex replacement is unsafe.
  `preview_withheld` indicates this. Other confidential labels can remain.
- `GET /api/state` returns existing history/coverage/analysis and additive
  `destination: {provider,model,endpoint}`; endpoint is null without live delivery.
- `GET /api/audit` exports bounded, allowlisted plaintext JSONL (last 1000 records).
  Demo history is temporary and removed on shutdown. Save explicitly before exiting.
- Existing `/api/send`, collector `/api/events`, `/api/posture`, and `/api/demo`
  retain their permission contracts. Collector and user tokens are separate.
  No network sender, signer or VPN operation was added by this change.

HTTP statuses: 200 is a completed request, **not approval or delivery success**;
400 input/classification failure; 401 authentication; 403 origin/host/query denied;
404 unsupported operation; 413 body limit; 415 content type; 429 capacity/rate limit;
503 result unconfirmed. Errors use existing `{error: string}` JSON, with no raw
input echoed. Keep HTTP statuses machine-readable; do not parse Japanese messages.

Delivery states remain separate from decisions: `prevented_in_gateway`,
`dispatch_pending`, `delivery_unknown`, `demo_received`, `provider_completed`.
The server durably reserves request ID + fingerprint before sending; same ID and
same content return the existing result, changed content is rejected. On timeout
or lost response do not allocate a new ID and resend. The UI disables send after
an uncertain send for the rest of that page session; reload is not a reconciliation
procedure. Check audit/provider state with the operator. Provider text is volatile
and may not be returned on replay. There is no cancellation-after-dispatch API.
UI fetch timeout (90s) does not cancel an external side effect. Retrying an
inspection is safe for delivery but appends another audit event.

## Compatibility and limits

Existing CLI entries and HTTP fields remain; changes are additive except the
intentional safety correction withholding secret/PII preview text. No dependencies
were added. Standard OOXML, JSON, HTTP statuses, SHA-256 and existing signed
classification are used; no new authorization protocol. The standalone report
schema is explicitly versioned; it is not a universal DLP interchange standard.
See CONTROL_SCOPE.md for OCR, managed isolation, live delivery, SSO and VPN gates.
