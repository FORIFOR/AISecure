# Independent review — 2026-09-19

Reviewer: separate verification agent; no product/test implementation edits.
`independent-product-verification` skill was unavailable and was not used.
Target: HEAD `26002d840130e52b07f35dd9c9ea8189d8913ee2` plus local working-tree changes.
Environment: macOS/Darwin 25.6.0, Python 3.14.6, Node v26.5.0,
Chromium 151.0.7922.34. Only loopback servers were contacted.

## Results

- **PASS** baseline: `.venv/bin/python -m unittest tests.control.test_bundles tests.control.test_service_native -q`, exit 0, 38 tests before implementation. Existing ResourceWarning for unclosed test file was observed.
- **PASS** changed UI: `NODE_PATH=/Users/shuhei/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules AISECURE_TEST_PORT=19879 node tools/check_control_browser.cjs docs/quality/evidence/2026-09-19/independent-browser`, exit 0. Sixteen checks pass, external requests 0, JS errors 0. Saved report request ID matches actual audit record; source hash is present. Evidence: `independent-browser/browser.json`, downloaded reports and screenshots in that directory.
- **PASS** additional independent Python probe (below), exit 0: split-run secret no longer appears in preview; metadata does not contain raw secret; SDK/bundle SHA-256 matches exact source bytes; sample generation is deterministic; repeated unknown delivery invokes transport once.
- **PASS** additional hand-written Playwright probe against `python -m aisecure.control --demo --port 19880`, exit 0: open administrator details, intercept and abort `/api/send`, check consent and click send. UI says unconfirmed and disables send. Edit sample, check consent, explicitly inspect again: send remains disabled and interception count remains exactly 1. No remote provider was involved. An initial probe attempt timed out because the test had not opened the details element; the probe was corrected, without product changes.
- **BLOCKED** native Japanese IME, native browser toolbar zoom, real beginner evaluation and competitor comparison. Synthetic composition/CSS zoom is not an OS/human test.
- **BLOCKED** real provider delivery, actual network isolation and native extension enforcement: out of authorized scope/environment. No PASS claim from demo transport.

No additional blocking product defect found in reviewed scope. Initial findings
(authentication recovery, stale report invalidation, in-flight editing, no saved
artifact, undisclosed destination, split-run preview leakage) were addressed.
Delivery reconciliation remains operator-driven and is explicitly documented; an
uncertain send cannot be cleared by editing input in the same page session.

## Python probe executed

Command: `.venv/bin/python - <<'PY'` with the following body, exit 0:

```python
import io, zipfile, json, hashlib, secrets
from tests.control.helpers import office, files, Store, keypair
from tests.control.test_bundles import Transport
from aisecure.control.bundles import redacted_text_preview, BundleGateway, sign_bundle
from aisecure.control.inspection import inspect_document
from aisecure.control.example_document import sample_file
raw = office()
b = io.BytesIO()
with zipfile.ZipFile(io.BytesIO(raw)) as zin, zipfile.ZipFile(b, 'w') as zout:
    for n in zin.namelist():
        zout.writestr(n, b'<worksheet><c><is><r><t>api_</t></r><r><t>key=synthetic-secret-value</t></r></is></c></worksheet>' if n == 'xl/worksheets/sheet1.xml' else zin.read(n))
raw = b.getvalue()
r = redacted_text_preview(files(raw))
assert r['preview_withheld'] and 'synthetic-secret-value' not in json.dumps(r)
assert 'DOC-SECRET' in json.dumps(r)
s = inspect_document(raw, 'xlsx')
assert s['input_sha256'] == hashlib.sha256(raw).hexdigest()
assert 'synthetic-secret-value' not in json.dumps(s) and 'api_' not in json.dumps(s)
f = sample_file('Public sample')
assert f == sample_file('Public sample')
with Store() as store:
    priv, pub = keypair()
    t = Transport(fail=True)
    g = BundleGateway(store.audit, pub, 'model', t, 'org')
    check = g.check('q', files(raw), secrets.token_hex(16))
    assert check['documents'][0]['input_sha256'] == s['input_sha256']
    rid = secrets.token_hex(16)
    proof = sign_bundle(priv, 'q', [f], 'model', rid, 'org')
    first = g.send('q', [f], rid, proof, consent=True)
    second = g.send('q', [f], rid, proof, consent=True)
    assert first['execution_state'] == 'delivery_unknown' and second['replayed'] and len(t.calls) == 1
```

## Reviewed file identities (SHA-256)

```
84614e69bbd14f642f0105ecf2cd759f36138875e7582be3c860e8f1079b2ac6  aisecure/control/web/app.js
b9a12381d93057a384ed9593057fc843762c13502af3a5514771f2d460a1e50b  aisecure/control/bundles.py
6b3a816685996fc3e6e048e5ba5b773154b576c2d1b2c0a1ec81518cf7328cb1  aisecure/control/inspection.py
788fcd46f53b94ad915cea438a072cf1717772259e7993e224709479d4a3cdd3  aisecure/control/example_document.py
```
