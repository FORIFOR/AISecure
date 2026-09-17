# AISecure first proof

The first proof is the real local Workbench with synthetic input and a demo transport.

```bash
python -m pip install '.[workbench]'
aisecure-workbench --demo
```

This path binds to loopback, creates temporary demo keys/state, and uses `DemoTransport`. It does **not** send the sample text to an external AI provider. The temporary evidence store is removed when the process exits.

## What to verify first

1. Load the public sample and confirm it can be checked.
2. Load the confidential or secret sample and confirm the decision is not silently sent.
3. Open the reason/evidence view and confirm the decision can be traced to the stored event.
4. Check the history so `inspection` and any requested send/result remain distinguishable.

## What this does not prove

- It does not prove host-wide DLP, EDR, USB control, personal-cloud blocking, or VPN isolation.
- It does not prove that an enterprise network prevents bypass around the managed path.
- It does not inspect every image, PDF, audio file, encrypted archive, or other unsupported attachment format.
- A demo BLOCK proves the Workbench/preflight path rejected that synthetic request; it is not evidence that every application on the machine was prevented from transmitting data.

## Moving beyond the first proof

The general CLI is available as:

```bash
aisecure --help
```

Real provider mode is deliberately separate and opt-in. It requires dedicated storage, external keys/tokens and the managed-egress acknowledgement. Do not use a green demo as evidence that a production deployment, endpoint control or VPN response has been verified.
