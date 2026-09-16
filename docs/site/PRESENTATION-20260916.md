# Product presentation refresh — 2026-09-16

## Scope
Japanese and English homepages only. No detection, approval or enforcement logic changed.

- Replace the old walkthrough on both homepages with an original 18-second silent product-concept film: 1920×1080, 30 fps, H.264/MP4, fast-start, Japanese/English versions, local JPEG posters and WebVTT captions. No stock footage, downloaded fonts, external video embeds or audio tracks are distributed.
- Navy and white replace the previous all-green treatment. Mint is an accent; red/amber/green are reserved for decision states. The hierarchy is preflight first, reasons second, investigation third.
- Keep the four Python-backed synthetic examples and all relevant implementation limits. Technical fields are disclosure details rather than the first thing visitors read.
- Keep existing explicit-consent inquiry handling and disable it gracefully without `crypto.randomUUID`. No new collection or tracking is added.
- Real endpoint/VPN protection remains unimplemented or unconnected as described in `PREVENTION_BOUNDARY.ja.md`. The film is labelled as a concept, not a live UI recording or proof of enforcement.

## Reproduce the film

Install Pillow 12.3.0, ffmpeg, and system Noto Sans CJK fonts. Font binaries are never copied into the repository.

```sh
python tools/render_product_film.py --out docs/media
```

This deterministically draws synthetic scenes and eases the cards into place. The point of the film is to explain content → decision → evidence, not to claim a deployed integration. Native controls, captions, a transcript and static posters remain available. Playback is user-initiated and does not loop automatically.

## Verification

```sh
python -m unittest discover -s tests -v
python -m pip install playwright==1.57.0
python -m playwright install --with-deps chromium
python tools/check_product_presentation.py
```

The browser check uses a local HTTP server, exercises Japanese/English at 320, 390, 768 and 1440 pixels, asserts no horizontal overflow, tests keyboard navigation and verifies native 1920×1080 / 18-second video playback. External requests are blocked so no real inquiry is sent. `--offline` instead renders the same local resources in memory; that is not a live-URL check.

The initial local check used `--offline` because navigation is restricted in the authoring environment. All eight layouts and video playback passed; no JavaScript errors or unsolicited POST requests were observed. Eight new presentation-contract tests passed locally. Full repository CI, public deployment and independent security review are separate checks; do not infer one from another.
