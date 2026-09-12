#!/usr/bin/env python3
"""Publish a zero-install, in-browser interactive preview of the AI Secure UI.

    python3 tools/make-preview.py

Inlines the real web assets (style.css, i18n.js, app.js) and a baked read-only
snapshot into a single static page, so anyone can click through the actual UI —
all six views, EN/JA toggle — from a browser, with no Python and no clone. Write
actions are disabled in preview mode. Output: docs/try.html.
"""
from __future__ import annotations
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs/try.html"


def state() -> dict:
    from aisecure.store import Store
    from aisecure.demo import sample
    with tempfile.TemporaryDirectory() as d:
        store = Store(d)
        store.ingest(sample(), "demo")
        result = store.state()
        store.close()
    result["llm"] = {"configured": False, "requested_model": None,
                     "default_provider": "deterministic-template", "real_connection_tested": False}
    return result


def build() -> str:
    html = (ROOT / "web/index.html").read_text(encoding="utf-8")
    css = (ROOT / "web/style.css").read_text(encoding="utf-8")
    i18n = (ROOT / "web/i18n.js").read_text(encoding="utf-8")
    js = (ROOT / "web/app.js").read_text(encoding="utf-8")
    boot = (f"window.__AI_SECURE_PREVIEW__={json.dumps(state(), ensure_ascii=False)};")
    banner = (
        '<div style="position:fixed;bottom:14px;left:14px;right:14px;max-width:760px;margin:0 auto;'
        'background:#16241d;color:#e8efe9;border-radius:12px;padding:12px 18px;font:13px/1.6 '
        '-apple-system,BlinkMacSystemFont,\"Segoe UI\",\"Noto Sans JP\",sans-serif;z-index:200;'
        'box-shadow:0 18px 50px #14251c44;display:flex;gap:14px;align-items:center;flex-wrap:wrap">'
        '<span><b>Read-only preview.</b> This is the real UI on synthetic data — click around all six views. '
        'Actions are disabled here; run the local app to try them.</span>'
        '<a href="https://github.com/FORIFOR/AISecure/issues/new?template=tester-feedback.md" '
        'style="margin-left:auto;background:#7fc49f;color:#0d1511;border-radius:8px;padding:8px 14px;'
        'font-weight:600;text-decoration:none;white-space:nowrap">Give 2-min feedback →</a>'
        '<a href="https://github.com/FORIFOR/AISecure" style="color:#9ad6b4;text-decoration:none;'
        'white-space:nowrap">GitHub ↗</a></div>'
    )
    head_extra = (
        '<meta name="description" content="Try AI Secure in your browser — the real security-triage UI on synthetic data, no install.">'
        '<meta property="og:title" content="Try AI Secure in your browser">'
        '<meta property="og:description" content="Click through the real UI on synthetic data — no install, no account.">'
        '<meta property="og:image" content="https://forifor.github.io/AISecure/media/social-card.png">'
        '<meta name="twitter:card" content="summary_large_image">'
        '<meta name="twitter:image" content="https://forifor.github.io/AISecure/media/social-card.png">'
    )
    return (html
            .replace("<title>AI Secure — Evidence before action.</title>",
                     "<title>Try AI Secure — in-browser preview</title>" + head_extra)
            .replace('<link rel="stylesheet" href="/style.css">', f"<style>{css}</style>")
            .replace('<script defer src="/i18n.js"></script>', f"<script>{boot}</script><script>{i18n}</script>")
            .replace('<script defer src="/app.js"></script>', "")
            .replace("</body>", f"{banner}<script>{js}</script></body>"))


def main() -> None:
    OUT.write_text(build(), encoding="utf-8")
    print(f"{OUT.relative_to(ROOT)}  {OUT.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
