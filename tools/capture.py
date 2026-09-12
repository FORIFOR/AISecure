#!/usr/bin/env python3
"""Capture real screenshots of the local UI with headless Chrome.

    python3 tools/capture.py [outdir]

Builds a read-only preview page from the same HTML/CSS/JS the app serves, with a
real state snapshot generated from the bundled synthetic data, then screenshots
each view at desktop and phone widths. No network, no server, no credentials.
"""
from __future__ import annotations
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
VIEWS = ["overview", "assets", "tuning", "audit", "plans", "about"]
SIZES = {"desktop": (1512, 1000), "mobile": (390, 844)}


def state() -> dict:
    sys.path.insert(0, str(ROOT))
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


def page(view: str, snapshot: dict | None = None) -> str:
    """Inline the real HTML/CSS/JS with a read-only state, scripts after the body."""
    html = (ROOT / "web/index.html").read_text(encoding="utf-8")
    css = (ROOT / "web/style.css").read_text(encoding="utf-8")
    i18n = (ROOT / "web/i18n.js").read_text(encoding="utf-8")
    js = (ROOT / "web/app.js").read_text(encoding="utf-8")
    boot = (f"window.__AI_SECURE_LANG__='en';"
            f"window.__AI_SECURE_PREVIEW__={json.dumps(snapshot or state(), ensure_ascii=False)};"
            f"window.__AI_SECURE_VIEW__={json.dumps(view)};")
    # app.js renders asynchronously; wait for it before switching view.
    after = ("(function w(n){const v=window.__AI_SECURE_VIEW__;"
             "const ready=document.getElementById('viewContent').childNodes.length>0;"
             "if(!ready&&n<200)return setTimeout(()=>w(n+1),10);"
             "if(v&&v!=='overview'){const b=document.querySelector('[data-view=\"'+v+'\"]');if(b)b.click();}"
             "document.documentElement.setAttribute('data-ready','1');})(0);")
    return (html.replace('<link rel="stylesheet" href="/style.css">', f"<style>{css}</style>")
                .replace('<script defer src="/i18n.js"></script>', f"<script>{boot}</script><script>{i18n}</script>")
                .replace('<script defer src="/app.js"></script>', "")
                .replace("</body>", f"<script>{js}</script><script>{after}</script></body>"))


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "docs/screenshots")
    out.mkdir(parents=True, exist_ok=True)
    if not Path(CHROME).exists():
        raise SystemExit(f"Chrome not found at {CHROME}")
    with tempfile.TemporaryDirectory() as tmp:
        for view in VIEWS:
            source = Path(tmp) / f"{view}.html"
            source.write_text(page(view), encoding="utf-8")
            for label, (w, h) in SIZES.items():
                target = out / (f"{view}.png" if label == "desktop" else f"{view}-mobile.png")
                subprocess.run([CHROME, "--headless", "--disable-gpu", "--hide-scrollbars",
                                "--force-device-scale-factor=2", f"--window-size={w},{h}",
                                f"--screenshot={target}", "--virtual-time-budget=3000",
                                source.as_uri()], check=True, capture_output=True)
                print(f"{target.relative_to(ROOT)}  {target.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
