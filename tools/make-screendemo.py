#!/usr/bin/env python3
"""A Screen Studio–style product demo for AI Secure.

    python3 tools/make-screendemo.py

Real product screenshots are framed in a rounded window on a soft gradient, then
driven with auto-zoom punch-ins toward the region under discussion, a smoothly
moving cursor, and lower-third captions — the Screen Studio vocabulary — and
scored with the same instrumental track. Fully local (Chrome + ffmpeg).
"""
from __future__ import annotations
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BGM = Path("/Users/shuhei/Downloads/bgm/I11 Quiet Momentum • R2.wav")
OUT = ROOT / "docs/media/screendemo.mp4"
W, H, FPS, SCALE = 1920, 1080, 30, 2
MONO = 'ui-monospace,SFMono-Regular,Menlo,"Noto Sans Mono",monospace'
SANS = '-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans JP","Hiragino Kaku Gothic ProN",sans-serif'


def shot(html: str, target: Path, w: int = W, h: int = H, scale: int = SCALE) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as fh:
        fh.write(html)
        src = Path(fh.name)
    subprocess.run([CHROME, "--headless", "--disable-gpu", "--hide-scrollbars", "--default-background-color=00000000",
                    f"--force-device-scale-factor={scale}", f"--window-size={w},{h}",
                    f"--screenshot={target}", "--virtual-time-budget=3000", src.as_uri()],
                   check=True, capture_output=True)
    src.unlink()


def framed(image: Path, target: Path) -> None:
    """Real screenshot inside a rounded browser window on a soft brand gradient."""
    html = f"""<!doctype html><meta charset=utf-8><style>
    *{{margin:0;box-sizing:border-box}}
    html,body{{width:{W}px;height:{H}px;overflow:hidden}}
    body{{display:flex;align-items:center;justify-content:center;
      background:linear-gradient(135deg,#eef3ec 0%,#e5efe8 45%,#e8eef6 100%)}}
    .win{{width:{W-380}px;border-radius:22px;overflow:hidden;background:#fff;
      box-shadow:0 40px 100px #24402e26,0 8px 24px #24402e14;border:1px solid #dbe4dd}}
    .bar{{height:44px;background:#f3f6f2;border-bottom:1px solid #e4ebe4;display:flex;align-items:center;padding:0 18px;gap:9px}}
    .bar i{{width:12px;height:12px;border-radius:50%;background:#d3ddd4;display:block}}
    .bar i:nth-child(1){{background:#e6b0a6}}.bar i:nth-child(2){{background:#ecd6a6}}.bar i:nth-child(3){{background:#a9cbb0}}
    .bar .u{{margin-left:16px;font:12px {MONO};color:#8ba090;background:#fff;border:1px solid #e4ebe4;
      border-radius:7px;padding:5px 14px}}
    img{{display:block;width:100%}}
    </style><body><div class=win><div class=bar><i></i><i></i><i></i>
    <span class=u>127.0.0.1 · AI Secure</span></div>
    <img src="{image.as_uri()}"></div></body>"""
    shot(html, target)


def caption(text: str, target: Path) -> None:
    html = f"""<!doctype html><meta charset=utf-8><style>
    *{{margin:0;box-sizing:border-box}}html,body{{width:{W}px;height:{H}px}}
    body{{background:transparent;display:flex;align-items:flex-end;justify-content:center;padding-bottom:70px}}
    .cap{{font:600 30px {SANS};color:#20352f;background:#ffffffee;border:1px solid #dfe6df;
      border-radius:14px;padding:16px 30px;box-shadow:0 18px 50px #24402e1f;letter-spacing:-.01em}}
    </style><body>{("<div class=cap>"+text+"</div>") if text else ""}</body>"""
    shot(html, target, scale=1)


def cursor_png(target: Path) -> None:
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='72' height='72' viewBox='0 0 24 24'>"
           "<path d='M4 2 L4 20 L9 15 L12.5 22 L15 21 L11.5 14 L18 14 Z' fill='white' stroke='#20352f' "
           "stroke-width='1.4' stroke-linejoin='round'/></svg>")
    html = (f"<!doctype html><meta charset=utf-8><style>*{{margin:0}}html,body{{width:72px;height:72px;"
            f"background:transparent}}</style><body>{svg}</body>")
    shot(html, target, w=72, h=72, scale=1)


def segment(framed_png: Path, cap_png: Path, seconds: float, zoom: tuple[float, float],
            focus: tuple[float, float], cur_from: tuple[int, int], cur_to: tuple[int, int],
            cursor: Path, out: Path) -> None:
    frames = round(FPS * seconds)
    z0, z1 = zoom
    fx, fy = focus
    iw, ih = W * SCALE, H * SCALE
    # Static punch-in via crop+scale (reliable), plus a gentle zoompan from 1.0 for life.
    Z = max(z1, 1.001)
    cw = int(iw / Z) // 2 * 2
    ch = int(ih / Z) // 2 * 2
    cx = int((iw - cw) * fx) // 2 * 2
    cy = int((ih - ch) * fy) // 2 * 2
    drift = 0.03
    dr = drift / max(frames - 1, 1)
    ease = f"(1-pow(1-min(t/{seconds - 0.2:.3f}\\,1)\\,3))"
    cxp = f"{cur_from[0]}+({cur_to[0] - cur_from[0]})*{ease}"
    cyp = f"{cur_from[1]}+({cur_to[1] - cur_from[1]})*{ease}"
    vf = (
        f"[0:v]scale={iw}:{ih},crop={cw}:{ch}:{cx}:{cy},scale={W}:{H},"
        f"zoompan=z='min(1.0+{dr:.6f}*on,{1.0+drift})':d={frames}:"
        f"x='(iw-iw/zoom)/2':y='(ih-ih/zoom)/2':s={W}x{H}:fps={FPS}[bg];"
        f"[bg][2:v]overlay=x='{cxp}':y='{cyp}'[cur];"
        f"[cur][1:v]overlay=0:0,fade=t=in:st=0:d=0.3:color=0xeaf0ea,"
        f"fade=t=out:st={seconds-0.3:.3f}:d=0.3:color=0xeaf0ea,format=yuv420p[v]"
    )
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-loop", "1", "-t", f"{seconds}", "-i", str(framed_png),
                    "-loop", "1", "-t", f"{seconds}", "-i", str(cap_png),
                    "-loop", "1", "-t", f"{seconds}", "-i", str(cursor),
                    "-filter_complex", vf, "-map", "[v]", "-r", str(FPS), "-t", f"{seconds}",
                    "-c:v", "libx264", "-preset", "medium", "-crf", "18", str(out)], check=True)


def end_card(target: Path) -> None:
    html = f"""<!doctype html><meta charset=utf-8><style>*{{margin:0;box-sizing:border-box}}
    html,body{{width:{W}px;height:{H}px}}
    body{{background:linear-gradient(135deg,#eef3ec,#e8eef6);display:flex;align-items:center;justify-content:center}}
    .wrap{{text-align:center}}
    .mark{{display:inline-grid;grid-template-columns:1fr 1fr;gap:10px;width:96px;height:106px;transform:rotate(-9deg);margin-bottom:34px}}
    .mark i{{background:#175b48;border-radius:12px}}.mark i:nth-child(2){{background:#8eab92}}.mark i:nth-child(3){{background:#c9d8c7}}
    h2{{font:660 54px {SANS};letter-spacing:-.04em;color:#20352f}}
    .u{{font:30px {MONO};color:#175b48;margin-top:22px}}
    </style><body><div class=wrap><div class=mark><i></i><i></i><i></i><i></i></div>
    <h2>Evidence before action.</h2><div class=u>github.com/FORIFOR/AISecure</div></div></body>"""
    shot(html, target)


def storyboard(work: Path) -> list[tuple]:
    ov = framed_path(work, "overview")
    tu = framed_path(work, "tuning")
    ec = work / "end.png"; end_card(ec)
    cur = work / "cursor.png"; cursor_png(cur)

    def cap(name, text):
        p = work / f"cap_{name}.png"; caption(text, p); return p

    # (framed, caption, seconds, (z0,z1), focus(fx,fy), cursor_from, cursor_to)
    # Every segment starts wide (z=1.0) and punches IN toward the region — a clean
    # Screen Studio move, and it avoids a zoompan blank when z starts above 1.
    return [
        (ov, cap("s1", "One screen — the reason to act, with its evidence"), 5.0, (1.0, 1.07), (0.34, 0.58), (360, 240), (820, 640), cur),
        (ov, cap("s2", "The path, not the score"), 4.4, (1.0, 1.42), (0.33, 0.70), (300, 300), (980, 620), cur),
        (ov, cap("s3", "No real action — a human approves"), 3.0, (1.0, 1.5), (0.62, 0.88), (760, 300), (1120, 720), cur),
        (tu, cap("s4", "Detection settings — every threshold, explained"), 3.4, (1.0, 1.06), (0.18, 0.42), (900, 500), (300, 330), cur),
        (tu, cap("s5", "Measure the false-positive cost before you deploy"), 4.6, (1.0, 1.4), (0.56, 0.52), (300, 340), (1120, 560), cur),
        (ec, cap("end", ""), 3.2, (1.0, 1.05), (0.5, 0.5), (2200, 2200), (2200, 2200), cur),
    ]


def framed_path(work: Path, name: str) -> Path:
    src = ROOT / f"docs/screenshots/{name}.png"
    out = work / f"framed_{name}.png"
    framed(src, out)
    return out


def main() -> None:
    if not Path(CHROME).exists() or not BGM.exists():
        raise SystemExit("Chrome or BGM missing")
    work = Path(tempfile.mkdtemp())
    clips, total = [], 0.0
    for i, (fr, cap, secs, zoom, focus, cf, ct, cur) in enumerate(storyboard(work)):
        clip = work / f"seg{i}.mp4"
        segment(fr, cap, secs, zoom, focus, cf, ct, cur, clip)
        clips.append(clip); total += secs
        print(f"  segment {i}: {secs}s")
    listing = work / "list.txt"; listing.write_text("".join(f"file '{c}'\n" for c in clips), encoding="utf-8")
    silent = work / "v.mp4"
    # Re-encode on concat: -c copy leaves only the first clip playable when the
    # per-segment h264 streams differ slightly.
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
                    "-i", str(listing), "-r", str(FPS), "-c:v", "libx264", "-preset", "medium",
                    "-crf", "18", "-pix_fmt", "yuv420p", str(silent)], check=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fo = max(total - 2.2, 0.1)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(silent), "-i", str(BGM),
                    "-filter_complex",
                    f"[1:a]atrim=0:{total:.3f},afade=t=in:st=0:d=1.2,afade=t=out:st={fo:.2f}:d=2.2,volume=0.6[a]",
                    "-map", "0:v", "-map", "[a]", "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
                    "-shortest", "-movflags", "+faststart", str(OUT)], check=True)
    print(f"{OUT.relative_to(ROOT)}  {OUT.stat().st_size // 1024} KiB  ~{total:.1f}s")


if __name__ == "__main__":
    main()
