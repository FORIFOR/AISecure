#!/usr/bin/env python3
"""Build the demo video and GIF from the real CLI output and the real UI.

    python3 tools/make-demo.py

Terminal scenes are rendered from output this script actually produces by running
the commands; UI scenes are screenshots of the same HTML/CSS/JS the app serves,
driven by the bundled synthetic data. Nothing is mocked up in a design tool.

Requires Google Chrome (screenshots) and ffmpeg (encoding), both local.
"""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
W, H, SCALE, FPS = 1280, 720, 2, 25
OUT = ROOT / "docs/media"

FONT = ('-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans JP",'
        '"Hiragino Kaku Gothic ProN",Meiryo,sans-serif')
MONO = 'ui-monospace,SFMono-Regular,Menlo,"Noto Sans Mono",monospace'
BASE = f"""
*{{box-sizing:border-box;margin:0}}
html,body{{width:{W}px;height:{H}px;overflow:hidden}}
body{{background:#f6f7f5;color:#20352f;font-family:{FONT};display:flex;
     align-items:center;justify-content:center}}
.wrap{{width:{W - 120}px}}
.eyebrow{{font-size:13px;letter-spacing:.18em;color:#7d9084;font-weight:700;margin-bottom:18px}}
h1{{font-size:46px;line-height:1.35;letter-spacing:-.04em;font-weight:650}}
h2{{font-size:30px;line-height:1.4;letter-spacing:-.035em;font-weight:650;margin-bottom:14px}}
p{{font-size:17px;line-height:1.85;color:#5d6f65}}
.term{{background:#16241d;border-radius:14px;padding:26px 30px;font-family:{MONO};
      font-size:15px;line-height:1.95;color:#d7e5da;box-shadow:0 24px 60px #14251c22}}
.term>div{{white-space:pre}}
.term .dots{{display:flex;gap:7px;margin-bottom:18px}}
.term .dots i{{width:11px;height:11px;border-radius:50%;background:#33473c;display:block}}
.term .p{{color:#6fae87}}
.term .c{{color:#fff}}
.term .m{{color:#9fb3a6}}
.term .hi{{color:#ffd08a}}
.term .bad{{color:#ff9d8a}}
.term .ok{{color:#8fe0a8}}
table{{width:100%;border-collapse:collapse;font-size:17px;margin-top:8px}}
th{{font-size:13px;color:#8a9685;text-align:left;padding:10px 14px;border-bottom:1px solid #dfe5dc;font-weight:500}}
td{{padding:14px;border-bottom:1px solid #edf0e9}}
td.n{{font-variant-numeric:tabular-nums;font-weight:600;text-align:right}}
.card{{background:#fff;border:1px solid #e3e8e2;border-radius:16px;padding:26px 30px;
      box-shadow:0 18px 50px #23372b0d}}
.bad{{color:#a44136}}
.good{{color:#175b48}}
.mark{{display:inline-grid;grid-template-columns:1fr 1fr;gap:5px;width:42px;height:46px;
      transform:rotate(-9deg);margin-bottom:26px}}
.mark i{{background:#175b48;border-radius:4px}}
.mark i:nth-child(2){{background:#8eab92}}
.mark i:nth-child(3){{background:#c9d8c7}}
.foot{{margin-top:26px;font-size:15px;color:#7d8c81;font-family:{MONO}}}
"""


def html(body: str, extra: str = "") -> str:
    return f"<!doctype html><meta charset=utf-8><style>{BASE}{extra}</style><body>{body}</body>"


def term(lines: list[str]) -> str:
    rows = "".join(f"<div>{line}</div>" for line in lines)
    return html(f'<div class=wrap><div class=term><div class=dots><i></i><i></i><i></i></div>{rows}</div></div>')


def shot(source: str, target: Path) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as handle:
        handle.write(source)
        path = Path(handle.name)
    subprocess.run([CHROME, "--headless", "--disable-gpu", "--hide-scrollbars",
                    f"--force-device-scale-factor={SCALE}", f"--window-size={W},{H}",
                    f"--screenshot={target}", "--virtual-time-budget=4000", path.as_uri()],
                   check=True, capture_output=True)
    path.unlink()


def ui_scene(view: str, target: Path, script: str = "") -> None:
    from tools.capture import page
    source = page(view).replace("</body>", f"<script>setTimeout(()=>{{{script}}},400);</script></body>" if script else "</body>")
    shot(source, target)


PROMPT = '<span class=p>$</span> <span class=c>'


def scenes() -> list[tuple[str, float]]:
    """(html-or-uiview, seconds). Numbers below come from docs/evaluation/."""
    return [
        (html('<div class=wrap style="text-align:center">'
              '<div class=mark style="margin:0 auto 26px"><i></i><i></i><i></i><i></i></div>'
              '<div class=eyebrow>AI SECURE — EVIDENCE BEFORE ACTION</div>'
              '<h1>「CVSSが高い順」をやめて、<br>経路・権限・行動を<b>つないで</b>見る。</h1>'
              '<p style="margin-top:22px">公開された接続機器・保守アカウント・大量ファイル参照を関連付け、'
              '根拠付きで初動対応を判断する。ローカル完結・LLM不要。</p></div>'), 4.0),

        (term([f'{PROMPT}python3 -m aisecure import \\</span>',
               '<span class=c>&nbsp;&nbsp;--source generic-asset-csv=assets.csv \\</span>',
               '<span class=c>&nbsp;&nbsp;--source generic-auth-csv=auth.csv \\</span>',
               '<span class=c>&nbsp;&nbsp;--source generic-file-access-jsonl=access.jsonl</span>',
               '&nbsp;',
               '<span class=m>読み込み 1,848 行 / 取り込み 1,848 行 / 読み飛ばし 0 行</span>',
               '<span class=m>資産 4 / イベント 1,844</span>',
               '&nbsp;',
               '<span class=ok>→ 読み取り専用。ソースには書き込まない。</span>',
               '<span class=ok>→ 許可した項目以外は取り込まない。読めない値は「不明」。</span>']), 5.0),

        (html('<div class=wrap><div class=eyebrow>THE QUESTION NOBODY MEASURES</div>'
              '<h2>「300秒に100ファイル」は、正常な業務では何件鳴るのか。</h2>'
              '<p>夜間バックアップ。分析担当者の一括参照。移行作業。<br>'
              'どれも同じ形をしている。だから閾値は、正常な業務で測ってから決める。</p></div>'), 4.5),

        (term([f'{PROMPT}python3 -m aisecure baseline --days 5 --users 40 --out normal.json</span>',
               f'{PROMPT}python3 -m aisecure evaluate normal*.json incident.json --sweep</span>',
               '&nbsp;',
               '<span class=m>シナリオ 4件 / 18.84日 / 85,509イベント</span>',
               '&nbsp;',
               '<span class=hi>ルール                        件数   検知   誤検知</span>',
               '<span class=bad>AS-003  単体の大量ファイル参照    103      1    102</span>',
               '<span class=ok>AS-004  相関（機器+権限+行動）       1      1      0</span>']), 6.0),

        (html('<div class=wrap><div class=card>'
              '<div class=eyebrow>MEASURED, NOT ASSUMED</div>'
              '<h2>単体ルールは99%が正常業務。<br>相関は19日間で誤検知ゼロ。</h2>'
              '<p style="margin-bottom:18px">閾値を上げて誤検知を0にすると、事案も検知できなくなる。'
              '21通り試した結果がそれを示している。</p>'
              '<table><tr><th>設定</th><th style="text-align:right">誤検知</th>'
              '<th style="text-align:right">検知漏れ</th></tr>'
              '<tr><td>100ファイル / 300秒（既定）</td><td class="n bad">102</td><td class=n>0</td></tr>'
              '<tr><td>300ファイル / 120秒（静か）</td><td class="n good">0</td><td class="n bad">事案も見逃す</td></tr>'
              '</table></div></div>'), 6.0),

        ("ui:overview", 6.0),
        ("ui:tuning", 5.0),

        (html('<div class=wrap style="text-align:center">'
              '<div class=eyebrow>WHAT THIS IS NOT</div>'
              '<h2>できないことを、先に書く。</h2>'
              '<p>常時監視しない。通信を遮断しない。アカウントを停止しない。<br>'
              'v0.2 はローカル検証版で、対応はすべてシミュレーションです。<br>'
              '<b>合成データの測定値であり、実環境の誤検知率ではありません。</b></p></div>'), 5.0),

        (html('<div class=wrap style="text-align:center">'
              '<div class=mark style="margin:0 auto 26px"><i></i><i></i><i></i><i></i></div>'
              '<h1 style="font-size:40px">Evidence before action.</h1>'
              '<p style="margin-top:18px">判断の根拠は手元に。操作の権限は人に。</p>'
              '<div class=foot>github.com/FORIFOR/AISecure &nbsp;·&nbsp; MIT &nbsp;·&nbsp; Python 3.11+ / 依存ゼロ</div>'
              '</div>'), 4.0),
    ]


def main() -> None:
    if not Path(CHROME).exists() or not shutil.which("ffmpeg"):
        raise SystemExit("Chrome と ffmpeg が必要です。")
    OUT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp())
    listing = []
    for index, (scene, seconds) in enumerate(scenes()):
        frame = work / f"{index:02}.png"
        if scene.startswith("ui:"):
            ui_scene(scene[3:], frame)
        else:
            shot(scene, frame)
        print(f"  scene {index}: {frame.name} ({seconds}s)")
        listing.append(f"file '{frame}'\nduration {seconds}")
    listing.append(f"file '{work}/{len(scenes()) - 1:02}.png'")
    playlist = work / "list.txt"
    playlist.write_text("\n".join(listing), encoding="utf-8")

    mp4 = OUT / "demo.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(playlist),
                    "-vf", f"scale={W * SCALE}:{H * SCALE}:force_original_aspect_ratio=decrease,"
                           f"pad={W * SCALE}:{H * SCALE}:(ow-iw)/2:(oh-ih)/2:color=0xf6f7f5,"
                           f"scale={W}:{H},fps={FPS},format=yuv420p",
                    "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-movflags", "+faststart", str(mp4)],
                   check=True)
    gif = OUT / "demo.gif"
    palette = work / "palette.png"
    common = f"fps=10,scale=900:-1:flags=lanczos"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(mp4), "-vf", f"{common},palettegen=stats_mode=diff",
                    str(palette)], check=True)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(mp4), "-i", str(palette),
                    "-lavfi", f"{common}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3", str(gif)], check=True)
    shutil.rmtree(work, ignore_errors=True)
    for path in (mp4, gif):
        print(f"{path.relative_to(ROOT)}  {path.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
