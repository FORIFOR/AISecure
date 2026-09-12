#!/usr/bin/env python3
"""Build a short SaaS-intro animation for AI Secure, with BGM.

    python3 tools/make-intro.py

Scenes are rendered as high-res cards with headless Chrome (great typography,
JP-capable) and real product screenshots, then animated by ffmpeg (Ken Burns
zoom + fades) and scored with a chosen instrumental track. Deterministic and
fully local — no external video/audio service is called.

Requires Google Chrome and ffmpeg.
"""
from __future__ import annotations
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BGM = Path("/Users/shuhei/Downloads/bgm/I11 Quiet Momentum • R2.wav")
NARRATE = "--narrate" in sys.argv
LANG = "ja" if "--lang" in sys.argv and sys.argv[sys.argv.index("--lang") + 1] == "ja" else "en"
_suffix = ("-narrated" if NARRATE else "") + ("-ja" if LANG == "ja" else "")
OUT = ROOT / f"docs/media/intro{_suffix}.mp4"
VOICE = "Kyoko" if LANG == "ja" else "Daniel"
VOICE_RATE = 170 if LANG == "ja" else 168
W, H, FPS, SCALE = 1920, 1080, 30, 2
FADE = 0.4
VO_LEAD, VO_TAIL = 0.6, 0.9

FONT = ('-apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans JP",'
        '"Hiragino Kaku Gothic ProN",Meiryo,sans-serif')
MONO = 'ui-monospace,SFMono-Regular,Menlo,"Noto Sans Mono",monospace'
CSS = f"""
*{{box-sizing:border-box;margin:0}}
html,body{{width:{W}px;height:{H}px;overflow:hidden}}
body{{background:#f6f7f5;color:#20352f;font-family:{FONT};display:flex;
     align-items:center;justify-content:center;position:relative}}
.wrap{{width:{W-260}px;text-align:center}}
.eyebrow{{font-size:22px;letter-spacing:.28em;color:#7d9084;font-weight:700;margin-bottom:34px}}
h1{{font-size:92px;line-height:1.14;letter-spacing:-.05em;font-weight:680}}
h2{{font-size:60px;line-height:1.24;letter-spacing:-.04em;font-weight:660}}
p.sub{{font-size:30px;line-height:1.7;color:#5d6f65;margin-top:30px}}
.mark{{display:inline-grid;grid-template-columns:1fr 1fr;gap:12px;width:120px;height:132px;
      transform:rotate(-9deg);margin-bottom:44px}}
.mark i{{background:#175b48;border-radius:14px}}
.mark i:nth-child(2){{background:#8eab92}}.mark i:nth-child(3){{background:#c9d8c7}}
.brandname{{font-size:74px;font-weight:680;letter-spacing:-.05em}}
.path{{display:flex;align-items:center;justify-content:center;gap:22px;margin-top:56px}}
.node{{background:#fff;border:1px solid #e3e8e2;border-radius:20px;padding:28px 26px;width:340px;
      box-shadow:0 24px 60px #23372b0e}}
.node .n{{width:44px;height:44px;border:1px solid #d7dfd1;color:#66805b;border-radius:12px;
      display:grid;place-items:center;font-size:18px;margin:0 auto 16px;font-family:{MONO}}}
.node strong{{display:block;font-size:26px;font-weight:650}}
.node small{{display:block;font-size:18px;color:#8b978d;margin-top:8px}}
.arrow{{color:#a9b7a0;font-size:40px}}
.stats{{display:flex;gap:26px;margin-top:52px}}
.stat{{flex:1;background:#fff;border:1px solid #e3e8e2;border-radius:22px;padding:38px 34px;text-align:left;
      box-shadow:0 24px 60px #23372b0e}}
.stat .k{{font-size:24px;color:#5d6f65;margin-bottom:18px;line-height:1.4}}
.stat .v{{font-size:96px;font-weight:680;letter-spacing:-.05em;font-variant-numeric:tabular-nums;line-height:1}}
.stat .u{{font-size:26px;color:#8b978d;font-weight:400;letter-spacing:0}}
.bad .v{{color:#a44136}}.good .v{{color:#175b48}}
.chips{{display:flex;gap:16px;justify-content:center;flex-wrap:wrap;margin-top:44px}}
.chip{{font-family:{MONO};font-size:26px;color:#4f6457;border:1px solid #d7dfd1;
      border-radius:12px;padding:14px 22px;background:#fff}}
.url{{font-family:{MONO};font-size:34px;color:#175b48;margin-top:30px}}
.foot{{position:absolute;bottom:70px;left:0;right:0;text-align:center;font-family:{MONO};
      font-size:22px;color:#8b978d}}
.hl{{color:#a44136}}
.dim{{color:#aab4ab}}
"""


def card(body: str) -> str:
    return f"<!doctype html><meta charset=utf-8><style>{CSS}</style><body>{body}</body>"


MARK = '<div class=mark><i></i><i></i><i></i><i></i></div>'


def shot_of(name: str) -> str:
    """Use the localized screenshot when it exists (e.g. overview.ja.png)."""
    if LANG == "ja":
        ja = ROOT / f"docs/screenshots/{name}.ja.png"
        if ja.exists():
            return str(ja)
    return str(ROOT / f"docs/screenshots/{name}.png")


def scenes_en() -> list[tuple[str, float, float, str]]:
    return [
        (card(f'<div class=wrap>{MARK}<div class=brandname>AI&nbsp;Secure</div>'
              '<p class="sub" style="letter-spacing:.24em;font-size:24px;color:#7d9084;margin-top:18px">'
              'EVIDENCE BEFORE ACTION</p></div>'), 3.6, 1.05, ""),
        (card('<div class=wrap><div class=eyebrow>THE PROBLEM</div>'
              '<h2>Hundreds of alerts, ranked by CVSS.<br>'
              '<span class=dim>The one that matters is</span> <span class=hl>buried.</span></h2></div>'), 4.2, 1.06,
         "Security teams face hundreds of alerts, ranked by a severity score. The one that matters is often buried."),
        (card('<div class=wrap><div class=eyebrow>THE IDEA</div>'
              '<h2>Correlate the path, not the score.</h2>'
              '<div class=path>'
              '<div class=node><div class=n>01</div><strong>Exposed + unpatched</strong><small>edge gateway</small></div>'
              '<div class=arrow>→</div>'
              '<div class=node><div class=n>02</div><strong>Privileged login</strong><small>unmanaged / unapproved</small></div>'
              '<div class=arrow>→</div>'
              '<div class=node><div class=n>03</div><strong>Bulk file access</strong><small>sensitive files</small></div>'
              '</div></div>'), 5.0, 1.045,
         "AI Secure correlates the path instead. An exposed gateway, a privileged login, and a burst of file access, as one case."),
        (card('<div class=wrap><div class=eyebrow>WE MEASURED OUR OWN RULE</div>'
              '<h2 style="font-size:52px">On 18.8 days of normal business traffic</h2>'
              '<div class=stats>'
              '<div class="stat bad"><div class=k>Bulk-access rule, alone</div>'
              '<div class=v>102<span class=u>&nbsp;/103 false positives</span></div></div>'
              '<div class="stat good"><div class=k>Correlated: exposure + privilege + behaviour</div>'
              '<div class=v>0<span class=u>&nbsp;/1 false positives</span></div></div>'
              '</div></div>'), 5.6, 1.04,
         "We measured our own rules on nineteen days of normal traffic. The volume rule fired a hundred and two false positives. The correlation fired zero."),
        (shot_of("overview"), 4.6, 1.10, "One reviewable case, with its evidence attached, and what is still unknown."),
        (shot_of("tuning"), 4.0, 1.10, "And you measure the false-positive cost before you deploy a threshold."),
        (card('<div class=wrap><div class=eyebrow>WHAT IT IS</div>'
              '<h2>Runs on your machine. Nothing leaves it.</h2>'
              '<div class=chips><span class=chip>Local-first</span><span class=chip>No LLM</span>'
              '<span class=chip>0 dependencies</span><span class=chip>MIT</span>'
              '<span class=chip>127.0.0.1 only</span></div></div>'), 4.0, 1.05,
         "It runs entirely on your machine. No L L M, no dependencies, open source."),
        (card(f'<div class=wrap>{MARK}<h2>Evidence before action.</h2>'
              '<div class=url>github.com/FORIFOR/AISecure</div></div>'
              '<div class=foot>Open source · Python 3.11+ · A local security-triage prototype</div>'), 4.4, 1.05,
         "AI Secure. Evidence before action."),
    ]


def scenes_ja() -> list[tuple[str, float, float, str]]:
    return [
        (card(f'<div class=wrap>{MARK}<div class=brandname>AI&nbsp;Secure</div>'
              '<p class="sub" style="letter-spacing:.24em;font-size:24px;color:#7d9084;margin-top:18px">'
              'EVIDENCE BEFORE ACTION</p></div>'), 3.6, 1.05, ""),
        (card('<div class=wrap><div class=eyebrow>課題</div>'
              '<h2>数百の警告を、CVSS順に。<br>'
              '<span class=dim>本当に重要なものは、</span><span class=hl>埋もれる。</span></h2></div>'), 4.4, 1.06,
         "セキュリティ担当は、深刻度スコア順に並んだ数百の警告に向き合います。本当に重要なものは、しばしば埋もれてしまいます。"),
        (card('<div class=wrap><div class=eyebrow>着想</div>'
              '<h2>スコアではなく、経路を相関させる。</h2>'
              '<div class=path>'
              '<div class=node><div class=n>01</div><strong>外部公開＋未修正</strong><small>接続機器</small></div>'
              '<div class=arrow>→</div>'
              '<div class=node><div class=n>02</div><strong>特権ログイン</strong><small>非管理端末 / 未承認</small></div>'
              '<div class=arrow>→</div>'
              '<div class=node><div class=n>03</div><strong>大量ファイル参照</strong><small>機密ファイル</small></div>'
              '</div></div>'), 5.4, 1.045,
         "AIセキュアは、経路を相関させます。外部公開かつ未修正の接続機器、条件に問題がある特権ログイン、そして短時間の大量参照を、ひとつの事案として提示します。"),
        (card('<div class=wrap><div class=eyebrow>自分たちのルールを測りました</div>'
              '<h2 style="font-size:52px">正常業務 18.8日ぶんのトラフィックで</h2>'
              '<div class=stats>'
              '<div class="stat bad"><div class=k>大量参照ルール単体</div>'
              '<div class=v>102<span class=u>&nbsp;/103 が誤検知</span></div></div>'
              '<div class="stat good"><div class=k>相関：公開 ＋ 特権 ＋ 行動</div>'
              '<div class=v>0<span class=u>&nbsp;/1 が誤検知</span></div></div>'
              '</div></div>'), 5.8, 1.04,
         "自分たちのルールを、正常業務 19日ぶんのトラフィックで測りました。量だけのルールは、102件の誤検知。経路の相関は、ゼロでした。"),
        (shot_of("overview"), 4.8, 1.10, "根拠を添えた、ひとつの確認可能な事案。そして、まだ分からないことも示します。"),
        (shot_of("tuning"), 4.2, 1.10, "閾値を導入する前に、その誤検知コストを測れます。"),
        (card('<div class=wrap><div class=eyebrow>特長</div>'
              '<h2>あなたの端末で動く。データは外に出ない。</h2>'
              '<div class=chips><span class=chip>ローカル完結</span><span class=chip>LLM不要</span>'
              '<span class=chip>依存ゼロ</span><span class=chip>MIT</span>'
              '<span class=chip>127.0.0.1のみ</span></div></div>'), 4.2, 1.05,
         "すべてお使いの端末で動きます。LLM不要、依存ゼロ、オープンソースです。"),
        (card(f'<div class=wrap>{MARK}<h2>Evidence before action.</h2>'
              '<div class=url>github.com/FORIFOR/AISecure</div></div>'
              '<div class=foot>オープンソース · Python 3.11+ · ローカル完結のセキュリティ初動支援プロトタイプ</div>'), 4.4, 1.05,
         "AIセキュア。判断の根拠は手元に、操作の権限は人に。"),
    ]


def scenes() -> list[tuple[str, float, float, str]]:
    """(html-or-image-path, base_seconds, zoom_max, narration). Numbers from docs/evaluation/."""
    return scenes_ja() if LANG == "ja" else scenes_en()


def narration_wav(text: str, work: Path, i: int) -> tuple[Path, float]:
    """On-device macOS TTS -> a tight 48k stereo wav. (No cloud voice is available here.)"""
    aiff = work / f"vo{i:02}.aiff"
    subprocess.run(["say", "-v", VOICE, "-r", str(VOICE_RATE), "-o", str(aiff), text], check=True)
    wav = work / f"vo{i:02}.wav"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(aiff),
                    "-af", "aformat=channel_layouts=stereo:sample_rates=48000", str(wav)], check=True)
    dur = float(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                "-of", "default=nw=1:nk=1", str(wav)], capture_output=True, text=True).stdout)
    return wav, dur


def vo_segment(vo: Path | None, seconds: float, work: Path, i: int) -> Path:
    """A wav of exactly `seconds`, with the line (if any) delayed by VO_LEAD."""
    seg = work / f"seg{i:02}.wav"
    if vo is None:
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-t", f"{seconds}",
                        "-i", "anullsrc=channel_layout=stereo:sample_rate=48000", str(seg)], check=True)
    else:
        delay = int(VO_LEAD * 1000)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(vo), "-af",
                        f"adelay={delay}|{delay},apad,aformat=channel_layouts=stereo:sample_rates=48000",
                        "-t", f"{seconds}", str(seg)], check=True)
    return seg


def shot(html: str, target: Path) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as h:
        h.write(html)
        src = Path(h.name)
    subprocess.run([CHROME, "--headless", "--disable-gpu", "--hide-scrollbars",
                    f"--force-device-scale-factor={SCALE}", f"--window-size={W},{H}",
                    f"--screenshot={target}", "--virtual-time-budget=3000", src.as_uri()],
                   check=True, capture_output=True)
    src.unlink()


def prepare_frame(source: str, target: Path) -> None:
    """Cards render directly; product screenshots get matted onto the brand ground."""
    if source.endswith(".png"):
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", source, "-vf",
                        f"scale={W*SCALE}:{H*SCALE}:force_original_aspect_ratio=decrease,"
                        f"pad={W*SCALE}:{H*SCALE}:(ow-iw)/2:(oh-ih)/2:color=0xf6f7f5", str(target)],
                       check=True)
    else:
        shot(source, target)


def scene_clip(frame: Path, seconds: float, zmax: float, out: Path, zoom_in: bool) -> None:
    frames = round(FPS * seconds)
    zr = (zmax - 1.0) / frames
    z = f"min(zoom+{zr:.6f},{zmax})" if zoom_in else f"if(eq(on,0),{zmax},max(zoom-{zr:.6f},1.0))"
    vf = (f"zoompan=z='{z}':d={frames}:x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':s={W}x{H}:fps={FPS},"
          f"fade=t=in:st=0:d={FADE}:color=0xf6f7f5,fade=t=out:st={seconds-FADE:.3f}:d={FADE}:color=0xf6f7f5,"
          f"format=yuv420p")
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-i", str(frame),
                    "-t", f"{seconds}", "-r", str(FPS), "-vf", vf,
                    "-c:v", "libx264", "-preset", "medium", "-crf", "18", str(out)], check=True)


def main() -> None:
    if not Path(CHROME).exists():
        raise SystemExit("Chrome not found")
    if not BGM.exists():
        raise SystemExit(f"BGM not found: {BGM}")
    work = Path(tempfile.mkdtemp())
    clips, vo_segs = [], []
    total = 0.0
    for i, (src, base, zmax, vo_text) in enumerate(scenes()):
        vo, vo_dur = (narration_wav(vo_text, work, i) if (NARRATE and vo_text) else (None, 0.0))
        secs = max(base, VO_LEAD + vo_dur + VO_TAIL) if vo else base
        frame = work / f"f{i:02}.png"
        prepare_frame(src, frame)
        clip = work / f"c{i:02}.mp4"
        scene_clip(frame, secs, zmax, clip, zoom_in=(i % 2 == 0))
        clips.append(clip)
        if NARRATE:
            vo_segs.append(vo_segment(vo, secs, work, i))
        total += secs
        print(f"  scene {i}: {secs:.1f}s (zoom {zmax}){' + VO' if vo else ''}")
    listing = work / "list.txt"
    listing.write_text("".join(f"file '{c}'\n" for c in clips), encoding="utf-8")
    silent = work / "video.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
                    "-i", str(listing), "-c", "copy", str(silent)], check=True)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fade_out_start = max(total - 2.5, 0.1)
    bgm_vol = 0.30 if NARRATE else 0.62
    bgm_chain = (f"[1:a]atrim=0:{total:.3f},afade=t=in:st=0:d=1.5,"
                 f"afade=t=out:st={fade_out_start:.2f}:d=2.5,volume={bgm_vol}[b]")
    if NARRATE:
        vo_list = work / "vo_list.txt"
        vo_list.write_text("".join(f"file '{s}'\n" for s in vo_segs), encoding="utf-8")
        vo_full = work / "vo_full.wav"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
                        "-i", str(vo_list), "-c", "copy", str(vo_full)], check=True)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(silent), "-i", str(BGM), "-i", str(vo_full),
                        "-filter_complex",
                        f"{bgm_chain};[2:a]volume=1.0[v];[b][v]amix=inputs=2:duration=first:dropout_transition=0,volume=1.9[a]",
                        "-map", "0:v", "-map", "[a]", "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
                        "-shortest", "-movflags", "+faststart", str(OUT)], check=True)
    else:
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(silent), "-i", str(BGM),
                        "-filter_complex", f"{bgm_chain.replace('[b]', '[a]')}",
                        "-map", "0:v", "-map", "[a]", "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
                        "-shortest", "-movflags", "+faststart", str(OUT)], check=True)
    tag = f"narrated ({VOICE}, on-device TTS)" if NARRATE else "music only"
    print(f"{OUT.relative_to(ROOT)}  {OUT.stat().st_size // 1024} KiB  ~{total:.1f}s  {tag}  BGM: {BGM.name}")


if __name__ == "__main__":
    main()
