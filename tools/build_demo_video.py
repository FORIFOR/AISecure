"""Edit the recorded demo into a site cut and a vertical cut.

    NODE_PATH=<playwright> node tools/record_demo.cjs docs/media/demo-raw
    NODE_PATH=<playwright> node tools/make_endcards.cjs docs/media/demo-raw
    python -m tools.build_demo_video docs/media/demo-raw docs/media

Both cuts come from the same recording (`raw.webm`). The inspection is never
sped up or slowed down: the holds that let a viewer read were recorded, not
added in the edit.

The vertical cut is not a centre crop. It re-frames onto one column of the app
at a time — the input column while the text is typed, the verdict column once
the result is there — using the panel coordinates the recorder measured, and it
puts the captions below the frame instead of over the UI.

Captions are PNG overlays rendered by tools/make_endcards.cjs, because this
ffmpeg build has no freetype and browser text layout sets Japanese correctly.

See docs/site/VIDEO.md for the storyboard and the rules this must not break.
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path

# (start, end, overlay stem) against the raw recording.
CAPTIONS = [(0.4, 4.9, 'cap0'), (5.2, 7.5, 'cap1'), (7.9, 12.6, 'cap2'),
            (12.9, 16.9, 'cap3'), (17.3, 23.9, 'cap4')]
# The verdict appeared 0.19s after the click. That is the real measurement.
SPEED = (8.0, 12.2, 'speed')
FPS = 25
# zoompan counts output frames; it has no seconds clock.
ZOOM_CLOCK = f'(on/{FPS})'
# Where the vertical cut switches from the input column to the verdict column.
VERTICAL_IN, VERTICAL_SWITCH, VERTICAL_OUT = 2.0, 7.8, 22.6
BAND = (600, 760)   # crop size in recorded CSS pixels
BAND_SCALE = 2      # the source is pre-scaled 2x before cropping


def run(args: list[str]) -> None:
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr[-2500:])
        raise SystemExit(f'ffmpeg failed: {" ".join(args[:8])} …')


def ramp(t0: float, t1: float, clock: str = 't') -> str:
    """0 before t0, 1 after t1, linear between, in ffmpeg's expression syntax."""
    return f'clip(({clock}-{t0})/{round(t1 - t0, 3)},0,1)'


def rebase(window: tuple[float, float], items) -> list[tuple[float, float, str]]:
    """Shift caption times into a segment's own timeline, dropping the rest."""
    start, end = window
    out = []
    for t0, t1, stem in items:
        if t1 <= start or t0 >= end:
            continue
        out.append((max(0.0, round(t0 - start, 2)), round(min(t1, end) - start, 2), stem))
    return out


def overlay_graph(raw_dir: Path, prefix: str, timed) -> tuple[list[str], str]:
    inputs, steps, stream = [], [], '[base]'
    for index, (t0, t1, stem) in enumerate(timed):
        inputs += ['-i', str(raw_dir / f'{prefix}-{stem}.png')]
        nxt = f'[o{index}]'
        steps.append(f"{stream}[{index + 1}:v]overlay=0:0:enable='between(t,{t0},{t1})'{nxt}")
        stream = nxt
    inputs += ['-i', str(raw_dir / f'{prefix}-badge.png')]
    steps.append(f'{stream}[{len(timed) + 1}:v]overlay=0:0[out]')
    return inputs, ';'.join(steps)


def encode_segment(raw: Path, raw_dir: Path, dest: Path, *, prefix: str, chain: list[str],
                   timed, window: tuple[float, float] | None) -> None:
    inputs, steps = overlay_graph(raw_dir, prefix, timed)
    graph = ','.join(chain) + '[base];' + steps
    trim = ['-ss', str(window[0]), '-to', str(window[1])] if window else []
    run(['ffmpeg', '-y', *trim, '-i', str(raw), *inputs,
         '-filter_complex', graph, '-map', '[out]', '-r', str(FPS),
         '-c:v', 'libx264', '-preset', 'slow', '-crf', '20',
         '-pix_fmt', 'yuv420p', '-an', str(dest)])


def encode_card(card: Path, dest: Path, size: str, seconds: float) -> None:
    run(['ffmpeg', '-y', '-loop', '1', '-t', str(seconds), '-i', str(card),
         '-vf', f'scale={size},format=yuv420p', '-r', str(FPS),
         '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-an', str(dest)])


def concat(parts: list[Path], listing: Path, dest: Path) -> None:
    # concat resolves entries against the list file, so write absolute paths.
    listing.write_text(''.join(f"file '{p.resolve()}'\n" for p in parts), encoding='utf-8')
    run(['ffmpeg', '-y', '-f', 'concat', '-safe', '0', '-i', str(listing),
         '-c', 'copy', '-movflags', '+faststart', str(dest)])


def column_crop(box: dict, viewport: dict) -> str:
    """A crop centred on one panel, clamped inside the recorded frame."""
    width, height = BAND
    centre = box['x'] + box['width'] / 2
    x = min(max(centre - width / 2, 0), viewport['width'] - width)
    y = min(max(box['y'], 0), max(viewport['height'] - height, 0))
    return (f'crop={width * BAND_SCALE}:{height * BAND_SCALE}:'
            f'{round(x * BAND_SCALE)}:{round(y * BAND_SCALE)}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw_dir', type=Path)
    parser.add_argument('out_dir', type=Path)
    args = parser.parse_args(argv)
    raw = args.raw_dir / 'raw.webm'
    marks_path = args.raw_dir / 'marks.json'
    if not raw.exists() or not marks_path.exists():
        raise SystemExit(f'{raw} がありません。先に tools/record_demo.cjs を実行してください。')
    if not (args.raw_dir / 'h-cap0.png').exists():
        raise SystemExit('字幕PNGがありません。先に tools/make_endcards.cjs を実行してください。')
    marks = json.loads(marks_path.read_text(encoding='utf-8'))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    work = args.raw_dir / 'work'
    work.mkdir(exist_ok=True)

    # Site cut: a shallow push toward the verdict panel. A deeper zoom clipped words.
    zin, zout = ramp(7.7, 9.2, ZOOM_CLOCK), ramp(16.4, 17.9, ZOOM_CLOCK)
    desktop_body = work / 'desktop-body.mp4'
    encode_segment(raw, args.raw_dir, desktop_body, prefix='h', timed=[*CAPTIONS, SPEED],
                   window=None, chain=[
                       'scale=2880:1620:flags=lanczos',
                       (f"zoompan=z='1+0.12*{zin}-0.12*{zout}'"
                        f":x='clip((0.5+0.11*{zin}-0.11*{zout})*iw-(iw/zoom)/2,0,iw-iw/zoom)'"
                        f":y='clip(0.5*ih-(ih/zoom)/2,0,ih-ih/zoom)':d=1:s=1920x1080:fps={FPS}"),
                   ])
    desktop_tail = work / 'desktop-tail.mp4'
    encode_card(args.raw_dir / 'endcard-16x9.png', desktop_tail, '1920:1080', 3.6)
    desktop = args.out_dir / 'demo-desktop.mp4'
    concat([desktop_body, desktop_tail], work / 'desktop.txt', desktop)

    # Phone cut: hold on the column that matters, captions under the frame.
    viewport = marks['viewport']
    pad = 'pad=1080:1920:0:230:0x07080b'
    segments = []
    for name, window, box in [
        ('a', (VERTICAL_IN, VERTICAL_SWITCH), marks['boxes']['input']),
        ('b', (VERTICAL_SWITCH, VERTICAL_OUT), marks['boxes']['result']),
    ]:
        dest = work / f'vertical-{name}.mp4'
        encode_segment(raw, args.raw_dir, dest, prefix='v',
                       timed=rebase(window, [*CAPTIONS, SPEED]), window=window,
                       chain=['scale=2880:1620:flags=lanczos', column_crop(box, viewport),
                              'scale=1080:1368:flags=lanczos', pad])
        segments.append(dest)
    vertical_tail = work / 'vertical-tail.mp4'
    encode_card(args.raw_dir / 'endcard-9x16.png', vertical_tail, '1080:1920', 3.0)
    vertical = args.out_dir / 'demo-vertical.mp4'
    concat([*segments, vertical_tail], work / 'vertical.txt', vertical)

    poster = args.out_dir / 'demo-poster.jpg'
    run(['ffmpeg', '-y', '-ss', '14.0', '-i', str(desktop), '-frames:v', '1',
         '-q:v', '4', str(poster)])

    report = {'source': 'docs/media/demo-raw/raw.webm — real app, no time compression'}
    for path in [desktop, vertical]:
        data = json.loads(subprocess.run(
            ['ffprobe', '-v', 'error', '-show_entries', 'format=duration,size',
             '-show_entries', 'stream=width,height', '-of', 'json', str(path)],
            capture_output=True, text=True).stdout)
        report[path.name] = {
            'seconds': round(float(data['format']['duration']), 2),
            'kib': int(data['format']['size']) // 1024,
            'size': f"{data['streams'][0]['width']}x{data['streams'][0]['height']}",
        }
    report['poster_kib'] = poster.stat().st_size // 1024
    (args.out_dir / 'demo-build.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
