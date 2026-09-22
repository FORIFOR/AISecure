/* Render the demo's end cards and caption overlays with the same tokens as the
   public site, so the video stays in the product's own design.

   Captions are rendered here rather than by ffmpeg's drawtext: this build of
   ffmpeg has no freetype, and browser text layout gives correct Japanese
   typography. Each caption is a full-frame transparent PNG, composited later.

   NODE_PATH=<playwright> node tools/make_endcards.cjs docs/media/demo-raw */
const { chromium } = require('playwright');
const path = require('node:path');
const fs = require('node:fs');

const out = path.resolve(process.argv[2] || 'docs/media/demo-raw');

const TOKENS = `--paper:#07080b;--ink:#eef1f6;--muted:#98a1b2;--green:#54e0b2;--edge:#272c38;--raised:#11141b`;
const FONT = `"Hiragino Sans","Noto Sans JP",system-ui,sans-serif`;

// Text is kept here so the storyboard, the recorder and the build agree.
const CAPTIONS = [
  ['cap0', '社外秘の資料を、AIに貼ろうとしている'],
  ['cap1', '送る前に、この端末だけで検査する'],
  ['cap2', '保留。外部送信していません'],
  ['cap3', '理由・根拠ルール・検査範囲まで出る'],
  ['cap4', '判定はJSONで手元に残る'],
];
const SPEED = '検査 0.19秒（実時間・早送りなし）';
const BADGE = '実アプリの画面収録 · デモモード · 合成サンプル';

const endCard = (width, height, vertical) => `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<style>
  :root{${TOKENS}}
  *{box-sizing:border-box;margin:0}
  html,body{width:${width}px;height:${height}px}
  body{background:var(--paper);color:var(--ink);display:grid;place-items:center;font-family:${FONT};
    background-image:radial-gradient(rgba(148,163,184,.13) 1px,transparent 1px);background-size:${vertical ? 30 : 34}px ${vertical ? 30 : 34}px}
  .card{width:${vertical ? 90 : 72}%;display:flex;flex-direction:column;gap:${vertical ? 44 : 34}px;
    align-items:${vertical ? 'center' : 'flex-start'};text-align:${vertical ? 'center' : 'left'}}
  .eyebrow{font:700 ${vertical ? 30 : 26}px/1.3 ui-monospace,monospace;letter-spacing:.16em;color:var(--green)}
  h1{font-size:${vertical ? 76 : 82}px;line-height:1.16;letter-spacing:-.04em;font-weight:700}
  h1 em{font-style:normal;color:var(--green)}
  pre{background:var(--raised);border:1px solid var(--edge);border-radius:18px;
    padding:${vertical ? '38px 34px' : '34px 40px'};font:${vertical ? 34 : 32}px/1.85 ui-monospace,monospace;color:#b7f0d9;text-align:left;width:100%}
  .foot{font-size:${vertical ? 32 : 30}px;color:var(--muted);line-height:1.6}
</style></head><body>
<div class="card">
  <p class="eyebrow">AISECURE · MIT · ローカル完結</p>
  <h1>3分で、<em>手元で</em>試せる。</h1>
  <pre>pip install '.[control]'
python -m aisecure.control --demo</pre>
  <p class="foot">github.com/FORIFOR/AISecure<br>見逃し率0.30も公開しています</p>
</div></body></html>`;

/* One caption, positioned where it belongs in the finished frame. */
const overlay = (width, height, { text, size, bottom, weight = 600, muted = false }) =>
  `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<style>
  :root{${TOKENS}}
  *{box-sizing:border-box;margin:0}
  html,body{width:${width}px;height:${height}px;background:transparent}
  body{display:flex;align-items:flex-end;justify-content:center;font-family:${FONT}}
  .line{margin-bottom:${bottom}px;max-width:${Math.round(width * 0.88)}px;
    background:rgba(7,8,11,.86);border:1px solid var(--edge);border-radius:16px;
    padding:${Math.round(size * 0.46)}px ${Math.round(size * 0.78)}px;
    font-size:${size}px;font-weight:${weight};line-height:1.45;letter-spacing:-.01em;
    color:${muted ? 'var(--muted)' : 'var(--ink)'};text-align:center;
    backdrop-filter:blur(6px)}
</style></head><body><div class="line">${text}</div></body></html>`;

/* The honesty badge stays on screen for the whole cut. */
const badge = (width, height, vertical) =>
  `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<style>
  :root{${TOKENS}}
  *{box-sizing:border-box;margin:0}
  html,body{width:${width}px;height:${height}px;background:transparent}
  body{display:flex;align-items:flex-start;justify-content:${vertical ? 'center' : 'flex-start'};font-family:${FONT}}
  .tag{margin:${vertical ? '92px 0 0' : '44px 0 0 48px'};background:rgba(7,8,11,.62);
    border:1px solid var(--edge);border-radius:999px;padding:${vertical ? '16px 30px' : '12px 24px'};
    font-size:${vertical ? 30 : 26}px;color:var(--muted);letter-spacing:.01em}
</style></head><body><div class="tag">${BADGE}</div></body></html>`;

(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const shoot = async (name, html, width, height) => {
    const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
    await page.setContent(html, { waitUntil: 'load' });
    await page.screenshot({ path: `${out}/${name}.png`, omitBackground: true });
    await page.close();
  };

  await shoot('endcard-16x9', endCard(1920, 1080, false), 1920, 1080);
  await shoot('endcard-9x16', endCard(1080, 1920, true), 1080, 1920);

  for (const [name, text] of CAPTIONS) {
    await shoot(`h-${name}`, overlay(1920, 1080, { text, size: 50, bottom: 96 }), 1920, 1080);
    await shoot(`v-${name}`, overlay(1080, 1920, { text, size: 52, bottom: 170 }), 1080, 1920);
  }
  await shoot('h-speed', overlay(1920, 1080, { text: SPEED, size: 32, bottom: 218, weight: 500, muted: true }), 1920, 1080);
  await shoot('v-speed', overlay(1080, 1920, { text: SPEED, size: 34, bottom: 60, weight: 500, muted: true }), 1080, 1920);
  await shoot('h-badge', badge(1920, 1080, false), 1920, 1080);
  await shoot('v-badge', badge(1080, 1920, true), 1080, 1920);

  await browser.close();
  console.log('end cards and caption overlays written to ' + out);
})();
