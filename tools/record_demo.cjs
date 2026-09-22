/* Record the real control workbench performing a real inspection.

   Starts `python -m aisecure.control --demo`, drives the actual UI, and saves
   the raw screen recording. Nothing here is mocked: the verdict in the video is
   produced by the shipped Scanner. See docs/site/VIDEO.md for the storyboard.

   NODE_PATH=<playwright> node tools/record_demo.cjs docs/media/demo-raw */
const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const out = path.resolve(process.argv[2] || 'docs/media/demo-raw');
const port = process.env.AISECURE_DEMO_PORT || '18979';
const python = process.env.AISECURE_PYTHON || '.venv/bin/python';
// Synthetic only. Never a real document, address, credential or destination.
const SAMPLE = '社外秘：次期モデルの原価内訳と取引先別の掛け率をまとめたメモです。これは架空のサンプルです。';

function waitForPort(deadlineMs) {
  const deadline = Date.now() + deadlineMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = net.connect({ host: '127.0.0.1', port: Number(port) });
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) reject(Error('server never accepted a connection'));
        else setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

(async () => {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aisecure-demo-'));
  const server = spawn(python, ['-m', 'aisecure.control', '--demo', '--port', port],
    { env: { ...process.env, TMPDIR: temporary }, stdio: ['ignore', 'pipe', 'pipe'] });

  const url = await new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(Error('startup timeout')), 20000);
    server.stdout.on('data', chunk => {
      buffer += chunk;
      const match = buffer.match(/Open: (http[^\s]+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
    server.on('exit', () => reject(Error('server exited')));
  });
  await waitForPort(20000);

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 810 },
    deviceScaleFactor: 2,
    reducedMotion: 'no-preference',
    acceptDownloads: true,
    recordVideo: { dir: out, size: { width: 1440, height: 810 } },
  });
  const page = await context.newPage();
  const marks = [];
  const boxes = {};
  const mark = name => marks.push({ name, at: Date.now() });

  await page.goto(url, { waitUntil: 'load' });
  await page.locator('#mode').filter({ hasText: 'DEMO' }).waitFor();
  // The startup token must never appear in a published frame.
  await page.evaluate(() => history.replaceState(null, '', location.pathname));
  const started = Date.now();
  mark('ready');

  // 0–3s: the problem is on screen — a confidential draft about to be pasted.
  await page.locator('#sample-text').fill('');
  await page.waitForTimeout(1600);

  // 3–8s: type the real sample into the real field.
  await page.locator('#sample-text').click();
  await page.locator('#sample-text').type(SAMPLE, { delay: 72 });
  mark('typed');
  await page.waitForTimeout(1500);
  // The vertical cut re-frames onto one column at a time, so record where the
  // columns actually are instead of guessing crop coordinates later.
  boxes.input = await page.locator('.input-panel').boundingBox();

  // 8–13s: run the actual inspection. No wait is shortened in the edit.
  await page.locator('#check').scrollIntoViewIfNeeded();
  await page.waitForTimeout(900);
  await page.locator('#check').click();
  mark('check_clicked');
  await page.locator('#result').filter({ hasText: 'DOC-CLASS' }).waitFor({ timeout: 30000 });
  mark('verdict_shown');
  await page.waitForTimeout(5200);

  // 13–22s: read the verdict, its rule and its coverage.
  await page.locator('#result').scrollIntoViewIfNeeded();
  await page.waitForTimeout(1200);
  boxes.result = await page.locator('.outcome-panel').boundingBox();
  await page.waitForTimeout(3000);

  // 22–28s: keep the report.
  const downloadWait = page.waitForEvent('download');
  await page.locator('#save').click();
  const download = await downloadWait;
  const saved = path.join(out, 'report.json');
  await download.saveAs(saved);
  mark('report_saved');
  await page.waitForTimeout(3600);

  const verdictText = await page.locator('#result').innerText();
  await context.close();
  await browser.close();
  server.kill('SIGINT');

  const video = fs.readdirSync(out).find(f => f.endsWith('.webm'));
  fs.renameSync(path.join(out, video), path.join(out, 'raw.webm'));
  fs.writeFileSync(path.join(out, 'marks.json'), JSON.stringify({
    started, marks: marks.map(m => ({ name: m.name, t: +((m.at - started) / 1000).toFixed(2) })),
    sample: SAMPLE, verdict: verdictText.slice(0, 600), boxes, viewport: { width: 1440, height: 810 },
    note: 'Real local server, real Scanner verdict, no mock and no time compression.',
  }, null, 2));
  console.log(JSON.stringify(marks.map(m => `${m.name} @ ${((m.at - started) / 1000).toFixed(2)}s`), null, 2));
  console.log(verdictText.slice(0, 300));
})();
