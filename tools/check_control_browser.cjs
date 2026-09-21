/* Real loopback app acceptance. NODE_PATH may point at bundled Playwright. */
const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const out = path.resolve(process.argv[2] || '/tmp/aisecure-control-qa');
fs.mkdirSync(out, {recursive:true});
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aisecure-browser-'));
const port = process.env.AISECURE_TEST_PORT || '18878';
const base = `http://127.0.0.1:${port}`;
let proc;
async function stopServer() {
 const current = proc;
 if (!current || current.exitCode !== null || current.signalCode !== null) return;
 await new Promise(resolve => {
  const timer=setTimeout(() => current.kill('SIGKILL'),5000);
  current.once('exit',() => {clearTimeout(timer);resolve();});
  current.kill('SIGINT');
 });
}
const outcome = {checks:[], environment:{os:os.platform(),release:os.release(),node:process.version}, external_requests:[], errors:[]};
function pass(name) { outcome.checks.push({name,status:'PASS'}); }
let browser;
(async () => {
 try {
  browser = await chromium.launch({...(process.env.AISECURE_CHROMIUM ? {executablePath:process.env.AISECURE_CHROMIUM} : {})});
  outcome.environment.browser=browser.version();
  for (const width of [360,390,768,1440]) {
   await stopServer();
   proc = spawn(process.env.AISECURE_PYTHON || '.venv/bin/python', ['-m','aisecure.control','--demo','--port',port], {env:{...process.env, TMPDIR:temporary}, stdio:['ignore','pipe','pipe']});
  const url = await new Promise((resolve,reject) => {
   let buffer=''; const timer=setTimeout(() => reject(Error('startup timeout')),15000);
   proc.stdout.on('data', chunk => { buffer+=chunk; const match=buffer.match(/Open: (http[^\s]+)/); if(match){clearTimeout(timer);resolve(match[1]);} });
   proc.on('exit', () => reject(Error('server exited')));
  });
  const token = new URL(url).hash.slice(7);

   const context = await browser.newContext({viewport:{width,height:1000}, reducedMotion:'reduce', acceptDownloads:true, ...(width===1440 ? {recordVideo:{dir:path.join(out,'video')}} : {})});
   await context.route('**/*',route => { if (!route.request().url().startsWith(base+'/')) {outcome.external_requests.push(route.request().url()); return route.abort();} return route.continue(); });
   const page = await context.newPage(); page.on('pageerror',error => outcome.errors.push(error.message));
   await page.goto(url); await page.locator('#mode').filter({hasText:'DEMO'}).waitFor();
   assert.equal(await page.evaluate(() => location.hash),'');
   assert(!/結果を更新/.test(await page.locator('#feedback').innerText()));
   await page.screenshot({path:path.join(out,`initial-${width}.png`),fullPage:true});
   assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length),0);
   await page.locator('#check').focus();
   assert.notEqual(await page.locator('#check').evaluate(el => getComputedStyle(el).outlineStyle),'none');
   await page.keyboard.press('Enter');
   await page.locator('#result').filter({hasText:'DOC-CLASS'}).waitFor();
   assert.match(await page.locator('#result').innerText(),/外部送信していません/);
   assert.match(await page.locator('#result').innerText(),/保留/);
   assert.equal(await page.evaluate(() => document.activeElement.id),'result');
   const response = await page.request.get(base+'/api/audit',{headers:{Authorization:'Bearer '+token}});
   const audit = (await response.text()).trim().split('\n').map(JSON.parse);
   assert.equal(audit.at(-1).kind,'document_inspection');
   assert(await page.locator('#save').evaluate(el => Boolean(el.previousElementSibling && el.previousElementSibling.id === 'result')));
   const downloadWait=page.waitForEvent('download'); await page.locator('#save').click();
   const download=await downloadWait; const dest=path.join(out,`report-${width}.json`); await download.saveAs(dest);
   const report=JSON.parse(fs.readFileSync(dest));
   assert.equal(report.request_id,audit.at(-1).request_id); assert.equal(report.execution_state,'not_executed');
   assert.equal(report.documents[0].input_sha256.length,64); assert(!JSON.stringify(report).includes(token));
   pass(`first success, keyboard, saved report and audit match at ${width}px`);
   await page.screenshot({path:path.join(out,`control-${width}.png`),fullPage:true});
   assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
   await page.locator('#sample-text').fill('api_key=synthetic-secret-value');
   assert(await page.locator('#save').isDisabled()); assert.equal(await page.locator('#result').innerText(),'');
   await page.locator('#check').click(); await page.locator('#result').filter({hasText:'DOC-SECRET'}).waitFor();
   assert.match(await page.locator('#result').innerText(),/拒否/); pass(`secret blocks and edits invalidate report at ${width}px`);
   await page.locator('#question').fill(''); await page.locator('#check').click();
   await page.locator('#feedback').filter({hasText:'入力してください'}).waitFor();
   assert.equal(await page.locator('#sample-text').inputValue(),'api_key=synthetic-secret-value');
   assert.equal(await page.evaluate(() => document.activeElement.id),'question');
   assert.equal(await page.locator('#question').getAttribute('aria-invalid'),'true');
   assert.equal(await page.locator('#question').getAttribute('aria-describedby'),'feedback');
   await page.screenshot({path:path.join(out,`error-${width}.png`),fullPage:true});
   await page.locator('#question').fill('この資料を確認してください。');
   assert.equal(await page.locator('#feedback').innerText(),'');
   await page.route('**/api/check',async route => { await new Promise(resolve => setTimeout(resolve,300)); await route.continue(); });
   await page.locator('#check').click(); assert(await page.locator('#question').isDisabled()); assert.equal(await page.locator('#result').getAttribute('aria-busy'),'true');
   await page.locator('#result').filter({hasText:'DOC-SECRET'}).waitFor(); await page.unroute('**/api/check');
   pass(`invalid input recovery and in-flight edit protection at ${width}px`);
   await page.route('**/api/check',route => route.abort());
   await page.locator('#check').click(); await page.locator('#feedback').filter({hasText:'接続が途切れました'}).waitFor();
   await page.unroute('**/api/check'); await page.locator('#check').click(); await page.locator('#result').filter({hasText:'DOC-SECRET'}).waitFor();
   pass(`network failure retains input and explicit recheck works at ${width}px`);
   await page.locator('#sample-text').fill(''); await page.locator('#check').click();
   await page.locator('#feedback').filter({hasText:'サンプル本文'}).waitFor();
   await page.locator('#source').selectOption('files');
   assert.equal(await page.locator('#feedback').innerText(),'');
   await page.locator('#files').setInputFiles({name:'broken.pdf',mimeType:'application/pdf',buffer:Buffer.from('not a pdf')});
   await page.locator('#check').click(); await page.locator('#result').filter({hasText:'読み取れませんでした'}).waitFor();
   pass(`malformed document is not treated as no findings at ${width}px`);
   await page.reload(); await page.locator('#connection').waitFor();
   await page.locator('#question').fill('認証後も残す入力');
   await page.locator('#token').fill(token); await page.locator('#reconnect').click();
   await page.locator('#connection').waitFor({state:'hidden'}); assert.equal(await page.locator('#question').inputValue(),'認証後も残す入力');
   pass(`reload authentication recovery at ${width}px`);
   await page.locator('#sample-text').fill('日本語の長文です。'.repeat(200));
   let checksDuringComposition=0;
   const observe=request => {if(request.url().endsWith('/api/check')) checksDuringComposition++;};
   page.on('request',observe);
   await page.locator('#sample-text').dispatchEvent('compositionstart',{data:'編'});
   await page.locator('#sample-text').dispatchEvent('keydown',{key:'Enter',isComposing:true});
   await page.locator('#sample-text').dispatchEvent('compositionend',{data:'編集'});
   assert.equal(checksDuringComposition,0); page.off('request',observe);
   await page.locator('#check').click(); await page.locator('#result').filter({hasText:'保留'}).waitFor();
   assert(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches));
   await page.evaluate(() => document.documentElement.style.zoom='2');
   assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
   await page.screenshot({path:path.join(out,`control-${width}-css-200.png`),fullPage:true});
   pass(`long Japanese, synthetic composition, reduced motion, CSS 200% at ${width}px`);
   const video=page.video();
   await context.close();
   if(video) { await video.saveAs(path.join(out,'primary-flow.webm')); await video.delete(); }
  }
  assert.equal(outcome.external_requests.length,0); assert.deepEqual(outcome.errors,[]);
  pass('no external browser requests or JS errors');
 } catch(error) { outcome.checks.push({name:error.stack,status:'FAIL'});process.exitCode=1; }
 finally {
  if(browser) await browser.close();
  await stopServer();
  const leftovers=fs.readdirSync(temporary).filter(name => name.startsWith('aisecure-control-demo-'));
  outcome.checks.push({name:'demo state removed on shutdown',status:leftovers.length?'FAIL':'PASS'});
  if(leftovers.length)process.exitCode=1;
  outcome.checks.push({name:'native Japanese IME, browser toolbar 200% zoom, real beginner and competitor comparison',status:'BLOCKED',reason:'Synthetic composition/CSS zoom are not native OS input or human evaluation.'});
  fs.writeFileSync(path.join(out,'browser.json'),JSON.stringify(outcome,null,2)+'\n');
  console.log(JSON.stringify(outcome,null,2));
  fs.rmSync(temporary,{recursive:true,force:true});
 }
})();
