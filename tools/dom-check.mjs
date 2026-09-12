// 画面の実行確認（ブラウザ不要）
//
//     node tools/dom-check.mjs
//
// web/app.js の各画面を Node 上の最小DOMで実行し、実行時エラーが出ないこと、
// 各画面が空にならないこと、検知設定画面に必要な項目が出ることを確認します。
//
// これは「JavaScriptが落ちない」ことの確認であって、ブラウザでの描画・レイアウト・
// CSS・アクセシビリティの検証ではありません。DOM実装は本チェック専用の簡易版です。
// 実ブラウザでの確認は別途必要です（docs/TEST_REPORT.md 参照）。
import { execFileSync } from 'node:child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..') + '/';
const STATE = execFileSync('python3', ['-c', `
import json, tempfile, sys
sys.path.insert(0, ${JSON.stringify(ROOT)})
from aisecure.store import Store
from aisecure.demo import sample
with tempfile.TemporaryDirectory() as d:
    store = Store(d)
    store.ingest(sample(), "demo")
    state = store.state()
    state["llm"] = {"configured": False, "requested_model": None,
                    "default_provider": "deterministic-template", "real_connection_tested": False}
    store.close()
print(json.dumps(state, ensure_ascii=False))
`], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

class El {
  constructor(tag) { this.tagName = tag; this.children = []; this.attrs = {}; this.dataset = {};
    this._text = ''; this.classList = makeClassList(this); this.className = ''; this.style = {}; this.hidden = false; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text; }
  append(...kids) { for (const k of kids) this.children.push(k); }
  replaceChildren(...kids) { this.children = kids; this._text = ''; }
  appendChild(k) { this.children.push(k); return k; }
  remove() {}
  setAttribute(k, v) { this.attrs[k] = v; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener() {}
  get firstChild() { return this.children[0]; }
  get innerText() { return [this._text, ...this.children.map(c => c.innerText || '')].join('\n'); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  querySelectorAll(sel) {
    const out = [];
    const want = sel.split(/\s+/).pop();
    const walk = (n) => { for (const c of n.children) {
      if (want.startsWith('.') ? String(c.className).split(' ').includes(want.slice(1))
        : want.startsWith('[') ? Object.keys(c.dataset).length && want.includes('data-view')
        : c.tagName === want) out.push(c);
      walk(c); } };
    walk(this); return out;
  }
}
function makeClassList(el) { return { toggle(c, on) { const s = new Set(String(el.className).split(' ').filter(Boolean));
  on ? s.add(c) : s.delete(c); el.className = [...s].join(' '); } }; }

const ids = {};
for (const id of ['toast','viewLabel','pageTitle','pageSubtitle','navCount','providerBadge','viewContent',
                  'dataMode','statusBanner','planDialogContent','loginDialog','planDialog','tokenInput',
                  'loginError','loginButton','demoButton','importButton','fileInput']) ids[id] = new El('div');
ids.statusBanner.children = [new El('span'), new El('span'), new El('span')];
for (const d of ['loginDialog','planDialog']) { ids[d].showModal = () => {}; ids[d].close = () => {}; ids[d].open = false; }
const navItems = ['overview','assets','plans','tuning','audit','about'].map(v => { const b = new El('button'); b.dataset.view = v; return b; });
const brand = new El('a');

global.window = { __AI_SECURE_PREVIEW__: JSON.parse(STATE), confirm: () => false };
global.location = { hash: '', pathname: '/' };
global.history = { replaceState() {} };
global.URLSearchParams = class { constructor() {} get() { return ''; } };
global.setTimeout = (fn) => 0; global.clearTimeout = () => {};
global.document = {
  createElement: (t) => new El(t),
  getElementById: (id) => ids[id] || new El('div'),
  querySelectorAll: (sel) => sel.includes('data-view') ? navItems : [],
  querySelector: (sel) => sel === '.brand' ? brand : new El('div'),
  body: new El('body'),
};
global.fetch = async () => { throw new Error('no network in this check'); };

const src = fs.readFileSync(ROOT + 'web/app.js', 'utf8');
const mod = new Function(src + '\nreturn {render, changeView, get view(){return view}};');
const app = mod();

const problems = [];
for (const v of ['overview','assets','plans','tuning','audit','about']) {
  try {
    app.changeView(v);
    const text = ids.viewContent.innerText;
    if (!text.trim()) problems.push(`${v}: empty output`);
    if (v === 'tuning') for (const needle of ['distinct_file_threshold','identity_conditions','aisecure evaluate','設定ハッシュ'])
      if (!text.includes(needle)) problems.push(`tuning: missing "${needle}"`);
    if (v === 'overview' && !text.includes('保守アカウント')) problems.push('overview: correlation card missing');
  } catch (e) { problems.push(`${v}: ${e.message}`); }
}
console.log(problems.length ? 'PROBLEMS:\n' + problems.join('\n') : 'OK: 6画面すべてが実行時エラーなく描画されました');
process.exit(problems.length ? 1 : 0);
