'use strict';
const $ = id => document.getElementById(id);
let token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
history.replaceState(null, '', location.pathname);
let requestId, report = null, running = false, connected = false, deliveryEnabled = false;
let uncertainSend = false;
const text = (tag, value) => { const el = document.createElement(tag); el.textContent = value; return el; };
const invalid = (field, message) => Object.assign(new Error(message), {field});
function feedback(message, state = '') {
  document.querySelectorAll('[aria-invalid="true"]').forEach(el => {el.removeAttribute('aria-invalid'); el.removeAttribute('aria-describedby');});
  $('feedback').textContent = ''; $('status').textContent = '';
  const target = $('documents').hidden ? $('status') : $('feedback');
  target.textContent = message; target.dataset.state = state; return target;
}
const names = {allow:'検査通過', block:'拒否', review:'保留', no_findings:'検出なし（許可ではありません）', not_connected:'未接続'};
const states = {not_executed:'外部送信していません', prevented_in_gateway:'この経路で送信を停止しました', dispatch_pending:'送信結果はまだ未確認です', delivery_unknown:'送信結果は未確認です。接続先と監査ログを確認してください', provider_completed:'接続先から完了応答を受け取りました', demo_received:'ローカルのデモが受信しました（外部送信なし）'};
const coverage = {supported_text_complete:'対応する文字範囲を検査済み（画像・意味の安全性は対象外）', partial:'未検査の内容が残っています', unreadable:'読み取れませんでした'};
const rules = {'DOC-SECRET':'認証情報らしい文字列があります。原本から削除し、検査し直してください。', 'DOC-PII':'個人情報らしい文字列があります。取り扱いを確認してください。', 'DOC-CLASS':'社外秘などの機密表記があります。管理者に分類を確認してください。', 'DOC-INJECTION':'指示を書き換えようとする文字列があります。内容を確認してください。'};
function controls() {
  document.querySelectorAll('button, textarea, select, input').forEach(el => { el.disabled = running; });
  $('save').disabled = running || !report;
  $('send').disabled = running || !connected || !deliveryEnabled || !$('consent').checked || uncertainSend;
}
function invalidate() {
  feedback('');
  requestId = crypto.randomUUID().replaceAll('-', ''); $('request-id').textContent = requestId;
  $('label').value = ''; $('consent').checked = false; report = null;
  $('result').replaceChildren(); $('result-note').textContent = '入力を変更しました。もう一度検査してください。';
  controls();
}
async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {method: body ? 'POST' : 'GET', signal: AbortSignal.timeout(90000),
      headers: {'Authorization': 'Bearer ' + token, ...(body ? {'Content-Type':'application/json'} : {})},
      ...(body ? {body:JSON.stringify(body)} : {})});
  } catch { throw Error(path === '/api/send' ? '送信結果は未確認です。自動再送しません。監査ログと接続先を確認してください。' : '接続が途切れました。入力を保持しています。サーバーの起動を確認して再度検査してください。'); }
  if (response.status === 401) {
    connected = false; $('connection').hidden = false;
    throw Error('認証を再開してください。入力は保持しています。');
  }
  if (!response.ok) {
    if (response.status === 400) throw Error('入力を確認してください。質問は空にせず、対応形式・サイズと分類証明のJSONを確認して再検査できます。');
    throw Error((await response.json()).error || '結果未確認です。');
  }
  return response;
}
async function files() {
  if ($('source').value === 'sample') {
    const value = $('sample-text').value;
    if (!value.trim() || new TextEncoder().encode(value).length > 8192) throw invalid('sample-text', 'サンプル本文は1〜8192バイトで入力してください。');
    return [await (await api('/api/sample', {text:value})).json()];
  }
  const selected = [...$('files').files];
  if (!selected.length || selected.length > 4 || selected.reduce((n,f) => n + f.size, 0) > 16*1024*1024) throw invalid('files', '1〜4件、合計16MiBまでの資料を選択してください。');
  if (selected.some(f => !/\.(xlsx|pptx|pdf)$/i.test(f.name))) throw invalid('files', 'xlsx・pptx・pdfの資料を選択してください。');
  return Promise.all(selected.map(file => new Promise((resolve,reject) => {
    const r = new FileReader(); r.onerror = () => reject(Error('資料を読めません。選択し直してください。'));
    r.onload = () => resolve({format:file.name.split('.').pop().toLowerCase(), base64:r.result.split(',')[1]}); r.readAsDataURL(file);
  })));
}
async function busy(fn) {
  if (running) return;
  running = true; controls(); $('result').setAttribute('aria-busy','true'); feedback('処理しています。まだ完了していません。', 'pending');
  let errorField = null;
  try { const message = await fn(); feedback(message || '確認結果を更新しました。'); }
  catch (e) { errorField = e.field || ( $('documents').hidden ? 'status' : 'feedback' ); feedback(e.message, 'error'); }
  finally {
    running = false; $('result').setAttribute('aria-busy','false'); controls();
    if (!$('connection').hidden) $('token').focus();
    else if (errorField) {
      const field = $(errorField); const detail = field.closest('details');
      if (detail) detail.open = true;
      if (['INPUT','TEXTAREA','SELECT'].includes(field.tagName)) {field.setAttribute('aria-invalid','true'); field.setAttribute('aria-describedby','feedback');}
      field.focus();
    }
  }
}
function renderResult(obj) {
  $('result').replaceChildren(); const box = text('article',''); box.dataset.decision = obj.decision || 'preview';
  box.append(text('h3', names[obj.decision] || 'テキスト案'));
  if (obj.execution_state) box.append(text('p', states[obj.execution_state] || '実行状態：' + obj.execution_state));
  if (obj.classification === 'unknown') box.append(text('p','分類が未確認のため送信は許可されません。結果を保存し、必要なら管理者に相談してください。'));
  for (const [i,d] of (obj.documents || []).entries()) {
    box.append(text('h3', `資料 ${i+1} · ${d.format}`), text('p', `検査範囲：${coverage[d.coverage] || d.coverage} / ${d.units}単位`));
    for (const f of d.findings) box.append(text('p', `${f.rule}：検出記録${f.count}件（同じ箇所の再検査を含む）。${rules[f.rule] || '未対応の内容や構造を含みます。原本と検査範囲を管理者に確認してください。'}`));
    if (!d.findings.length) box.append(text('p','対応する文字範囲での検出はありません。安全性や送信許可の証明ではありません。'));
  }
  if (obj.rules?.length) box.append(text('p','判定根拠：' + obj.rules.join('、')));
  if (obj.output) box.append(text('pre',obj.output));
  if (obj.text !== undefined) { box.append(text('p','原本の代替ではありません。未検査の内容は含まれず、再分類が必要です。'), text('pre',obj.text)); }
  $('result').append(box); $('result').focus();
}
async function operation(path) {
  let label;
  try { label = $('label').value.trim() ? JSON.parse($('label').value) : undefined; }
  catch { throw invalid('label', '分類証明のJSONを確認してください。'); }
  if (!$('question').value.trim()) throw invalid('question', '資料について確認したいことを入力してください。');
  const payload = {question:$('question').value, files:await files(), request_id:requestId, ...(label ? {label} : {}), consent:$('consent').checked};
  report = null; $('result').replaceChildren(); $('result-note').textContent = '検査中です。';
  if (path === '/api/send') uncertainSend = true;
  try {
    const result = await (await api(path,payload)).json();
    renderResult(result);
    if (path === '/api/check') {
      report = result;
      const next = text('p', result.decision === 'block'
        ? '次の操作：検出理由を確認し、原本を修正してから選び直し、再検査してください。記録が必要ならJSONで保存できます。'
        : '次の操作：検査範囲と理由を確認してください。記録が必要ならJSONで保存し、送信の可否は管理者に確認してください。');
      $('result').append(next);
    }
    if (path === '/api/send') uncertainSend = ['dispatch_pending','delivery_unknown'].includes(result.execution_state);
    $('result-note').textContent = report ? '検査完了です。「保留」「拒否」は送信の判定です。外部AIには送信していません。保存するJSONは本文・質問を含みませんが、ファイルのハッシュと検出情報を含みます。' : '送信操作の状態を確認してください。';
  } catch (error) { $('result-note').textContent = '結果を確認できません。入力は保持しています。'; throw error; }
  try { await refresh(); } catch { return '検査・送信の結果を表示しましたが、履歴の更新に失敗しました。'; }
}
function download(blob, name) {
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
}
$('check').onclick = () => busy(() => operation('/api/check'));
$('send').onclick = () => busy(() => operation('/api/send'));
$('save').onclick = () => { if (report) { download(new Blob([JSON.stringify(report,null,2)+'\n'],{type:'application/json'}),'aisecure-report.json'); feedback('ダウンロードを開始しました。保存先でJSONを確認してください。'); } };
$('preview').onclick = () => busy(async () => { report=null; renderResult(await (await api('/api/preview',{files:await files(),consent:true})).json()); $('result-note').textContent='テキスト案を表示しています。検査結果を保存するには再検査してください。'; });
for (const id of ['question','sample-text']) $(id).addEventListener('input',invalidate);
$('files').addEventListener('change',invalidate);
$('source').addEventListener('change',() => { $('sample-fields').hidden = $('source').value !== 'sample'; $('file-fields').hidden = $('source').value !== 'files'; invalidate(); });
$('label').addEventListener('input',() => { feedback(''); report=null; $('result').replaceChildren(); $('result-note').textContent='分類証明を変更しました。再検査してください。'; $('consent').checked=false; controls(); });
$('consent').addEventListener('change',controls);
for (const b of document.querySelectorAll('[data-tab]')) b.onclick = () => {
  feedback('');
  for (const s of document.querySelectorAll('main>section:not(#connection)')) s.hidden = s.id !== b.dataset.tab;
  for (const n of document.querySelectorAll('[data-tab]')) n.removeAttribute('aria-current'); b.setAttribute('aria-current','page');
};
async function refresh() {
  const state = await (await api('/api/state')).json(); connected=true; deliveryEnabled=state.delivery_enabled;
  $('connection').hidden=true;
  $('mode').textContent = state.mode === 'demo' ? 'DEMO · 外部送信なし · 終了時に履歴削除' : state.delivery_enabled ? '管理対象経路' : '管理モード · 外部AI送信無効';
  const dest = state.destination;
  $('destination').textContent = dest.provider === 'openai' ? `送信先：${dest.endpoint} / モデル：${dest.model}。資料と質問を送信します。接続先で料金が発生する場合があります。` : dest.provider === 'demo' ? '送信先：この端末のデモ受信器。外部AI送信・API料金なし。' : '外部AI送信は無効です。検査結果を保存して確認できます。';
  $('demo').hidden=state.mode !== 'demo'; $('cases').replaceChildren();
  for (const c of state.analysis.cases) { const card=text('article',''); card.append(text('span',c.priority+' / '+c.rule),text('h3',c.observed),text('p','可能性：'+c.hypothesis),text('p','未確認：'+c.unknown.join(' ')),text('small','証跡 '+c.evidence_count+'件 / 自動操作なし')); $('cases').append(card); }
  if (!state.analysis.cases.length) $('cases').append(text('p','現在の入力では確認候補がありません。未収集の経路は分析できません。'));
  $('vpn-results').replaceChildren();
  if (!state.vpn) $('vpn-results').append(text('p','VPN台帳・設定の観測は未接続です。'));
  else { for (const f of state.vpn.posture.findings) { const card=text('article',''); card.append(text('h3',`${f.asset_id} · ${f.priority}`),text('p',f.status),text('p',f.reasons.join(' '))); $('vpn-results').append(card); } for (const f of state.vpn.controls) $('vpn-results').append(text('p',f.observed)); }
  $('history').replaceChildren();
  for (const event of state.history) { const card=text('article',''); card.append(text('p',`${new Date(event.at*1000).toLocaleString()} · ${event.kind}`),text('p',`${names[event.decision] || event.decision} / ${states[event.execution_state] || event.execution_state}`),text('small',(event.rules || []).join('、'))); $('history').append(card); }
  if (!state.history.length) $('history').append(text('p','まだ履歴はありません。資料を検査すると本文を含まない記録が残ります。'));
}
$('reconnect').onclick = () => busy(async () => { token=$('token').value.trim(); $('token').value=''; await refresh(); return '再接続しました。入力を保持しています。'; });
$('demo').onclick = () => busy(async () => { await api('/api/demo',{}); await refresh(); });
$('export').onclick = () => busy(async () => { download(await (await api('/api/audit')).blob(),'aisecure-audit.jsonl'); return 'ダウンロードを開始しました。保存先を確認してください。'; });
invalidate(); $('result-note').textContent='まだ検査していません。サンプルをそのまま試せます。';
busy(async () => { await refresh(); return '接続しました。サンプルを編集するか、そのまま検査できます。'; });
