'use strict';
const PREVIEW = window.__AI_SECURE_PREVIEW__ || null;
const EVIDENCE_SHOWN = 200;
let token = '', state = null, view = 'overview', selectedId = null, currentPlan = null, toastTimer;
const $ = (id) => document.getElementById(id);
const VIEW_LABELS = {overview:'概要',assets:'資産と露出',plans:'対応計画',tuning:'検知設定',audit:'監査記録',about:'設計と安全性'};
const HEADINGS = {overview:['対応すべき理由を、ひとつの画面に。','外部公開・特権・データアクセスをつないで、次の一手を判断する。'],assets:['スコアの向こうに、実際のリスクを。','公開範囲、特権、機密情報への到達性。未確認の情報は、安全と扱いません。'],plans:['何を変えるか。何が止まるか。','根拠と業務影響を確認し、人が承認する。初期版はシミュレーション専用です。'],tuning:['閾値は、正常な業務で測ってから決める。','大量参照の閾値と特権ログインの条件は変更できます。変更内容は監査記録に残ります。'],audit:['判断と承認の経緯を、残す。','鍵付きハッシュチェーンで記録の整合性を確認。外部チェックポイントは別途保管してください。'],about:['AIに任せること。任せないこと。','小さな責務を、明示的な契約でつなぐ。判断・説明・操作の権限を分離します。']};

function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; }
function add(parent, ...children) { children.filter(Boolean).forEach(c => parent.append(c)); return parent; }
function pill(text, cls='neutral') { return el('span','pill '+cls,text); }
function button(text, cls, fn, disabled=false) { const b=el('button','button '+cls,text); b.type='button'; b.disabled=disabled; b.addEventListener('click',fn); return b; }
function notify(message,error=false) { clearTimeout(toastTimer); const n=$('toast'); n.textContent=message; n.classList.toggle('error',error); n.hidden=false; toastTimer=setTimeout(()=>n.hidden=true,7000); }
function date(value) { return value ? new Date(value).toLocaleString('ja-JP',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—'; }
function count(n) { return Number(n || 0).toLocaleString('ja-JP'); }
function auditAction(action) { return ({'snapshot.ingested':'スナップショットを読み込み','plan.proposed':'対応計画を作成','plan.approved':'管理者がシミュレーションを承認','plan.simulated':'シミュレーション完了（実操作なし）','finding.explained':'根拠の説明を生成','report.exported':'検証レポートを書き出し','rules.configured':'検知設定を記録'})[action] || action; }
async function api(path,body,rawBody=false) {
  if(PREVIEW) throw new Error('閲覧用プレビューです。操作はZIP内のローカルアプリで実行してください。');
  const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'Authorization':'Bearer '+token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:rawBody?body:JSON.stringify(body)}),credentials:'omit',cache:'no-store'});
  const data=await response.json();
  if(!response.ok) { if(response.status===401 && !$('loginDialog').open) $('loginDialog').showModal(); throw new Error(data.error || '要求に失敗しました。'); }
  return data;
}
async function run(fn) { try { await fn(); } catch(e) { notify(e.message || '処理に失敗しました。',true); } }
async function refresh() { state=PREVIEW || await api('/api/state'); render(); }
function changeView(next) { view=next; render(); }
function getSelected() { return state.findings.find(f=>f.id===selectedId) || state.findings[0] || null; }
function section(title,right) { return add(el('div','section-title'),el('h2','',title),typeof right==='string'?el('small','',right):right); }
function stat(label,value,caption,unit='',emphasis=false) { return add(el('div','stat'+(emphasis?' emphasis':'')),el('div','stat-label',label),add(el('div','stat-value'),el('span','',value),el('small','',unit)),el('div','stat-caption',caption)); }
function empty(title,text) { return add(el('section','empty-state'),el('p','eyebrow','START WITH EVIDENCE'),el('h2','',title),el('p','',text),button('架空データで体験する','primary',()=>run(loadDemo),!!PREVIEW)); }
function render() {
  if(!state) return;
  $('viewLabel').textContent=VIEW_LABELS[view]; $('pageTitle').textContent=HEADINGS[view][0]; $('pageSubtitle').textContent=HEADINGS[view][1];
  document.querySelectorAll('[data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===view); if(b.dataset.view===view)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
  const mode=state.snapshot?.source_mode;
  $('dataMode').textContent=PREVIEW?'閲覧プレビュー':mode==='demo'?'架空データ':mode==='imported'?'手動入力':'未接続';
  $('statusBanner').children[1].textContent=PREVIEW?'架空ログによる閲覧用プレビューです。操作はZIP内のローカルアプリで実行できます。':mode==='demo'?'架空ログの検証です。GSSの実ログではありません。実環境の常時監視・遮断は行いません。':'手動スナップショット解析です。ログの真正性と現在の状態は別途確認してください。実環境の常時監視・遮断は行いません。';
  $('navCount').textContent=state.findings.filter(f=>f.priority==='P1').length;
  $('providerBadge').textContent=state.llm?.configured?'ローカルLLM設定済み / 接続未確認':'ルール検知 / LLM未使用';
  const container=$('viewContent'); container.replaceChildren();
  if(!state.audit.valid) add(container,add(el('div','caution'),el('strong','','監査記録に不整合があります。対応操作を停止し、保存データを確認してください。')));
  if(view==='about'){renderAbout(container);return;}
  if(view==='tuning'){renderTuning(container);return;}
  if(!state.snapshot){add(container,empty('まだ、分析するデータがありません。','最初は安全な架空データで、根拠の確認から対応計画の承認までを体験できます。外部サービスへの接続は不要です。'));return;}
  ({overview:renderOverview,assets:renderAssets,plans:renderPlans,audit:renderAudit})[view](container);
}
function renderOverview(root) {
  const findings=state.findings, selected=getSelected(), correlations=findings.filter(f=>f.kind==='correlation');
  add(root,add(el('div','stats-grid'),stat('最優先の対応候補',count(findings.filter(f=>f.priority==='P1').length),'P1は調査・対応の優先順位です','件',true),stat('関連付けた事案',count(correlations.length),'侵害の断定ではありません','件'),stat('解析済みイベント',count(state.snapshot.event_counts.total),'重複IDを除いた入力件数','件'),stat('台帳に登録された資産',count(state.snapshot.assets.length),'実環境へ自動接続はしていません','台')));
  add(root,section('いま、確認すること','スナップショット時刻 '+date(state.snapshot.as_of)));
  if(!selected){add(root,empty('現在のルールでは、検知候補がありません。','未検知は安全を保証しません。入力範囲、欠損、収集状況、ルールの適用範囲を確認してください。'));return;}
  const grid=el('div','content-grid'), card=el('article','card incident-card'), inner=el('div','card-pad');
  add(inner,add(el('div','incident-topline'),pill(selected.priority,selected.priority==='P1'?'danger':'warn'),pill(selected.kind==='correlation'?'相関候補 / 要確認':'対応候補 / 要確認','neutral'),el('span','mono muted',selected.rule+' · '+selected.id)));
  const isCorrelation=selected.kind==='correlation';
  add(inner,el('h2','incident-title',isCorrelation?'保守アカウントに、関連する3つの兆候。':selected.title),el('p','incident-description',isCorrelation?'公開された接続機器、条件に問題がある特権ログイン、短時間の大量参照。同じユーザーとセッションに属するログを、ひとつの事案として提示します。':selected.reasons.join(' ')));
  if(isCorrelation){
    const path=el('div','path-grid');
    const steps=[['01','外部公開 + 未修正',selected.gateway_id],['02','特権ログイン','非管理端末 / 未承認'],['03','大量ファイル参照',count(selected.distinct_files)+'個 / 機密 '+count(selected.sensitive_files)+'個']];
    steps.forEach((s,i)=>{if(i)add(path,el('div','path-arrow','→'));add(path,add(el('div','path-node'),el('span','path-number',s[0]),el('strong','',s[1]),el('small','',s[2])));});add(inner,path);
  }
  add(inner,el('div','caution','「関連している」と「侵害・漏えいが確定した」は別です。外部送信の証拠は、この入力にはありません。'));
  add(inner,add(el('div','card-actions'),el('small','muted','実操作なし · 人による承認が必要'),button('対応計画を確認する →','primary',()=>run(()=>openPlan(selected)),!!PREVIEW || !state.audit.valid)));
  const details=el('details','evidence-box');const shown=selected.evidence_ids.slice(0,EVIDENCE_SHOWN);const rest=selected.evidence_ids.length-shown.length;add(details,el('summary','',`根拠のイベントIDを見る（${count(selected.evidence_ids.length)}件）`),el('pre','evidence-ids',shown.join('\n')+(rest>0?`\n… 他${count(rest)}件（書き出しに全件含まれます）`:'')));add(inner,details);add(card,inner);add(grid,card);
  const brief=add(el('aside','card brief-card'),el('div','card-pad')); const body=brief.firstChild;
  add(body,add(el('div','brief-heading'),el('span','brief-mark','⌁'),el('h3','','判断の根拠'),pill('ルール説明 / LLM未使用','green')));
  const fact=(label,text,cls='')=>add(el('div','fact-block'),el('div','fact-label '+cls,label),el('p','',text));
  add(body,fact('● 入力から確認できること',selected.reasons[0]),fact('◐ 仮説',isCorrelation?'保守アカウントの不正利用の可能性。正規作業・例外承認の照合が必要です。':'優先的に調査・対応する必要がある可能性。実際の設定と作業記録を確認します。','warn'),fact('○ まだ分からないこと','脆弱性の実際の悪用、外部への送信、現在の機器・アカウントの状態。','neutral'));
  const output=el('div','model-output');output.hidden=true;output.setAttribute('role','status');
  const llmButton=button('ローカルAIで補助説明','secondary compact',()=>run(async()=>{
    llmButton.disabled=true;llmButton.textContent='説明を生成しています…';
    try{const r=await api('/api/explain',{snapshot_id:state.snapshot_id,finding_id:selected.id,use_llm:true});output.replaceChildren(el('strong','',r.actual_provider),el('p','',r.summary),el('p','microcopy',r.note));output.hidden=false;body.querySelector('.brief-heading .pill').textContent=r.llm_used?'ローカルLLM使用':'ルール説明 / LLM未使用';$('providerBadge').textContent=r.actual_provider;}
    finally{llmButton.disabled=false;llmButton.textContent='ローカルAIで補助説明';}
  }),!!PREVIEW || !state.llm?.configured);
  add(body,add(el('div','brief-meta'),el('div','','検知: '+state.rule_version+' / 自動実行なし'),el('div','',state.llm?.configured?'モデルを設定済み。接続と出力品質は別途検証が必要です。':'ローカルLLMは未設定です。説明は検知ルールから作成しています。')),llmButton,output);add(grid,brief);add(root,grid);
  const lower=el('div','lower-grid'), listing=el('section','');add(listing,section('検知と対応候補',`${findings.length}件`));const list=el('div','card');
  findings.forEach(f=>{const row=el('button','finding-row'+(selected.id===f.id?' selected':''));row.type='button';row.addEventListener('click',()=>{selectedId=f.id;render();});add(row,pill(f.priority,f.priority==='P1'?'danger':'warn'),add(el('div','finding-text'),el('strong','',f.title),el('small','',f.rule+' · '+(f.asset_id || f.gateway_id || '認証イベント')+' · 根拠 '+count(f.evidence_ids.length)+'件')),el('span','row-arrow','↗'));add(list,row);});add(listing,list);add(lower,listing);
  const scope=el('section','');add(scope,section('観測できている範囲','入力情報のみ'));const scopeCard=el('div','card card-pad');
  [['資産台帳',state.snapshot.assets.length+'台'],['認証ログ',count(state.snapshot.event_counts.login)+'件'],['ファイル参照ログ',count(state.snapshot.event_counts.file_access)+'件']].forEach(([name,num])=>add(scopeCard,add(el('div','telemetry-item'),el('span','',name),pill(num,'neutral'))));
  add(scopeCard,el('p','telemetry-caption','常時監視の接続は 0 / 3。入力にない挙動や低速な持ち出しは検知できません。正常・安全の保証はしません。'),el('p','telemetry-caption',`未確認: 資産項目 ${count(state.coverage.unknown_asset_fields)} / 認証項目 ${count(state.coverage.unknown_login_fields)} / 機密区分 ${count(state.coverage.unknown_classifications)} / 読み取りサイズ ${count(state.coverage.unknown_read_sizes)}`));
  const sources=state.coverage.provenance||[];
  if(sources.length){const box=el('details','evidence-box');add(box,el('summary','',`取り込み元ファイル（${count(sources.length)}件${sources.every(s=>s.verified)?'':' / 未検証の申告を含む'}）`),el('pre','evidence-ids',sources.map(s=>`${s.verified?'[この実行で読み取り]':'[申告値 / 未検証]'} ${s.label}  ${s.sha256.slice(0,16)}…  取込 ${count(s.rows_imported)}/${count(s.rows_read)}行`).join('\n')));add(scopeCard,box);}
  add(scope,scopeCard);add(lower,scope);add(root,lower);
}
function renderAssets(root){
  add(root,section('資産インベントリ','手動スナップショット / 到達性は登録情報'));
  const table=el('table','table');add(table,add(el('thead',''),add(el('tr',''),...['資産','外部公開','特権 / 機密への経路','脆弱性','優先度'].map(t=>el('th','',t)))));const tbody=el('tbody','');
  const bool=v=>v===null?'未確認':v?'あり':'なし';
  state.snapshot.assets.forEach(a=>{const f=state.findings.find(f=>f.asset_id===a.id&&f.kind==='exposure');const tr=el('tr','');add(tr,add(el('td',''),el('span','mono',a.id),el('small','',a.kind+' · '+date(a.observed_at))),add(el('td',''),pill(bool(a.internet_exposed),a.internet_exposed?'warn':'neutral')),add(el('td',''),el('span','',bool(a.privileged_path)+' / '+bool(a.sensitive_path))),add(el('td',''),el('span','',a.vulnerability?'CVSS '+(a.vulnerability.cvss??'不明'):'登録なし'),el('small','',a.vulnerability?.reference||'パッチ状態: '+a.patch_state)),add(el('td',''),pill(f?.priority || '未検知',f?.priority==='P1'?'danger':'neutral')));add(tbody,tr);});add(table,tbody);add(root,add(el('div','card table-wrap'),table),el('p','caution','未検知は安全を意味しません。脆弱性参照・CVSS・悪用有無は入力値であり、本版はKEVやベンダー情報へ自動照合していません。'));
}
function renderPlans(root){
  add(root,section('承認とシミュレーション','実環境の機器・アカウントは変更しません'));
  if(!state.proposals.length){add(root,add(el('div','empty-state'),el('h2','','まだ、対応計画はありません。'),el('p','','概要の検知候補から「対応計画を確認する」を選ぶと、業務影響と事前確認を含む計画が作成されます。'),button('概要に戻る','secondary',()=>changeView('overview'))));return;}
  state.proposals.forEach(p=>{const card=el('article','card plan-card');const status={pending:'承認待ち',expired:'期限切れ',simulated:'シミュレーション済み'}[p.status]||p.status;add(card,add(el('div','plan-card-head'),el('h3','',p.plan.title),pill(status,p.status==='pending'?'warn':'neutral')),el('p','',p.plan.impact),el('p','mono',p.id+' / '+p.plan.target),el('small','muted','期限: '+date(p.expires_at)+' · 実操作なし'));
    if(p.status==='pending')add(card,button('計画を開く','secondary compact',()=>{currentPlan={proposal_id:p.id,plan:p.plan,expires_at:p.expires_at,snapshot_id:state.snapshot_id};showPlanDialog();},!!PREVIEW));add(root,card);});
}
function renderAudit(root){
  add(root,add(el('div','audit-top'),add(el('div',''),pill(state.audit.valid?'内部チェーン整合':'整合性エラー',state.audit.valid?'green':'danger'),el('p','audit-note',state.audit.limitation)),button('検証レポートを書き出す ↓','secondary',()=>run(exportReport),!!PREVIEW)));
  add(root,section('操作記録',count(state.audit.count)+'件 / 画面は直近100件'));
  const table=el('table','table');add(table,add(el('thead',''),add(el('tr',''),...['記録','操作','根拠 / 実行状態'].map(v=>el('th','',v)))));const body=el('tbody','');
  state.audit_records.forEach(r=>add(body,add(el('tr',''),add(el('td',''),el('span','mono','#'+r.seq),el('small','',date(r.at))),add(el('td',''),el('span','',auditAction(r.action)),el('small','mono',r.action)),add(el('td',''),el('span','mono',r.payload.finding_id||r.payload.proposal_id||r.payload.snapshot_id||'—'),el('small','',r.payload.executed===false?'実際の変更は行っていません':r.payload.actual_provider||'整合性チェック対象')))));add(table,body);add(root,add(el('div','card table-wrap'),table),el('p','audit-note','ローカル管理者はDBと鍵の両方にアクセスできます。本版は独立した監査保管庫でも、証拠保全・法令遵守を保証する製品でもありません。'));
}
function renderTuning(root){
  const config=state.rule_config;
  add(root,section('現在の検知設定','設定ハッシュ '+config.digest));
  const table=el('table','table');add(table,add(el('thead',''),add(el('tr',''),...['項目','値','意味'].map(t=>el('th','',t)))));const body=el('tbody','');
  config.parameters.forEach(p=>add(body,add(el('tr',''),add(el('td',''),el('span','mono',p.name)),add(el('td',''),el('strong','',String(p.value))),add(el('td',''),el('span','',p.description)))));
  add(table,body);add(root,add(el('div','card table-wrap'),table));
  add(root,el('p','caution','既定値は同梱の合成データで確認した出発点です。導入先の正常な業務ログで測り直すまで、適切な値とは言えません。'));
  add(root,section('正常業務で測ってから決める','CLIで実行します'));
  const steps=[['01 / BASELINE','正常な業務の合成データを作る','python3 -m aisecure baseline --days 5 --users 40 --out normal.json\npython3 -m aisecure baseline --days 5 --users 40 --attack --out incident.json'],
               ['02 / EVALUATE','検知と誤検知を数える','python3 -m aisecure evaluate normal.json incident.json --sweep --out report.md'],
               ['03 / APPLY','決めた閾値で起動する','python3 -m aisecure --rules rules.json serve']];
  const grid=el('div','info-grid');steps.forEach(([label,title,code])=>{const card=add(el('article','card card-pad'),el('p','eyebrow',label),el('h3','',title));add(card,el('pre','evidence-ids',code));add(grid,card);});add(root,grid);
  add(root,el('p','audit-note','評価は合成データに対する結果です。実環境の誤検知率ではありません。閾値を上げれば確認件数は減りますが、小規模な持ち出しを見逃す可能性が上がります。設定の変更は起動時に監査記録へ残ります。'));
}
function renderAbout(root){
  const items=[['01 / COLLECT','必要なメタデータだけ受け取る','資産台帳と認証・ファイル参照ログをJSONで入力。氏名、原文、秘密鍵、ファイル本文は受け付けません。ユーザー・セッション・ファイル識別子は鍵付きハッシュで仮名化します。匿名化ではありません。'],['02 / DETECT','判定は再現可能なルールで','公開範囲・特権・機密情報への到達性を組み合わせ、CVSSの数字だけでは判断しません。大量参照は300秒以内に100個以上の異なるファイルが目安です。閾値は本番の正常ログで調整が必要です。'],['03 / EXPLAIN','AIは説明を補助するだけ','既定はLLMを使わないルール説明。任意のOllama接続では構造化した事実だけを送り、説明の参照IDを検証します。文章の正しさは保証せず、モデルにツールや対応権限は渡しません。'],['04 / RESPOND','変更する前に、人が判断する','影響・事前確認・復旧方針を表示し、5分間有効の計画に対して明示的な承認を求めます。v0.1はシミュレーションのみ。アカウント失効、機器設定変更、通信遮断を実行するコードはありません。'],['05 / AUDIT','できることと限界を明示する','読み込み・説明・計画・承認・シミュレーションを監査チェーンに記録します。末尾削除の検出には外部チェックポイントが必要であり、鍵とホストを同時に侵害された場合は保護できません。'],['NEXT / PRODUCTION','本番化は、接続と運用の検証から','実ログの読み取り専用コネクタ、SSO/RBAC、別権限の実行器、機器別API、外部監査保管、正常データを使う誤検知評価が未実装です。AI Secureは現時点でEDR・SIEM・VPN防御の代替ではありません。']];
  const grid=el('div','info-grid');items.forEach(([label,title,text])=>add(grid,add(el('article','card card-pad'),el('p','eyebrow',label),el('h3','',title),el('p','',text))));add(root,grid);
}
async function loadDemo(){
  if(state?.snapshot && !window.confirm('表示対象を架空データへ切り替えます。過去の入力と監査記録は保存されます。続行しますか？'))return;
  await api('/api/demo',{confirm:'LOAD SYNTHETIC DATA'});selectedId=null;await refresh();notify('架空の検証データを読み込みました。実環境への接続はありません。');
}
async function openPlan(finding){const result=await api('/api/plan',{snapshot_id:state.snapshot_id,finding_id:finding.id});currentPlan={...result,snapshot_id:state.snapshot_id};await refresh();showPlanDialog();}
function showPlanDialog(){
  const p=currentPlan, d=$('planDialogContent');d.replaceChildren();
  add(d,el('p','eyebrow','REVIEW BEFORE ACTION'),add(el('div','plan-card-head'),el('h2','',p.plan.title),pill('シミュレーション専用','warn')));d.querySelector('h2').id='planTitle';
  add(d,el('p','',p.plan.impact),el('p','mono','対象: '+p.plan.target));
  add(d,el('h3','','承認前の確認'));const checks=el('ul','detail-list');p.plan.prechecks.forEach(t=>add(checks,el('li','',t)));add(d,checks,el('h3','field-label','実運用時の復旧方針'),el('p','',p.plan.recovery),el('p','caution','この初期版は対応計画の検証用です。承認しても、現実のセッション・通信・機器設定には一切変更を加えません。'));
  const reasonLabel=el('label','field-label','承認理由（10〜500文字）');reasonLabel.htmlFor='approvalReason';const reason=el('textarea','');reason.id='approvalReason';reason.maxLength=500;reason.placeholder='根拠と業務影響をどう確認したか記入してください。';
  const confirmLabel=el('label','field-label','確認のため SIMULATE ONLY と入力');confirmLabel.htmlFor='approvalConfirm';const confirmation=el('input','');confirmation.type='text';confirmation.id='approvalConfirm';confirmation.autocomplete='off';confirmation.spellcheck=false;
  const ack=el('input','');ack.type='checkbox';ack.id='approvalAck';const ackLabel=el('label','ack-label');ackLabel.htmlFor=ack.id;add(ackLabel,ack,el('span','','実操作が行われないこと、および根拠・影響・復旧方針を確認しました。'));
  add(d,reasonLabel,reason,el('p','microcopy','理由の平文は保存せず、照合用の鍵付きハッシュのみを監査記録に保存します。'),confirmLabel,confirmation,ackLabel);
  const approve=button('承認してシミュレーション','primary',()=>run(async()=>{approve.disabled=true;try{const r=await api('/api/approve',{proposal_id:p.proposal_id,snapshot_id:p.snapshot_id,confirmation:confirmation.value,reason:reason.value});$('planDialog').close();await refresh();notify(r.message);}finally{approve.disabled=false;}}),true);
  const validate=()=>approve.disabled=!!PREVIEW||!ack.checked||confirmation.value!=='SIMULATE ONLY'||reason.value.trim().length<10;
  [reason,confirmation,ack].forEach(n=>n.addEventListener('input',validate));
  add(d,el('p','microcopy','承認期限: '+date(p.expires_at)+'。入力データが更新されると承認は拒否されます。'),add(el('div','dialog-buttons'),button('閉じる','secondary',()=>$('planDialog').close()),approve));$('planDialog').showModal();
}
async function exportReport(){const data=await api('/api/export');const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=el('a','');a.href=url;a.download='ai-secure-report.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);await refresh();notify('仮名化された識別子を含みます。保存先・共有範囲を確認してください。');}
async function login(){token=$('tokenInput').value.trim();try{await refresh();$('loginDialog').close();$('tokenInput').value='';$('loginError').textContent='';}catch(e){$('loginError').textContent=e.message;}}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>changeView(b.dataset.view)));
document.querySelector('.brand').addEventListener('click',e=>{e.preventDefault();changeView('overview');});
$('demoButton').addEventListener('click',()=>run(loadDemo));$('importButton').addEventListener('click',()=>$('fileInput').click());
$('fileInput').addEventListener('change',()=>run(async()=>{const file=$('fileInput').files[0];if(!file)return;try{if(file.size>2*1024*1024)throw new Error('JSONは2 MiB以下にしてください。');if(!window.confirm('管理権限があるログのメタデータのみを入力してください。ファイル本文・秘密鍵・トークンなどを含めないでください。読み込みますか？'))return;const raw=await file.text();await api('/api/ingest',raw,true);selectedId=null;await refresh();notify('手動スナップショットを解析しました。継続監視やログの真正性検証は行っていません。');}finally{$('fileInput').value='';}}));
$('loginButton').addEventListener('click',login);$('tokenInput').addEventListener('keydown',e=>{if(e.key==='Enter')login();});$('loginDialog').addEventListener('cancel',e=>e.preventDefault());
(async()=>{if(PREVIEW){$('demoButton').disabled=true;$('importButton').disabled=true;await refresh();return;}const params=new URLSearchParams(location.hash.slice(1));token=params.get('token')||'';if(location.hash)history.replaceState(null,'',location.pathname);if(!token){$('loginDialog').showModal();return;}try{await refresh();}catch(e){$('loginDialog').showModal();$('loginError').textContent=e.message;}})();
