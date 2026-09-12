'use strict';
const PREVIEW = window.__AI_SECURE_PREVIEW__ || null;
const EVIDENCE_SHOWN = 200;
let token = '', state = null, view = 'overview', selectedId = null, currentPlan = null, toastTimer;
const $ = (id) => document.getElementById(id);
const VIEWS = ['overview', 'assets', 'plans', 'tuning', 'audit', 'about'];

function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; }
function add(parent, ...children) { children.filter(Boolean).forEach(c => parent.append(c)); return parent; }
function pill(text, cls='neutral') { return el('span','pill '+cls,text); }
function button(text, cls, fn, disabled=false) { const b=el('button','button '+cls,text); b.type='button'; b.disabled=disabled; b.addEventListener('click',fn); return b; }
function notify(message,error=false) { clearTimeout(toastTimer); const n=$('toast'); n.textContent=message; n.classList.toggle('error',error); n.hidden=false; toastTimer=setTimeout(()=>n.hidden=true,7000); }
function date(value) { return value ? new Date(value).toLocaleString(lang==='ja'?'ja-JP':'en-GB',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—'; }
function count(n) { return Number(n || 0).toLocaleString(lang==='ja'?'ja-JP':'en-US'); }
function auditAction(action) { const k='audit.action.'+action; const v=t(k); return v===k?action:v; }
async function api(path,body,rawBody=false) {
  if(PREVIEW) throw new Error(t('err.previewOnly'));
  const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'Authorization':'Bearer '+token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:rawBody?body:JSON.stringify(body)}),credentials:'omit',cache:'no-store'});
  const data=await response.json();
  if(!response.ok) { if(response.status===401 && !$('loginDialog').open) $('loginDialog').showModal(); throw new Error(data.error || t('err.requestFailed')); }
  return data;
}
async function run(fn) { try { await fn(); } catch(e) { notify(e.message || t('err.processFailed'),true); } }
async function refresh() { state=PREVIEW || await api('/api/state'); render(); }
function changeView(next) { view=next; render(); }
function getSelected() { return state.findings.find(f=>f.id===selectedId) || state.findings[0] || null; }
function section(title,right) { return add(el('div','section-title'),el('h2','',title),typeof right==='string'?el('small','',right):right); }
function stat(label,value,caption,unit='',emphasis=false) { return add(el('div','stat'+(emphasis?' emphasis':'')),el('div','stat-label',label),add(el('div','stat-value'),el('span','',value),el('small','',unit)),el('div','stat-caption',caption)); }
function empty(title,text) { return add(el('section','empty-state'),el('p','eyebrow',t('empty.start')),el('h2','',title),el('p','',text),button(t('empty.tryDemo'),'primary',()=>run(loadDemo),!!PREVIEW)); }
function render() {
  if(!state) return;
  applyStatic();
  $('viewLabel').textContent=t('nav.'+view); $('pageTitle').textContent=t('headings.'+view)[0]; $('pageSubtitle').textContent=t('headings.'+view)[1];
  document.querySelectorAll('[data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===view); if(b.dataset.view===view)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
  const mode=state.snapshot?.source_mode;
  $('dataMode').textContent=PREVIEW?t('dataMode.preview'):mode==='demo'?t('dataMode.demo'):mode==='imported'?t('dataMode.imported'):t('dataMode.none');
  $('statusBanner').children[1].textContent=PREVIEW?t('banner.preview'):mode==='demo'?t('banner.demo'):mode==='imported'?t('banner.imported'):t('banner.default');
  $('navCount').textContent=state.findings.filter(f=>f.priority==='P1').length;
  $('providerBadge').textContent=state.llm?.configured?t('provider.configured'):t('provider.rule');
  const container=$('viewContent'); container.replaceChildren();
  if(!state.audit.valid) add(container,add(el('div','caution'),el('strong','',t('audit.broken'))));
  if(view==='about'){renderAbout(container);return;}
  if(view==='tuning'){renderTuning(container);return;}
  if(!state.snapshot){add(container,empty(t('empty.noData.title'),t('empty.noData.text')));return;}
  ({overview:renderOverview,assets:renderAssets,plans:renderPlans,audit:renderAudit})[view](container);
}
function renderOverview(root) {
  const findings=state.findings, selected=getSelected(), correlations=findings.filter(f=>f.kind==='correlation');
  add(root,add(el('div','stats-grid'),stat(t('stat.p1'),count(findings.filter(f=>f.priority==='P1').length),t('stat.p1.cap'),t('unit.cases'),true),stat(t('stat.corr'),count(correlations.length),t('stat.corr.cap'),t('unit.cases')),stat(t('stat.events'),count(state.snapshot.event_counts.total),t('stat.events.cap'),t('unit.cases')),stat(t('stat.assets'),count(state.snapshot.assets.length),t('stat.assets.cap'),t('unit.assets'))));
  add(root,section(t('ov.now'),t('ov.snapshotTime',date(state.snapshot.as_of))));
  if(!selected){add(root,empty(t('empty.noFind.title'),t('empty.noFind.text')));return;}
  const grid=el('div','content-grid'), card=el('article','card incident-card'), inner=el('div','card-pad');
  add(inner,add(el('div','incident-topline'),pill(selected.priority,selected.priority==='P1'?'danger':'warn'),pill(selected.kind==='correlation'?t('ov.corrPill'):t('ov.respPill'),'neutral'),el('span','mono muted',selected.rule+' · '+selected.id)));
  const isCorrelation=selected.kind==='correlation';
  add(inner,el('h2','incident-title',isCorrelation?t('ov.corrTitle'):selected.title),el('p','incident-description',isCorrelation?t('ov.corrDesc'):selected.reasons.join(' ')));
  if(isCorrelation){
    const path=el('div','path-grid');
    const steps=[['01',t('ov.step1'),selected.gateway_id],['02',t('ov.step2t'),t('ov.step2')],['03',t('ov.step3t'),t('ov.step3',count(selected.distinct_files),count(selected.sensitive_files))]];
    steps.forEach((s,i)=>{if(i)add(path,el('div','path-arrow','→'));add(path,add(el('div','path-node'),el('span','path-number',s[0]),el('strong','',s[1]),el('small','',s[2])));});add(inner,path);
  }
  add(inner,el('div','caution',t('ov.cautionRelated')));
  add(inner,add(el('div','card-actions'),el('small','muted',t('ov.actionNoOp')),button(t('ov.reviewPlan'),'primary',()=>run(()=>openPlan(selected)),!!PREVIEW || !state.audit.valid)));
  const details=el('details','evidence-box');const shown=selected.evidence_ids.slice(0,EVIDENCE_SHOWN);const rest=selected.evidence_ids.length-shown.length;add(details,el('summary','',t('ov.evidence',count(selected.evidence_ids.length))),el('pre','evidence-ids',shown.join('\n')+(rest>0?t('ov.evidenceMore',count(rest)):'')));add(inner,details);add(card,inner);add(grid,card);
  const brief=add(el('aside','card brief-card'),el('div','card-pad')); const body=brief.firstChild;
  add(body,add(el('div','brief-heading'),el('span','brief-mark','⌁'),el('h3','',t('ov.briefTitle')),pill(t('ov.briefPill'),'green')));
  const fact=(label,text,cls='')=>add(el('div','fact-block'),el('div','fact-label '+cls,label),el('p','',text));
  add(body,fact(t('ov.factObserved'),selected.reasons[0]),fact(t('ov.factHypo'),isCorrelation?t('ov.factHypoCorr'):t('ov.factHypoSingle'),'warn'),fact(t('ov.factUnknown'),t('ov.factUnknownText'),'neutral'));
  const output=el('div','model-output');output.hidden=true;output.setAttribute('role','status');
  const llmButton=button(t('ov.llmBtn'),'secondary compact',()=>run(async()=>{
    llmButton.disabled=true;llmButton.textContent=t('ov.llmGen');
    try{const r=await api('/api/explain',{snapshot_id:state.snapshot_id,finding_id:selected.id,use_llm:true});output.replaceChildren(el('strong','',r.actual_provider),el('p','',r.summary),el('p','microcopy',r.note));output.hidden=false;body.querySelector('.brief-heading .pill').textContent=r.llm_used?t('ov.briefPillLlm'):t('ov.briefPill');$('providerBadge').textContent=r.actual_provider;}
    finally{llmButton.disabled=false;llmButton.textContent=t('ov.llmBtn');}
  }),!!PREVIEW || !state.llm?.configured);
  add(body,add(el('div','brief-meta'),el('div','',t('ov.metaDetect',state.rule_version)),el('div','',state.llm?.configured?t('ov.metaModelYes'):t('ov.metaModelNo'))),llmButton,output);add(grid,brief);add(root,grid);
  const lower=el('div','lower-grid'), listing=el('section','');add(listing,section(t('ov.findings',findings.length)));const list=el('div','card');
  findings.forEach(f=>{const row=el('button','finding-row'+(selected.id===f.id?' selected':''));row.type='button';row.addEventListener('click',()=>{selectedId=f.id;render();});add(row,pill(f.priority,f.priority==='P1'?'danger':'warn'),add(el('div','finding-text'),el('strong','',f.title),el('small','',f.rule+' · '+(f.asset_id || f.gateway_id || t('ov.authEvent'))+' · '+t('ov.evCount',count(f.evidence_ids.length)))),el('span','row-arrow','↗'));add(list,row);});add(listing,list);add(lower,listing);
  const scope=el('section','');add(scope,section(t('ov.scope'),t('ov.scopeInput')));const scopeCard=el('div','card card-pad');
  [[t('ov.assetLedger'),state.snapshot.assets.length+t('unit.units')],[t('ov.authLog'),count(state.snapshot.event_counts.login)+t('unit.count')],[t('ov.fileLog'),count(state.snapshot.event_counts.file_access)+t('unit.count')]].forEach(([name,num])=>add(scopeCard,add(el('div','telemetry-item'),el('span','',name),pill(num,'neutral'))));
  add(scopeCard,el('p','telemetry-caption',t('ov.telemetry1')),el('p','telemetry-caption',t('ov.telemetry2',count(state.coverage.unknown_asset_fields),count(state.coverage.unknown_login_fields),count(state.coverage.unknown_classifications),count(state.coverage.unknown_read_sizes))));
  const sources=state.coverage.provenance||[];
  if(sources.length){const box=el('details','evidence-box');add(box,el('summary','',t('ov.sources',count(sources.length),!sources.every(s=>s.verified))),el('pre','evidence-ids',sources.map(s=>`${s.verified?t('ov.srcVerified'):t('ov.srcUnverified')} ${s.label}  ${s.sha256.slice(0,16)}…  ${t('ov.srcRows',count(s.rows_imported),count(s.rows_read))}`).join('\n')));add(scopeCard,box);}
  add(scope,scopeCard);add(lower,scope);add(root,lower);
}
function renderAssets(root){
  add(root,section(t('as.section'),t('as.sub')));
  const table=el('table','table');add(table,add(el('thead',''),add(el('tr',''),...[t('as.h.asset'),t('as.h.exposed'),t('as.h.path'),t('as.h.vuln'),t('as.h.pri')].map(h=>el('th','',h)))));const tbody=el('tbody','');
  const bool=v=>v===null?t('as.unknown'):v?t('as.yes'):t('as.no');
  state.snapshot.assets.forEach(a=>{const f=state.findings.find(f=>f.asset_id===a.id&&f.kind==='exposure');const tr=el('tr','');add(tr,add(el('td',''),el('span','mono',a.id),el('small','',a.kind+' · '+date(a.observed_at))),add(el('td',''),pill(bool(a.internet_exposed),a.internet_exposed?'warn':'neutral')),add(el('td',''),el('span','',bool(a.privileged_path)+' / '+bool(a.sensitive_path))),add(el('td',''),el('span','',a.vulnerability?t('as.cvss',a.vulnerability.cvss??t('as.cvssUnknown')):t('as.noVuln')),el('small','',a.vulnerability?.reference||t('as.patch',a.patch_state))),add(el('td',''),pill(f?.priority || t('as.notDetected'),f?.priority==='P1'?'danger':'neutral')));add(tbody,tr);});add(table,tbody);add(root,add(el('div','card table-wrap'),table),el('p','caution',t('as.caution')));
}
function renderPlans(root){
  add(root,section(t('pl.section'),t('pl.sub')));
  if(!state.proposals.length){add(root,add(el('div','empty-state'),el('h2','',t('pl.emptyTitle')),el('p','',t('pl.emptyText')),button(t('pl.back'),'secondary',()=>changeView('overview'))));return;}
  state.proposals.forEach(p=>{const card=el('article','card plan-card');const status={pending:t('pl.pending'),expired:t('pl.expired'),simulated:t('pl.simulated')}[p.status]||p.status;add(card,add(el('div','plan-card-head'),el('h3','',p.plan.title),pill(status,p.status==='pending'?'warn':'neutral')),el('p','',p.plan.impact),el('p','mono',p.id+' / '+p.plan.target),el('small','muted',t('pl.deadline',date(p.expires_at))));
    if(p.status==='pending')add(card,button(t('pl.open'),'secondary compact',()=>{currentPlan={proposal_id:p.id,plan:p.plan,expires_at:p.expires_at,snapshot_id:state.snapshot_id};showPlanDialog();},!!PREVIEW));add(root,card);});
}
function renderAudit(root){
  add(root,add(el('div','audit-top'),add(el('div',''),pill(state.audit.valid?t('au.chainOk'):t('au.chainErr'),state.audit.valid?'green':'danger'),el('p','audit-note',state.audit.limitation)),button(t('au.export'),'secondary',()=>run(exportReport),!!PREVIEW)));
  add(root,section(t('au.records',count(state.audit.count))));
  const table=el('table','table');add(table,add(el('thead',''),add(el('tr',''),...[t('au.h.record'),t('au.h.action'),t('au.h.basis')].map(v=>el('th','',v)))));const body=el('tbody','');
  state.audit_records.forEach(r=>add(body,add(el('tr',''),add(el('td',''),el('span','mono','#'+r.seq),el('small','',date(r.at))),add(el('td',''),el('span','',auditAction(r.action)),el('small','mono',r.action)),add(el('td',''),el('span','mono',r.payload.finding_id||r.payload.proposal_id||r.payload.snapshot_id||'—'),el('small','',r.payload.executed===false?t('au.noChange'):r.payload.actual_provider||t('au.integrityTarget'))))));add(table,body);add(root,add(el('div','card table-wrap'),table),el('p','audit-note',t('au.note')));
}
function renderTuning(root){
  const config=state.rule_config;
  add(root,section(t('tu.current'),t('tu.hash',config.digest)));
  const table=el('table','table');add(table,add(el('thead',''),add(el('tr',''),...[t('tu.h.name'),t('tu.h.value'),t('tu.h.meaning')].map(h=>el('th','',h)))));const body=el('tbody','');
  config.parameters.forEach(p=>add(body,add(el('tr',''),add(el('td',''),el('span','mono',p.name)),add(el('td',''),el('strong','',String(p.value))),add(el('td',''),el('span','',p.description)))));
  add(table,body);add(root,add(el('div','card table-wrap'),table));
  add(root,el('p','caution',t('tu.caution')));
  add(root,section(t('tu.measure'),t('tu.cli')));
  const steps=[['01 / BASELINE',t('tu.step1t'),'python3 -m aisecure baseline --days 5 --users 40 --out normal.json\npython3 -m aisecure baseline --days 5 --users 40 --attack --out incident.json'],
               ['02 / EVALUATE',t('tu.step2t'),'python3 -m aisecure evaluate normal.json incident.json --sweep --out report.md'],
               ['03 / APPLY',t('tu.step3t'),'python3 -m aisecure --rules rules.json serve']];
  const grid=el('div','info-grid');steps.forEach(([label,title,code])=>{const card=add(el('article','card card-pad'),el('p','eyebrow',label),el('h3','',title));add(card,el('pre','evidence-ids',code));add(grid,card);});add(root,grid);
  add(root,el('p','audit-note',t('tu.note')));
}
function renderAbout(root){
  const items=[['01 / COLLECT',t('ab.01t'),t('ab.01')],['02 / DETECT',t('ab.02t'),t('ab.02')],['03 / EXPLAIN',t('ab.03t'),t('ab.03')],['04 / RESPOND',t('ab.04t'),t('ab.04')],['05 / AUDIT',t('ab.05t'),t('ab.05')],['NEXT / PRODUCTION',t('ab.nextt'),t('ab.next')]];
  const grid=el('div','info-grid');items.forEach(([label,title,text])=>add(grid,add(el('article','card card-pad'),el('p','eyebrow',label),el('h3','',title),el('p','',text))));add(root,grid);
}
async function loadDemo(){
  if(state?.snapshot && !window.confirm(t('demo.confirm')))return;
  await api('/api/demo',{confirm:'LOAD SYNTHETIC DATA'});selectedId=null;await refresh();notify(t('demo.done'));
}
async function openPlan(finding){const result=await api('/api/plan',{snapshot_id:state.snapshot_id,finding_id:finding.id});currentPlan={...result,snapshot_id:state.snapshot_id};await refresh();showPlanDialog();}
function showPlanDialog(){
  const p=currentPlan, d=$('planDialogContent');d.replaceChildren();
  add(d,el('p','eyebrow',t('dlg.review')),add(el('div','plan-card-head'),el('h2','',p.plan.title),pill(t('dlg.simOnly'),'warn')));d.querySelector('h2').id='planTitle';
  add(d,el('p','',p.plan.impact),el('p','mono',t('dlg.target',p.plan.target)));
  add(d,el('h3','',t('dlg.preChecks')));const checks=el('ul','detail-list');p.plan.prechecks.forEach(x=>add(checks,el('li','',x)));add(d,checks,el('h3','field-label',t('dlg.recovery')),el('p','',p.plan.recovery),el('p','caution',t('dlg.cautionSim')));
  const reasonLabel=el('label','field-label',t('dlg.reasonLabel'));reasonLabel.htmlFor='approvalReason';const reason=el('textarea','');reason.id='approvalReason';reason.maxLength=500;reason.placeholder=t('dlg.reasonPlaceholder');
  const confirmLabel=el('label','field-label',t('dlg.confirmLabel'));confirmLabel.htmlFor='approvalConfirm';const confirmation=el('input','');confirmation.type='text';confirmation.id='approvalConfirm';confirmation.autocomplete='off';confirmation.spellcheck=false;
  const ack=el('input','');ack.type='checkbox';ack.id='approvalAck';const ackLabel=el('label','ack-label');ackLabel.htmlFor=ack.id;add(ackLabel,ack,el('span','',t('dlg.ack')));
  add(d,reasonLabel,reason,el('p','microcopy',t('dlg.microReason')),confirmLabel,confirmation,ackLabel);
  const approve=button(t('dlg.approve'),'primary',()=>run(async()=>{approve.disabled=true;try{const r=await api('/api/approve',{proposal_id:p.proposal_id,snapshot_id:p.snapshot_id,confirmation:confirmation.value,reason:reason.value});$('planDialog').close();await refresh();notify(r.message);}finally{approve.disabled=false;}}),true);
  const validate=()=>approve.disabled=!!PREVIEW||!ack.checked||confirmation.value!=='SIMULATE ONLY'||reason.value.trim().length<10;
  [reason,confirmation,ack].forEach(n=>n.addEventListener('input',validate));
  add(d,el('p','microcopy',t('dlg.deadline',date(p.expires_at))),add(el('div','dialog-buttons'),button(t('dlg.close'),'secondary',()=>$('planDialog').close()),approve));$('planDialog').showModal();
}
async function exportReport(){const data=await api('/api/export');const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=el('a','');a.href=url;a.download='ai-secure-report.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);await refresh();notify(t('export.note'));}
async function login(){token=$('tokenInput').value.trim();try{await refresh();$('loginDialog').close();$('tokenInput').value='';$('loginError').textContent='';}catch(e){$('loginError').textContent=e.message;}}
function toggleLang(){setLang(lang==='ja'?'en':'ja');const b=$('langToggle');if(b)b.textContent=t('lang.other');if(state)render();else applyStatic();}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>changeView(b.dataset.view)));
document.querySelector('.brand').addEventListener('click',e=>{e.preventDefault();changeView('overview');});
$('demoButton').addEventListener('click',()=>run(loadDemo));$('importButton').addEventListener('click',()=>$('fileInput').click());
if($('langToggle')){$('langToggle').textContent=t('lang.other');$('langToggle').addEventListener('click',toggleLang);}
$('fileInput').addEventListener('change',()=>run(async()=>{const file=$('fileInput').files[0];if(!file)return;try{if(file.size>2*1024*1024)throw new Error(t('import.tooLarge'));if(!window.confirm(t('import.confirm')))return;const raw=await file.text();await api('/api/ingest',raw,true);selectedId=null;await refresh();notify(t('import.done'));}finally{$('fileInput').value='';}}));
$('loginButton').addEventListener('click',login);$('tokenInput').addEventListener('keydown',e=>{if(e.key==='Enter')login();});$('loginDialog').addEventListener('cancel',e=>e.preventDefault());
applyStatic();
(async()=>{if(PREVIEW){$('demoButton').disabled=true;$('importButton').disabled=true;await refresh();return;}const params=new URLSearchParams(location.hash.slice(1));token=params.get('token')||'';if(location.hash)history.replaceState(null,'',location.pathname);if(!token){$('loginDialog').showModal();return;}try{await refresh();}catch(e){$('loginDialog').showModal();$('loginError').textContent=e.message;}})();
