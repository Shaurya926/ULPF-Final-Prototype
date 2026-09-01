const $ = (id) => document.getElementById(id);
const state = { events: [], inspection: null, analysis: null, mappings: {}, currentDraft: null };
const targets = ["", "@timestamp", "event.action", "event.category", "event.type", "event.severity", "event.outcome", "source.ip", "source.port", "destination.ip", "destination.port", "network.transport", "network.application", "observer.vendor", "observer.product", "observer.name"];

function esc(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
function pretty(value) { return JSON.stringify(value, null, 2); }
function toast(message, error=false) {
  const el = $('toast'); el.textContent = message; el.classList.toggle('error', error); el.classList.add('show');
  clearTimeout(window.__toast); window.__toast = setTimeout(() => el.classList.remove('show'), 3200);
}
async function api(url, options={}) {
  const res = await fetch(url, {headers: {'Content-Type':'application/json', ...(options.headers || {})}, ...options});
  if (!res.ok) { let detail = `${res.status} ${res.statusText}`; try { detail = (await res.json()).detail || detail; } catch (_) {} throw new Error(detail); }
  return res.json();
}
function switchScreen(name) {
  document.querySelectorAll('.screen').forEach(el => el.classList.toggle('active', el.id === `screen-${name}`));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.screen === name));
  $('screen-title').textContent = ({overview:'Overview', ingestion:'Ingestion', explorer:'Unified Event Explorer', inspector:'Hero Event Inspector', registry:'Parser Registry', onboarding:'Unknown Event / Onboarding'})[name];
  if (name === 'overview') loadOverview();
  if (name === 'explorer') loadEvents();
  if (name === 'registry') { loadRegistry(); loadDrafts(); }
  if (name === 'onboarding') loadUnknownState();
}

document.querySelectorAll('.nav-item').forEach(btn => btn.addEventListener('click', () => switchScreen(btn.dataset.screen)));

function bars(containerId, data) {
  const el = $(containerId); const entries = Object.entries(data || {}).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) { el.className = 'bar-list empty-state'; el.textContent = 'No events yet.'; return; }
  const max = Math.max(...entries.map(x=>x[1])); el.className = 'bar-list';
  el.innerHTML = entries.map(([label,count]) => `<div class="bar-row"><label>${esc(label)}</label><div class="bar-track"><div class="bar-fill" style="width:${Math.max(6,(count/max)*100)}%"></div></div><b>${count}</b></div>`).join('');
}
async function loadOverview() {
  try {
    const d = await api('/api/v1/overview');
    $('m-total').textContent = d.total_events; $('m-parsed').textContent = d.parsed_events; $('m-failed').textContent = d.unknown_failed; $('m-plugins').textContent = d.active_plugins;
    if (d.latest_throughput) {
      $('m-throughput').textContent = `${d.latest_throughput.events_per_sec.toFixed(1)} ev/s`;
      $('m-throughput-note').textContent = `${d.latest_throughput.batch_size} event(s) · ${d.latest_throughput.elapsed_ms.toFixed(1)} ms · local measurement`;
    } else { $('m-throughput').textContent = '—'; $('m-throughput-note').textContent = 'Run an ingestion batch'; }
    if (d.published_benchmark?.events_per_sec != null) {
      $('m-benchmark').textContent = `${d.published_benchmark.events_per_sec.toFixed(1)} ev/s`;
      $('m-benchmark-note').textContent = `${d.published_benchmark.events} synthetic events · p95 ${d.published_benchmark.p95_ms.toFixed(1)} ms · ${(d.published_benchmark.failure_rate*100).toFixed(1)}% failures`;
    } else { $('m-benchmark').textContent = '—'; $('m-benchmark-note').textContent = 'Run scripts/benchmark.py'; }
    bars('vendor-bars', d.vendor_distribution); bars('action-bars', d.action_distribution);
  } catch (e) { toast(`Overview failed: ${e.message}`, true); }
}

async function loadDataset(id, switchToIngest=true) {
  const d = await api(`/api/v1/demo/datasets/${id}`); $('ingest-text').value = d.payload;
  if ($('unknown-payload') && id === 'unknown') $('unknown-payload').value = d.events[0] || d.payload;
  if (switchToIngest) switchScreen('ingestion');
  toast(`${d.label}: ${id} loaded`); return d;
}
document.querySelectorAll('[data-dataset]').forEach(btn => btn.addEventListener('click', () => loadDataset(btn.dataset.dataset)));
$('judge-demo').addEventListener('click', async () => { try { await loadDataset('mixed'); } catch (e) { toast(e.message, true); } });

function renderProcessResults(items) {
  const el = $('processing-results');
  if (!items.length) { el.className='result-list empty-state'; el.textContent='No results.'; return; }
  const stored = items.filter(x=>x.status==='STORED').length; const q = items.length-stored;
  $('batch-summary').textContent = `${stored} stored · ${q} quarantined`;
  el.className='result-list'; el.innerHTML = items.map((x,i)=>`<div class="result-item"><strong class="${x.status==='STORED'?'status-stored':'status-quarantined'}">${esc(x.status)}</strong><span>${esc(x.plugin_id || x.reason || 'unknown')}</span><code>${esc(x.event_id || x.raw_event_id)}</code>${x.event_id?`<button class="button small inspect-result" data-event="${esc(x.event_id)}">Inspect</button>`:'<span></span>'}</div>`).join('');
  document.querySelectorAll('.inspect-result').forEach(btn => btn.addEventListener('click', ()=>openInspector(btn.dataset.event)));
}
async function processPayloads(mode) {
  const text = $('ingest-text').value; if (!text.trim()) return toast('Paste or load log events first.', true);
  try {
    let data;
    if (mode === 'paste') data = [await api('/api/v1/ingest/paste', {method:'POST', body:JSON.stringify({payload:text})})];
    else { const payloads = text.split(/\r?\n/).filter(x=>x.trim()); data = await api('/api/v1/ingest/batch', {method:'POST', body:JSON.stringify({payloads})}); }
    renderProcessResults(data); await loadOverview(); toast(`Processed ${data.length} event(s). Exact raw copies preserved.`);
  } catch (e) { toast(`Processing failed: ${e.message}`, true); }
}
$('process-paste').addEventListener('click', ()=>processPayloads('paste'));
$('process-batch').addEventListener('click', ()=>processPayloads('batch'));
$('file-input').addEventListener('change', async (e) => { const file=e.target.files[0]; if (!file) return; $('ingest-text').value = await file.text(); toast(`${file.name} loaded locally.`); });

function qs() {
  const params = new URLSearchParams();
  const pairs = [['search','f-search'],['action','f-action'],['vendor','f-vendor'],['source_ip','f-source'],['destination_ip','f-destination'],['protocol','f-protocol']];
  pairs.forEach(([key,id]) => { const v=$(id).value.trim(); if(v) params.set(key,v); }); params.set('limit','500'); return params.toString();
}
async function loadEvents() {
  try {
    const rows = await api(`/api/v1/events?${qs()}`); state.events = rows; $('event-count').textContent = `${rows.length} event${rows.length===1?'':'s'}`;
    const body = $('events-body'); body.innerHTML = rows.map(e => `<tr data-event="${esc(e.event_id)}"><td>${esc(e['@timestamp'])}</td><td>${esc(e.observer?.vendor)}</td><td>${esc(e.observer?.product)}</td><td>${esc(e.source?.ip || '—')}</td><td>${esc(e.destination?.ip || '—')}</td><td>${esc(e.destination?.port ?? '—')}</td><td>${esc(e.network?.transport || '—')}</td><td><span class="action-pill ${e.event?.action==='DENY'?'deny':''}">${esc(e.event?.action || '—')}</span></td><td>${esc(e.event?.category || '—')}</td><td>${esc(e.provenance?.parser_version || '—')}</td><td>${esc(e._status || 'STORED')}</td></tr>`).join('');
    $('events-empty').style.display = rows.length ? 'none' : 'block';
    body.querySelectorAll('tr').forEach(tr => tr.addEventListener('click', () => openInspector(tr.dataset.event)));
  } catch (e) { toast(`Explorer failed: ${e.message}`, true); }
}
$('apply-filters').addEventListener('click', loadEvents);
$('clear-filters').addEventListener('click', () => { ['f-search','f-action','f-vendor','f-source','f-destination','f-protocol'].forEach(id=>$(id).value=''); loadEvents(); });

async function openInspector(eventId) {
  try {
    const d = await api(`/api/v1/events/${encodeURIComponent(eventId)}/inspect`); state.inspection=d;
    $('inspect-title').textContent = `${d.normalized.observer?.vendor || 'Unknown'} ${d.normalized.event?.action || ''} event`;
    $('inspect-subtitle').textContent = `${d.normalized.provenance?.parser_id} ${d.normalized.provenance?.parser_version} · mapping ${d.normalized.provenance?.mapping_version}`;
    $('inspect-event-id').textContent = `event_id: ${d.event_id}`; $('inspect-raw-id').textContent = `raw_event_id: ${d.raw_event_id}`;
    $('raw-hash').textContent = `SHA-256 ${d.raw.sha256.slice(0,12)}…`; $('parsed-plugin').textContent = `parser ${d.plugin_id}`; $('validation-status').textContent = `validation ${d.validation.status}`;
    $('raw-view').textContent = d.raw.payload; $('parsed-view').textContent = pretty(d.parsed); $('normalized-view').textContent = pretty(d.normalized); $('extensions-view').textContent = pretty(d.extensions || {});
    const trace = d.field_trace || {}; $('trace-body').innerHTML = Object.entries(trace).map(([target,v]) => `<tr><td>${esc(target)}</td><td>${esc(Array.isArray(v.source_field)?v.source_field.join(', '):(v.source_field || (v.default?'default':'—')))}</td><td>${esc(v.transform || v.cast || (v.default?'default':'—'))}</td></tr>`).join('') || '<tr><td colspan="3">No trace entries.</td></tr>';
    switchScreen('inspector');
  } catch (e) { toast(`Inspector failed: ${e.message}`, true); }
}

async function loadRegistry() {
  try {
    const plugins = await api('/api/v1/plugins'); const el=$('registry-grid');
    el.innerHTML = plugins.map(p=>`<article class="plugin-card"><div class="plugin-top"><div><h4>${esc(p.vendor)} · ${esc(p.product)}</h4><p>${esc(p.id)} v${esc(p.version)}</p></div><button class="toggle ${p.enabled?'on':''}" data-plugin="${esc(p.id)}" data-enabled="${p.enabled}" aria-label="Toggle ${esc(p.id)}"></button></div><div class="plugin-meta"><div><span>Format</span><strong>${esc(p.format)}</strong></div><div><span>Contract</span><strong>${esc(p.contract_status)}</strong></div><div><span>Detection</span><strong>${esc(p.detection_summary)}</strong></div><div><span>Fixtures</span><strong>${esc(p.fixture_count)} test log(s)</strong></div></div></article>`).join('');
    el.querySelectorAll('.toggle').forEach(btn => btn.addEventListener('click', async () => { const enabled=btn.dataset.enabled!=='true'; try { await api(`/api/v1/plugins/${btn.dataset.plugin}/state`, {method:'PATCH', body:JSON.stringify({enabled})}); toast(`${btn.dataset.plugin} ${enabled?'enabled':'disabled'} for this runtime.`); loadRegistry(); loadOverview(); } catch(e){toast(e.message,true);} }));
  } catch(e){toast(`Registry failed: ${e.message}`,true);}
}

function mappingOptions(selected='') { return targets.map(t=>`<option value="${esc(t)}" ${t===selected?'selected':''}>${esc(t || '— do not map —')}</option>`).join(''); }
// liveLookup=true is used for rows the user adds by hand (the "Add row" button): as they type
// a source field name, we look it up in the most recently analyzed payload instead of leaving
// the observed-value column blank, matching what the auto-populated rows already show.
function addMappingRow(source='', value='', target='', liveLookup=false) {
  const tr=document.createElement('tr'); tr.innerHTML=`<td><input class="map-source" value="${esc(source)}" /></td><td><code class="map-value">${esc(String(value).slice(0,80))}</code></td><td><select class="map-target mapping-select">${mappingOptions(target)}</select></td><td><button class="icon-button remove-map">×</button></td>`;
  tr.querySelector('.remove-map').addEventListener('click',()=>tr.remove());
  if (liveLookup) {
    const sourceInput = tr.querySelector('.map-source');
    const valueCell = tr.querySelector('.map-value');
    const updateObservedValue = () => {
      const key = sourceInput.value.trim();
      const fields = state.analysis?.fields || {};
      if (!key) { valueCell.textContent = ''; valueCell.classList.remove('muted-note'); return; }
      if (Object.prototype.hasOwnProperty.call(fields, key)) {
        valueCell.textContent = String(fields[key]).slice(0, 80);
        valueCell.classList.remove('muted-note');
      } else {
        valueCell.textContent = 'Not found in sample.';
        valueCell.classList.add('muted-note');
      }
    };
    sourceInput.addEventListener('input', updateObservedValue);
  }
  $('mapping-body').appendChild(tr);
}
function collectMappings() { const out={}; document.querySelectorAll('#mapping-body tr').forEach(tr=>{const s=tr.querySelector('.map-source').value.trim(); const t=tr.querySelector('.map-target').value.trim(); if(s&&t) out[s]=t;}); return out; }
async function analyzeUnknown() {
  const payload=$('unknown-payload').value; if(!payload.trim()) return toast('Paste or load an unknown payload.',true);
  try {
    const d=await api('/api/v1/onboarding/analyze',{method:'POST',body:JSON.stringify({payload})}); state.analysis=d;
    $('analysis-summary').className='analysis-summary'; $('analysis-summary').innerHTML=`<div><span class="badge">${esc(d.format_hint)}</span> <span class="badge subtle">${d.field_count} fields</span></div><div>${(d.structure_notes||[]).map(n=>`<span class="analysis-chip">${esc(n)}</span>`).join('')}</div>`;
    $('mapping-body').innerHTML=''; Object.entries(d.fields||{}).forEach(([k,v])=>addMappingRow(k,v,d.suggested_mappings?.[k] || ''));
    toast(`Detected ${d.field_count} candidate field(s) without activating a parser.`);
  } catch(e){toast(`Analysis failed: ${e.message}`,true);}
}
async function loadUnknownState() {
  try {
    const [q,drafts]=await Promise.all([api('/api/v1/quarantine?limit=8'),api('/api/v1/onboarding/drafts?limit=8')]); const items=[];
    q.forEach(x=>items.push(`<div class="result-item"><strong class="status-quarantined">${esc(x.reason)}</strong><span>quarantine</span><code>${esc(x.raw_event_id)}</code><button class="button small use-quarantine" data-payload="${encodeURIComponent(x.payload)}">Use</button></div>`));
    drafts.forEach(x=>items.push(`<div class="result-item"><strong>${esc(x.status)}</strong><span>${esc(x.plugin_id)}</span><code>${esc(x.draft_id)}</code><span></span></div>`));
    $('unknown-list').className=items.length?'result-list':'result-list empty-state'; $('unknown-list').innerHTML=items.join('') || 'No unknown events or drafts yet.';
    document.querySelectorAll('.use-quarantine').forEach(btn=>btn.addEventListener('click',()=>{$('unknown-payload').value=decodeURIComponent(btn.dataset.payload); analyzeUnknown();}));
  } catch(e){toast(e.message,true);}
}
async function runPreview(save=false) {
  const payload=$('unknown-payload').value; if(!payload.trim()) return toast('Unknown payload is empty.',true);
  const body={payload,mappings:collectMappings(),vendor:$('draft-vendor').value.trim()||'Unknown',product:$('draft-product').value.trim()||'Unknown',plugin_id:$('draft-plugin').value.trim()||'draft_plugin'};
  try {
    if(save){const d=await api('/api/v1/onboarding/drafts',{method:'POST',body:JSON.stringify(body)}); toast(`Draft ${d.draft_id} saved. Auto-activated: ${d.auto_activated}.`); await loadUnknownState(); return;}
    const d=await api('/api/v1/onboarding/preview',{method:'POST',body:JSON.stringify(body)}); $('preview-json').textContent=pretty(d.normalized_preview); const ok=d.validation.ready_for_plugin_review; $('preview-status').textContent=ok?'Ready for review':'Needs mapping'; $('preview-status').className=`badge ${ok?'':'warning'}`; if(d.validation.missing_recommended_fields.length) toast(`Preview: missing ${d.validation.missing_recommended_fields.join(', ')}`); else toast('Preview generated. Draft still requires human review.');
  } catch(e){toast(`Preview failed: ${e.message}`,true);}
}
$('load-unknown').addEventListener('click',async()=>{try{const d=await loadDataset('unknown',false);$('unknown-payload').value=d.events[0]||d.payload;analyzeUnknown();}catch(e){toast(e.message,true);}});
$('analyze-unknown').addEventListener('click',analyzeUnknown); $('add-mapping').addEventListener('click',()=>addMappingRow('','','',true)); $('preview-mapping').addEventListener('click',()=>runPreview(false)); $('save-draft').addEventListener('click',()=>runPreview(true));

// ---- Registry: Unknown / Draft Parsers queue + review + test + register ----
async function loadDrafts() {
  try {
    const drafts = await api('/api/v1/onboarding/drafts?limit=20');
    const pending = drafts.filter(d => d.status !== 'REGISTERED');
    const el = $('drafts-grid');
    $('drafts-empty').style.display = pending.length ? 'none' : 'block';
    el.innerHTML = pending.map(d => `<article class="plugin-card draft-card"><div class="plugin-top"><div><h4>${esc(d.vendor)} · ${esc(d.product)}</h4><p>${esc(d.plugin_id)}</p></div><span class="badge warning">${esc(d.status.replace(/_/g,' '))}</span></div><div class="button-row"><button class="button small review-draft" data-draft="${esc(d.draft_id)}">Review &amp; register</button></div></article>`).join('');
    el.querySelectorAll('.review-draft').forEach(btn => btn.addEventListener('click', () => openDraftReview(btn.dataset.draft)));
  } catch (e) { toast(`Drafts failed: ${e.message}`, true); }
}
$('add-parser').addEventListener('click', () => switchScreen('onboarding'));

function currentDetectionRules() {
  const markers = $('draft-detection-all').value.split(',').map(s => s.trim()).filter(Boolean);
  return { confidence: 0.75, rules: { all_contains: markers } };
}

async function openDraftReview(draftId) {
  try {
    const d = await api(`/api/v1/onboarding/drafts/${draftId}`);
    state.currentDraft = d;
    $('draft-review-title').textContent = `${d.vendor} · ${d.product} — ${d.plugin_id}`;
    const fields = d.analysis.fields || {};
    $('draft-mapping-body').innerHTML = Object.entries(d.mappings).map(([s,t]) => `<tr><td>${esc(s)}</td><td><code>${esc(String(fields[s] ?? 'Not found in sample.')).slice(0,60)}</code></td><td>${esc(t)}</td></tr>`).join('') || '<tr><td colspan="3">No mappings were saved with this draft.</td></tr>';
    const markers = (d.analysis.suggested_detection?.rules?.all_contains) || [];
    $('draft-detection-all').value = markers.join(', ');
    $('draft-test-payload').value = '';
    $('draft-test-result').textContent = 'Paste another raw log above and run a test to see whether these rules match it and how it would map.';
    $('draft-review-panel').classList.remove('hidden');
    $('draft-review-panel').scrollIntoView({behavior:'smooth', block:'start'});
  } catch (e) { toast(`Review failed: ${e.message}`, true); }
}
$('close-draft-review').addEventListener('click', () => $('draft-review-panel').classList.add('hidden'));

$('draft-test-btn').addEventListener('click', async () => {
  const draft = state.currentDraft; if (!draft) return;
  const payload = $('draft-test-payload').value;
  if (!payload.trim()) return toast('Paste a log to test the draft against.', true);
  try {
    const body = { payload, detection_rules: currentDetectionRules() };
    const d = await api(`/api/v1/onboarding/drafts/${draft.draft_id}/test`, {method:'POST', body: JSON.stringify(body)});
    const verdict = d.detection.matched ? 'MATCH — this log would be recognized' : 'NO MATCH — detection rules need adjusting';
    $('draft-test-result').textContent = `${verdict}\n\n${pretty(d.normalized_preview)}`;
  } catch (e) { toast(`Test failed: ${e.message}`, true); }
});

$('draft-register-btn').addEventListener('click', async () => {
  const draft = state.currentDraft; if (!draft) return;
  try {
    const body = { detection_rules: currentDetectionRules() };
    const d = await api(`/api/v1/onboarding/drafts/${draft.draft_id}/register`, {method:'POST', body: JSON.stringify(body)});
    toast(`${d.id} registered — now live in the active registry, no restart needed.`);
    $('draft-review-panel').classList.add('hidden');
    loadRegistry(); loadDrafts(); loadOverview();
  } catch (e) { toast(`Register failed: ${e.message}`, true); }
});

loadOverview();
