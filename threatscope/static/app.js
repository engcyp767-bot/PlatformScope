const nativeFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const response = await nativeFetch(input, {...init, credentials: 'include'});
  if (response.status === 401) {
    const next = encodeURIComponent(`${location.pathname}${location.search}`);
    location.replace(`/login.html?next=${next}`);
  }
  return response;
};
const API_BASE = `${window.location.protocol}//${window.location.hostname}:8081/api/threatscope`;
const state = { file: null, jobId: null, analysis: null, config: null, poller: null, openedFromHistory: false, missingNotified: false, permissions: [], previewObjectUrl: null };
const $ = (id) => document.getElementById(id);
const arNumber = (value) => new Intl.NumberFormat('ar').format(value ?? 0);
const esc = (value) => String(value ?? '—').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

function rememberJobRoute(jobId, openedFromHistory = false) {
  if (!/^[0-9a-f]{32}$/.test(String(jobId || ''))) return;
  const url = new URL(window.location.href);
  url.search = '';
  url.searchParams.set('job', jobId);
  window.history.replaceState(
    { app: 'threatscope', jobId, openedFromHistory },
    '',
    `${url.pathname}${url.search}`
  );
}

function clearJobRoute() {
  window.history.replaceState({}, '', window.location.pathname);
}

function can(permission) { return state.permissions.includes(permission); }

async function loadAccess() {
  try {
    const response = await fetch(`${window.location.protocol}//${window.location.hostname}:8081/api/auth/status`, {cache:'no-store'});
    const data = await response.json(); state.permissions = data.user?.permissions || [];
    const show = (id, allowed) => { const element = $(id); if (element) element.style.display = allowed ? '' : 'none'; };
    show('dropZone', can('threatscope.analyze')); show('analyzeButton', can('threatscope.analyze'));
    const sourcePicker = $('sourceSystem').closest('.source-system-picker');
    if (sourcePicker) sourcePicker.style.display = can('threatscope.analyze') ? '' : 'none';
    show('enrichButton', can('threatscope.enrich'));
    const refresh = $('forceRefreshToggle').closest('label');
    if (refresh) refresh.style.display = can('threatscope.enrich') ? '' : 'none';
    ['excelLink','reportLink','wordLink'].forEach(id => show(id, can('threatscope.export')));
    show('deleteJob', can('threatscope.delete'));
  } catch (_) {}
}

async function api(url, options = {}) {
  const target = url.startsWith('/api/') ? `${API_BASE}${url.slice(4)}` : url;
  const response = await fetch(target, options);
  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new Error(payload.error || `خطأ HTTP ${response.status}`);
  return payload;
}

async function loadConfig() {
  try {
    state.config = await api('/api/config');
    $('limitText').textContent = `XLSX أو CSV · حد أقصى ${state.config.max_upload_mb} MB`;
  } catch (_) {}
}

function chooseFile(file) {
  $('uploadError').classList.add('hidden');
  if (!file || !/\.(xlsx|csv)$/i.test(file.name)) return showError('الصيغ المدعومة هي XLSX وCSV فقط.');
  const max = (state.config?.max_upload_mb || 20) * 1024 * 1024;
  if (file.size > max) return showError(`حجم الملف يتجاوز ${state.config?.max_upload_mb || 20} ميجابايت.`);
  state.file = file;
  $('fileName').textContent = 'بيانات التهديدات جاهزة للتحليل';
  $('fileSize').textContent = `${(file.size / 1024).toFixed(1)} KB`;
  $('selectedFile').classList.remove('hidden');
  $('analyzeButton').disabled = false;
}

function clearFile() {
  state.file = null; $('fileInput').value = ''; $('selectedFile').classList.add('hidden'); $('analyzeButton').disabled = true;
}

function showError(message) {
  $('uploadError').textContent = message; $('uploadError').classList.remove('hidden');
}

async function analyze() {
  if (!state.file) return;
  const sourceSystem = $('sourceSystem').value;
  if (!sourceSystem) { showError('اختر نظام XDR المصدر قبل بدء التحليل.'); $('sourceSystem').focus(); return; }
  $('progress').classList.remove('hidden'); $('analyzeButton').disabled = true; $('uploadError').classList.add('hidden');
  try {
    const contentType = state.file.name.toLowerCase().endsWith('.csv') ? 'text/csv' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    const result = await api('/api/analyze', { method: 'POST', headers: { 'Content-Type': contentType, 'X-Filename': encodeURIComponent(state.file.name), 'X-Source-System': sourceSystem }, body: state.file });
    state.jobId = result.job_id;
    state.analysis = result.analysis;
    state.openedFromHistory = false;
    rememberJobRoute(state.jobId, false);
    showDashboard();
  } catch (error) {
    showError(error.message); $('analyzeButton').disabled = false;
  } finally { $('progress').classList.add('hidden'); }
}

function showDashboard() {
  $('uploadView').classList.add('hidden'); $('dashboardView').classList.remove('hidden'); $('newAnalysis').classList.remove('hidden');
  $('reportLink').href = `${API_BASE}/report/${state.jobId}`; $('excelLink').href = `${API_BASE}/export/${state.jobId}.xlsx`; $('wordLink').href = `${API_BASE}/export/${state.jobId}.docx`;
  $('newAnalysis').textContent = state.openedFromHistory ? 'العودة للسجل' : 'تحليل جديد';
  render(); syncPolling(); window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function openWordPreview() {
  if (!state.jobId) return;
  const overlay = $('wordPreviewOverlay');
  const frame = $('wordPreviewFrame');
  const snapshot = Array.from(crypto.getRandomValues(new Uint8Array(12)), value => value.toString(16).padStart(2, '0')).join('');
  overlay.hidden = false; overlay.classList.add('loading'); document.body.style.overflow = 'hidden';
  $('previewDownloadWord').href = `${API_BASE}/export/${state.jobId}.docx?snapshot=${snapshot}`;
  frame.src = 'about:blank';
  if (state.previewObjectUrl) URL.revokeObjectURL(state.previewObjectUrl);
  state.previewObjectUrl = null;
  try {
    const response = await fetch(`${API_BASE}/report/${state.jobId}?snapshot=${snapshot}`, {cache: 'no-store'});
    if (!response.ok) {
      let message = `تعذر إنشاء المعاينة (${response.status})`;
      try { message = (await response.json()).error || message; } catch (_) {}
      throw new Error(message);
    }
    const blob = await response.blob();
    if (!blob.type.toLowerCase().includes('pdf')) throw new Error('استجابة المعاينة ليست ملف PDF صالحًا.');
    if (overlay.hidden) return;
    state.previewObjectUrl = URL.createObjectURL(new Blob([blob], {type: 'application/pdf'}));
    frame.onload = () => overlay.classList.remove('loading');
    frame.src = state.previewObjectUrl;
  } catch (error) {
    closeWordPreview();
    alert(error.message);
  }
}

function closeWordPreview() {
  $('wordPreviewOverlay').hidden = true; $('wordPreviewOverlay').classList.remove('loading');
  $('wordPreviewFrame').src = 'about:blank'; document.body.style.overflow = '';
  if (state.previewObjectUrl) URL.revokeObjectURL(state.previewObjectUrl);
  state.previewObjectUrl = null;
}

function card(label, value, note, alert = false) {
  return `<div class="summary-card ${alert ? 'alert' : ''}"><span>${esc(label)}</span><b>${arNumber(value)}</b><small>${esc(note)}</small></div>`;
}

function render() {
  const a = state.analysis, s = a.summary, m = a.metadata;
  $('dashboardTitle').textContent = 'تحليل التهديدات الأمنية';
  $('dashboardMeta').textContent = `${m.source_system_label || 'غير محدد — ملف سابق'} · ${s.records} سجل تهديد · ${s.unique_hashes} مؤشر فريد · تم التحليل ${new Date(m.analyzed_at).toLocaleString('ar')}`;
  const learning = a.learning || {};
  $('summaryCards').innerHTML = card('إجمالي السجلات', s.records, `${m.column_count} عمود`) + card('الهاشات الفريدة', s.unique_hashes, `${s.invalid_hashes} غير صالح`) + card('غير محلولة', s.unresolved, `${Math.round((s.unresolved / Math.max(s.records, 1)) * 100)}% من السجلات`, s.unresolved > 0) + card('حرجة ومرتفعة', s.critical + s.high, `${s.critical} حرجة`, s.critical > 0) + card('إجراءات معلقة', s.pending_actions, 'تحتاج متابعة', s.pending_actions > 0) + (learning.status === 'active' ? card('النموذج المحلي', learning.notable_records, `استشاري · ${learning.baseline_observations || 0} ملاحظة`, learning.notable_records > 0) : '');
  renderModelAnalysis();
  renderBars('classificationChart', a.distributions.classification, 6);
  renderBars('endpointChart', a.distributions.endpoint, 7);
  $('qualityList').innerHTML = qualityItem('صفوف مكررة', a.quality.duplicate_rows) + qualityItem('هاش غير صالح', a.quality.invalid_hashes) + qualityItem('أعمدة فارغة', a.quality.blank_columns.length) + qualityItem('خلايا صيغ', a.quality.formula_cells);
  renderProviders(); renderFindings();
}

function renderModelAnalysis() {
  const analysis = state.analysis?.model_analysis || {}, panel = $('modelAnalysisPanel');
  if (!['queued', 'running', 'completed'].includes(analysis.status)) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.remove('hidden');
  if (analysis.status !== 'completed') {
    $('modelAnalysisStatus').textContent = analysis.status === 'queued' ? 'في قائمة الانتظار' : 'جارٍ التحليل…';
    $('modelAnalysisStatus').className = 'status-pill running';
    $('modelAnalysisSummary').textContent = 'النتائج الأساسية متاحة الآن، ويجري إعداد قراءة مترابطة للتنبيهات والأدلة في الخلفية.';
    $('modelAnalysisPatterns').innerHTML = '';
    $('modelAnalysisRecommendations').innerHTML = '';
    return;
  }
  const result = analysis.result || {};
  $('modelAnalysisStatus').textContent = `${result.overall_assessment || 'اكتمل'} · ثقة ${arNumber(result.confidence || 0)}%`;
  $('modelAnalysisStatus').className = 'status-pill done';
  $('modelAnalysisSummary').textContent = result.executive_summary_ar || '';
  const patterns = (result.patterns || []).map(item => `<div class="model-analysis-item">${esc(item)}</div>`).join('');
  $('modelAnalysisPatterns').innerHTML = patterns ? `<b>الأنماط المترابطة</b>${patterns}` : '';
  const recommendations = (result.recommendations || []).map(item => `<div class="model-analysis-item">${esc(item)}</div>`).join('');
  $('modelAnalysisRecommendations').innerHTML = recommendations ? `<b>الإجراءات المقترحة</b>${recommendations}` : '';
}

function syncPolling() {
  const intelBusy = state.analysis?.enrichment?.status === 'running';
  const modelBusy = ['queued', 'running'].includes(state.analysis?.model_analysis?.status);
  if ((intelBusy || modelBusy) && !state.poller) state.poller = setInterval(refreshJob, 1500);
  if (!intelBusy && !modelBusy && state.poller) { clearInterval(state.poller); state.poller = null; }
}

function qualityItem(label, value) { return `<div class="quality-item"><b>${arNumber(value)}</b><span>${esc(label)}</span></div>`; }

function renderBars(target, values, limit) {
  const entries = Object.entries(values || {}).slice(0, limit), max = Math.max(...entries.map(([,v]) => v), 1);
  $(target).innerHTML = entries.map(([name, value]) => `<div class="bar-item"><span title="${esc(name)}">${esc(name)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(3, value/max*100)}%"></div></div><b>${arNumber(value)}</b></div>`).join('') || '<p>لا توجد بيانات.</p>';
}

function renderProviders() {
  const intel = state.analysis.enrichment || {}, providers = intel.providers || {};
  const configProviders = state.config?.providers || {};
  $('providerList').innerHTML = ['virustotal','malwarebazaar'].map(name => {
    const configured = configProviders[name]?.enabled, stats = providers[name] || {};
    const fallback = stats.fallback_hits ? ` · ${stats.fallback_hits} بديلة محفوظة` : '';
    const failures = stats.refresh_failures ? ` · ${stats.refresh_failures} تعذر تحديثها` : '';
    return `<div class="provider"><div><b>${name === 'virustotal' ? 'VirusTotal' : 'MalwareBazaar'}</b><small>${stats.cache_hits || 0} محفوظة · ${stats.queries || 0} طلب جديد · ${stats.errors || 0} أخطاء${fallback}${failures}</small></div><span class="provider-state ${configured ? 'on' : ''}">${configured ? 'مفعّل' : 'يحتاج مفتاحًا'}</span></div>`;
  }).join('');
  const labels = { not_started:'لم يبدأ', running:'جارٍ الفحص…', completed:'اكتمل', completed_partial:'مكتمل جزئيًا', disabled:'غير مفعّل', failed:'فشل' };
  const cacheSummary = ['completed','completed_partial'].includes(intel.status) && Number.isFinite(intel.total)
    ? (intel.force_refresh
      ? (intel.status === 'completed_partial'
        ? ` · تعذر تحديث ${intel.refresh_failures || 0} · استُخدمت ${intel.fallback || 0} نتائج محفوظة`
        : ` · تم تحديث ${intel.total || 0} من المصادر`)
      : ` · ${intel.cached || 0} محفوظة · ${intel.new || 0} جديدة`)
    : '';
  $('intelStatus').textContent = `${labels[intel.status] || intel.status}${cacheSummary}`;
  $('intelStatus').className = `status-pill ${intel.status === 'running' ? 'running' : ['completed','disabled'].includes(intel.status) ? 'done' : intel.status === 'completed_partial' ? 'partial' : ''}`;
  const anyEnabled = Object.values(configProviders).some(item => item.enabled);
  $('providerNotice').classList.toggle('hidden', anyEnabled);
  if (!anyEnabled) $('providerNotice').textContent = 'لم تُضبط مفاتيح مصادر معلومات التهديدات بعد. التحليل المحلي مكتمل، ويمكنك إضافة المفاتيح في متغيرات البيئة ثم إعادة تشغيل الخادم.';
  $('enrichButton').disabled = intel.status === 'running';
  $('forceRefreshToggle').disabled = intel.status === 'running';
  $('enrichButton').textContent = intel.status === 'running'
    ? 'جارٍ فحص الهاشات…'
    : ($('forceRefreshToggle').checked ? 'تحديث مباشر من المصادر' : 'فحص الجديد واستخدام المحفوظ');
}

function riskClass(level) { return level === 'حرج' ? 'risk-critical' : level === 'مرتفع' ? 'risk-high' : level === 'متوسط' ? 'risk-medium' : 'risk-low'; }

function renderFindings() {
  const query = $('searchInput').value.trim().toLowerCase(), level = $('riskFilter').value;
  const records = state.analysis.records.map((record, index) => ({...record, __recordIndex:index})).sort((a,b) => b.risk_score - a.risk_score).filter(record => {
    const haystack = `${record.threat_name} ${record.hash} ${record.endpoint} ${record.classification}`.toLowerCase();
    return (!query || haystack.includes(query)) && (!level || record.risk_level === level);
  });
  $('findingsBody').innerHTML = records.slice(0, 100).map(record => {
    const ai = record.ai_assessment;
    const aiClass = !ai ? 'warming' : ai.score >= 70 ? 'high' : ai.score >= 40 ? 'notable' : 'normal';
    const aiText = ai ? `${arNumber(ai.score)}% · ${esc(ai.level)}` : 'قيد التعلّم';
    const feedback = record.analyst_feedback?.label || '';
    const option = (value, label) => `<option value="${value}" ${feedback === value ? 'selected' : ''}>${label}</option>`;
    const feedbackControl = can('threatscope.feedback') ? `<select class="feedback-select" onchange="saveFeedback(${record.__recordIndex},this)">${option('', 'أضف حكمًا')}${option('confirmed_threat', 'تهديد مؤكد')}${option('false_positive', 'إنذار كاذب')}${option('benign', 'نشاط سليم')}${option('needs_review', 'يحتاج مراجعة')}</select>` : esc(feedback || '—');
    return `<tr><td><span class="score">${arNumber(record.risk_score)}</span></td><td><span class="risk-badge ${riskClass(record.risk_level)}">${esc(record.risk_level)}</span></td><td><b>${esc(record.threat_name)}</b></td><td>${esc(record.endpoint)}</td><td>${esc(record.classification)}</td><td class="hash" title="${esc(record.hash)}">${esc(record.hash)}</td><td>${esc(record.incident_status)}</td><td><span class="ai-badge ${aiClass}" title="${esc((ai?.reasons || []).join(' · '))}">${aiText}</span></td><td>${feedbackControl}</td></tr>`;
  }).join('');
  $('tableFoot').textContent = `عرض ${Math.min(records.length, 100)} من ${records.length} نتيجة`;
}

async function saveFeedback(recordIndex, select) {
  const label = select.value;
  if (!label || !state.jobId) return;
  select.disabled = true;
  try {
    const result = await api(`/api/feedback/${state.jobId}/${recordIndex}`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({label})
    });
    state.analysis.records[recordIndex].analyst_feedback = result.feedback;
    select.classList.add('saved');
  } catch (error) { alert(error.message); }
  finally { select.disabled = false; }
}

async function startEnrichment() {
  const forceRefresh = $('forceRefreshToggle').checked;
  if (forceRefresh && !confirm('سيتم تجاهل النتائج المحفوظة وإعادة فحص جميع الهاشات من المصادر الخارجية. هل تريد المتابعة؟')) return;
  try {
    const suffix = forceRefresh ? '?force=1' : '';
    await api(`/api/enrich/${state.jobId}${suffix}`, { method: 'POST' });
    state.analysis.enrichment = { status: 'running', force_refresh: forceRefresh }; renderProviders();
    clearInterval(state.poller); state.poller = setInterval(refreshJob, 1500);
  } catch (error) { alert(error.message); }
}

async function refreshJob() {
  try {
    const result = await api(`/api/jobs/${state.jobId}`); state.analysis = result.analysis; render(); syncPolling();
  } catch (_) {
    if (state.openedFromHistory && !state.missingNotified) {
      state.missingNotified = true;
      if (state.poller) clearInterval(state.poller);
      alert('هذه المهمة لم تعد موجودة؛ ربما تم حذفها من السجل.');
      window.location.replace('http://127.0.0.1:8080/?history=1');
    }
  }
}

async function deleteJob() {
  if (!confirm('هل تريد حذف بيانات التهديدات ونتائج هذه المهمة نهائيًا؟')) return;
  try { await api(`/api/jobs/${state.jobId}`, { method: 'DELETE' }); reset(); } catch (error) { alert(error.message); }
}

function reset() {
  if (state.openedFromHistory) {
    if (state.poller) clearInterval(state.poller);
    window.location.href = 'http://127.0.0.1:8080/?history=1';
    return;
  }
  if (state.poller) clearInterval(state.poller); state.jobId = null; state.analysis = null; clearFile();
  state.openedFromHistory = false; state.missingNotified = false; clearJobRoute();
  $('sourceSystem').value = '';
  $('forceRefreshToggle').checked = false; $('forceRefreshToggle').disabled = false;
  $('dashboardView').classList.add('hidden'); $('uploadView').classList.remove('hidden'); $('newAnalysis').classList.add('hidden'); window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function openJobFromUrl() {
  const jobId = new URLSearchParams(window.location.search).get('job');
  if (!jobId) return;
  if (!/^[0-9a-f]{32}$/.test(jobId)) {
    alert('رابط المهمة غير صالح. سيتم إعادتك إلى سجل العمليات.');
    window.location.replace('http://127.0.0.1:8080/?history=1');
    return;
  }
  const routeState = window.history.state || {};
  state.openedFromHistory = !(
    routeState.app === 'threatscope'
    && routeState.jobId === jobId
    && routeState.openedFromHistory === false
  );
  state.jobId = jobId;
  try {
    const result = await api(`/api/jobs/${jobId}`);
    state.analysis = result.analysis;
    showDashboard();
    syncPolling();
  } catch (_) {
    alert('تعذر فتح المهمة؛ ربما تم حذفها من سجل العمليات.');
    window.location.replace('http://127.0.0.1:8080/?history=1');
  }
}

const dropZone = $('dropZone');
dropZone.addEventListener('click', () => $('fileInput').click());
dropZone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') $('fileInput').click(); });
$('fileInput').addEventListener('change', e => chooseFile(e.target.files[0]));
['dragenter','dragover'].forEach(type => dropZone.addEventListener(type, e => { e.preventDefault(); dropZone.classList.add('dragging'); }));
['dragleave','drop'].forEach(type => dropZone.addEventListener(type, e => { e.preventDefault(); dropZone.classList.remove('dragging'); }));
dropZone.addEventListener('drop', e => chooseFile(e.dataTransfer.files[0]));
$('clearFile').addEventListener('click', clearFile); $('analyzeButton').addEventListener('click', analyze); $('newAnalysis').addEventListener('click', reset);
$('enrichButton').addEventListener('click', startEnrichment); $('forceRefreshToggle').addEventListener('change', renderProviders); $('searchInput').addEventListener('input', renderFindings); $('riskFilter').addEventListener('change', renderFindings); $('deleteJob').addEventListener('click', deleteJob);
$('reportLink').addEventListener('click', openWordPreview); $('closeWordPreview').addEventListener('click', closeWordPreview);
$('wordPreviewOverlay').addEventListener('click', event => { if (event.target.id === 'wordPreviewOverlay') closeWordPreview(); });
document.addEventListener('keydown', event => { if (event.key === 'Escape' && !$('wordPreviewOverlay').hidden) closeWordPreview(); });
async function initialize() { await loadAccess(); await loadConfig(); await openJobFromUrl(); }
initialize();
