const nativeFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
    const response = await nativeFetch(input, {...init, credentials: 'include'});
    if (response.status === 401) {
        const next = encodeURIComponent(`${location.pathname}${location.search}`);
        location.replace(`/login.html?next=${next}`);
    }
    return response;
};
const API_BASE = `${window.location.protocol}//${window.location.hostname}:8081/api/flowscope`;

const app = {
    jobId: null,
    pollInterval: null,
    analysisData: null,
    busy: false,
    openedFromHistory: false,
    permissions: [],
    previewObjectUrl: null,

    async init() {
        await this.loadAccess();
        this.setupDragAndDrop();
        this.checkServerHealth();
        document.getElementById('word-preview-overlay').addEventListener('click', event => {
            if (event.target.id === 'word-preview-overlay') this.closeReportPreview();
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && !document.getElementById('word-preview-overlay').hidden) this.closeReportPreview();
        });
        await this.openJobFromUrl();
    },

    async loadAccess() {
        try {
            const response = await fetch(`${window.location.protocol}//${window.location.hostname}:8081/api/auth/status`, {cache:'no-store'});
            const payload = await response.json();
            this.permissions = payload.user?.permissions || [];
            const show = (id, allowed) => { const element = document.getElementById(id); if (element) element.style.display = allowed ? '' : 'none'; };
            show('drop-zone', this.can('flowscope.analyze'));
            const sourcePicker = document.getElementById('source-system').closest('.source-system-picker');
            if (sourcePicker) sourcePicker.style.display = this.can('flowscope.analyze') ? '' : 'none';
            show('btn-enrich', this.can('flowscope.enrich'));
            const refresh = document.getElementById('force-refresh-toggle').closest('label');
            if (refresh) refresh.style.display = this.can('flowscope.enrich') ? '' : 'none';
            show('btn-export-word', this.can('flowscope.export'));
            show('btn-export-excel', this.can('flowscope.export'));
            show('btn-preview-word', this.can('flowscope.export'));
        } catch (_) {}
    },

    can(permission) { return this.permissions.includes(permission); },

    rememberJobRoute(jobId, openedFromHistory = false) {
        if (!/^[0-9a-f]{32}$/.test(String(jobId || ''))) return;
        const url = new URL(window.location.href);
        url.search = '';
        url.searchParams.set('job', jobId);
        window.history.replaceState(
            { app: 'flowscope', jobId, openedFromHistory },
            '',
            `${url.pathname}${url.search}`
        );
    },

    clearJobRoute() {
        window.history.replaceState({}, '', window.location.pathname);
    },

    async openJobFromUrl() {
        const jobId = new URLSearchParams(window.location.search).get('job');
        if (!jobId) return;
        if (!/^[0-9a-f]{32}$/.test(jobId)) {
            alert('رابط المهمة غير صالح. سيتم إعادتك إلى سجل العمليات.');
            window.location.replace('http://127.0.0.1:8080/?history=1');
            return;
        }
        const routeState = window.history.state || {};
        this.openedFromHistory = !(
            routeState.app === 'flowscope'
            && routeState.jobId === jobId
            && routeState.openedFromHistory === false
        );
        this.jobId = jobId;
        this.busy = true;
        this.showProgress(5, 'جارٍ تحميل النتائج المحفوظة…');
        await this.loadJobData();
    },

    escapeHtml(value) {
        return String(value ?? '').replace(/[&<>'"]/g, character => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
        })[character]);
    },

    protocolLabel(record) {
        const names = {1:'ICMP',2:'IGMP',6:'TCP',17:'UDP',41:'IPv6',47:'GRE',50:'ESP',51:'AH',58:'ICMPv6',89:'OSPF',132:'SCTP'};
        let value = String(record.protocol || '').trim();
        if (!value) {
            const match = String(record.attributes || '').match(/\bProtocols?\s*=\s*\[([^\]]+)\]/i);
            value = match ? match[1] : '';
        }
        if (!value) return '-';
        return value.split(/[,;/\s]+/).filter(Boolean).map(token => names[token] || (/^\d+$/.test(token) ? `IP-${token}` : token.toUpperCase())).join('، ');
    },

    intelligencePriority(providers) {
        const vt = providers?.virustotal || {}, abuse = providers?.abuseipdb || {}, shodan = providers?.shodan || {};
        if (vt.verdict === 'malicious' || Number(vt.malicious) >= 3 || Number(abuse.score) >= 75 || shodan.verdict === 'malicious') return 3;
        if (vt.verdict === 'suspicious' || Number(vt.suspicious) > 0 || Number(abuse.score) >= 25 || shodan.verdict === 'suspicious') return 2;
        if (['clean','ok'].includes(vt.verdict) || vt.source_status === 'ok' || abuse.source_status === 'ok' || shodan.source_status === 'ok') return 1;
        return 0;
    },

    eventIntelligence(record, results) {
        const usable = (ip) => {
            const providers = results[String(ip || '').trim()];
            return providers && typeof providers === 'object' && !providers.reason ? providers : null;
        };
        const source = String(record.event_source || '').trim();
        const sourceResult = usable(source);
        if (sourceResult) return {ip: source, providers: sourceResult, relation: 'المصدر'};
        const candidates = [...new Set(record.event_targets || [])]
            .map(ip => ({ip: String(ip).trim(), providers: usable(ip)}))
            .filter(item => item.ip && item.providers)
            .sort((a, b) => this.intelligencePriority(b.providers) - this.intelligencePriority(a.providers));
        return candidates.length ? {...candidates[0], relation: 'الهدف'} : null;
    },

    intelligenceSummary(match) {
        if (!match) return '<span>لا توجد نتيجة مرتبطة بهذا الحدث</span>';
        const priority = this.intelligencePriority(match.providers);
        const label = priority >= 3 ? 'خبيث' : priority === 2 ? 'مشبوه' : priority === 1 ? 'لا توجد دلالة ضارة' : 'غير متاح';
        const vt = match.providers.virustotal || {}, abuse = match.providers.abuseipdb || {};
        const evidence = [];
        if (Number(vt.malicious) > 0) evidence.push(`${Number(vt.malicious)} كشف ضار`);
        if (Number(vt.suspicious) > 0) evidence.push(`${Number(vt.suspicious)} كشف مشبوه`);
        if (Number(abuse.score) > 0) evidence.push(`درجة إساءة ${Number(abuse.score)}%`);
        return `<b>${this.escapeHtml(match.relation)} ${this.escapeHtml(match.ip)}: ${label}</b>${evidence.length ? `<small>${this.escapeHtml(evidence.join(' · '))}</small>` : ''}`;
    },

    async checkServerHealth() {
        try {
            const response = await fetch(`${API_BASE}/health`);
            if (response.ok) {
                const health = await response.json();
                document.getElementById('server-status').textContent = `متصل — v${health.version || '?'}`;
            } else {
                this.setServerStatusError();
            }
        } catch (e) {
            this.setServerStatusError();
        }
    },

    setServerStatusError() {
        const el = document.getElementById('server-status');
        el.textContent = 'غير متصل بالخادم';
        el.style.color = 'var(--danger)';
    },

    setupDragAndDrop() {
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');

        dropZone.addEventListener('click', () => fileInput.click());

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        ['dragleave', 'dragend'].forEach(type => {
            dropZone.addEventListener(type, (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
            });
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                this.handleFile(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                this.handleFile(e.target.files[0]);
            }
        });
    },

    async handleFile(file) {
        if (!file.name.endsWith('.csv') && !file.name.endsWith('.xlsx')) {
            alert('يرجى رفع ملف CSV أو XLSX فقط.');
            return;
        }
        const sourceSystem = document.getElementById('source-system').value;
        if (!sourceSystem) {
            alert('اختر نظام Flow المصدر قبل رفع الملف.');
            document.getElementById('source-system').focus();
            return;
        }

        if (this.busy) return;
        this.busy = true;
        this.showProgress(0, 'جاري رفع الملف...');

        try {
            const data = await this.uploadFile(file);

            this.jobId = data.job_id;
            this.openedFromHistory = false;
            this.rememberJobRoute(this.jobId, false);
            this.startPolling(500);
            await this.loadJobData();

        } catch (error) {
            alert(error.message);
            this.hideProgress();
            this.busy = false;
        }
    },

    uploadFile(file) {
        return new Promise((resolve, reject) => {
            const request = new XMLHttpRequest();
            request.open('POST', `${API_BASE}/analyze`);
            request.setRequestHeader('Content-Type', 'application/octet-stream');
            request.setRequestHeader('X-Filename', encodeURIComponent(file.name));
            request.setRequestHeader('X-Source-System', document.getElementById('source-system').value);
            request.upload.onprogress = event => {
                if (!event.lengthComputable) return;
                const percent = Math.round((event.loaded / event.total) * 100);
                this.showProgress(Math.min(percent, 95), `جاري رفع الملف... ${percent}%`);
            };
            request.onerror = () => reject(new Error('تعذر الاتصال بالخادم'));
            request.onload = () => {
                let data = {};
                try { data = JSON.parse(request.responseText); } catch (error) {}
                if (request.status < 200 || request.status >= 300) {
                    reject(new Error(data.error || 'حدث خطأ أثناء رفع الملف'));
                    return;
                }
                resolve(data);
            };
            request.send(file);
        });
    },

    showProgress(percent = 0, message = 'جاري التحليل...') {
        document.getElementById('upload-progress').style.display = 'block';
        const progressFill = document.getElementById('progress-fill');
        progressFill.style.width = `${percent}%`;
        progressFill.setAttribute('aria-valuenow', String(percent));
        document.getElementById('progress-text').textContent = message;
    },

    hideProgress() {
        document.getElementById('upload-progress').style.display = 'none';
        document.getElementById('progress-fill').style.width = '0%';
    },

    async loadJobData() {
        if (!this.jobId) return;

        try {
            const response = await fetch(`${API_BASE}/jobs/${this.jobId}`);
            if (!response.ok) {
                if (this.openedFromHistory && response.status === 404) {
                    this.stopPolling();
                    alert('هذه المهمة لم تعد موجودة؛ ربما تم حذفها من السجل.');
                    window.location.replace('http://127.0.0.1:8080/?history=1');
                    return;
                }
                throw new Error('فشل تحميل بيانات المهمة');
            }
            
            this.analysisData = await response.json();
            const analysis = this.analysisData.analysis || { status: 'completed', progress: 100 };

            if (analysis.status === 'queued' || analysis.status === 'running') {
                const count = analysis.total > 0 ? ` — ${analysis.processed} من ${analysis.total}` : '';
                const percent = Number(analysis.progress) || 0;
                this.showProgress(percent, `${analysis.stage || 'جاري التحليل'} — ${percent}%${count}`);
                this.startPolling(500);
                return;
            }

            if (analysis.status === 'error') {
                this.stopPolling();
                this.busy = false;
                throw new Error(analysis.error || 'فشل تحليل الملف');
            }

            this.busy = false;
            this.hideProgress();
            this.renderDashboard();
            
            // Check if enrichment is running
            const modelBusy = ['queued', 'running'].includes(this.analysisData.model_analysis?.status);
            if ((this.analysisData.enrichment && ['running', 'cancelling'].includes(this.analysisData.enrichment.status)) || modelBusy) {
                this.startPolling(1000);
            } else {
                this.stopPolling();
            }

        } catch (error) {
            console.error(error);
            alert(error.message);
            if (this.analysisData?.analysis?.status === 'error') {
                this.hideProgress();
                document.getElementById('file-input').value = '';
            }
        }
    },

    startPolling(delay) {
        if (this.pollInterval && this.pollDelay === delay) return;
        this.stopPolling();
        this.pollDelay = delay;
        this.pollInterval = setInterval(() => this.loadJobData(), delay);
    },

    stopPolling() {
        if (this.pollInterval) clearInterval(this.pollInterval);
        this.pollInterval = null;
        this.pollDelay = null;
    },

    renderDashboard() {
        document.getElementById('upload-view').style.display = 'none';
        document.getElementById('dashboard-view').style.display = 'block';
        
        const meta = this.analysisData.metadata;
        const summary = this.analysisData.summary;
        document.getElementById('btn-close-job').textContent = this.openedFromHistory ? 'العودة للسجل' : 'إغلاق';
        
        document.getElementById('data-type-badge').textContent = 
            `${meta.data_type === 'ads_events' ? 'أحداث ADS' : 'تدفقات شبكية'} · ${meta.source_system_label || 'غير محدد — ملف سابق'}`;

        // Render Stats
        const statsHtml = [];
        statsHtml.push(`
            <div class="stat-card glass-panel">
                <span class="stat-label">إجمالي السجلات</span>
                <span class="stat-value">${summary.records}</span>
            </div>
            <div class="stat-card glass-panel">
                <span class="stat-label">عناوين IP الفريدة</span>
                <span class="stat-value">${summary.unique_ips}</span>
            </div>
        `);
        
        if (meta.data_type === 'ads_events') {
            statsHtml.push(`
                <div class="stat-card glass-panel">
                    <span class="stat-label">أحداث حرجة</span>
                    <span class="stat-value stat-critical">${summary.critical || 0}</span>
                </div>
                <div class="stat-card glass-panel">
                    <span class="stat-label">أحداث مرتفعة</span>
                    <span class="stat-value stat-high">${summary.high || 0}</span>
                </div>
            `);
        } else {
            statsHtml.push(`
                <div class="stat-card glass-panel">
                    <span class="stat-label">إجمالي البيانات</span>
                    <span class="stat-value stat-high">${summary.formatted_bytes || 0}</span>
                </div>
                <div class="stat-card glass-panel">
                    <span class="stat-label">إجمالي الحزم</span>
                    <span class="stat-value">${summary.total_packets || 0}</span>
                </div>
            `);
        }
        const learning = this.analysisData.learning || {};
        if (learning.status === 'active') {
            statsHtml.push(`
                <div class="stat-card glass-panel ai-stat-card">
                    <span class="stat-label">النموذج المحلي · استشاري</span>
                    <span class="stat-value">${Number(learning.notable_records) || 0}</span>
                    <small>نتيجة ملحوظة من ${Number(learning.baseline_observations) || 0} ملاحظة تاريخية</small>
                </div>
            `);
        }
        
        document.getElementById('stats-container').innerHTML = statsHtml.join('');
        this.renderModelAnalysis();

        // Enrichment Panel
        const enrich = this.analysisData.enrichment;
        if (enrich && enrich.status !== 'not_started') {
            document.getElementById('enrichment-panel').style.display = 'block';
            const enrichmentBusy = ['running', 'cancelling'].includes(enrich.status);
            const refreshToggle = document.getElementById('force-refresh-toggle');
            refreshToggle.disabled = enrichmentBusy;
            document.getElementById('btn-enrich').disabled = enrichmentBusy || (enrich.status === 'completed' && !refreshToggle.checked);
            const cancelButton = document.getElementById('btn-cancel-enrich');
            cancelButton.style.display = ['running', 'cancelling'].includes(enrich.status) ? 'inline-flex' : 'none';
            cancelButton.disabled = enrich.status === 'cancelling';
            
            const badge = document.getElementById('enrich-status-badge');
            const checked = enrich.checked || 0;
            const total = enrich.total || 0;
            const cached = enrich.cached || 0;
            const newAddresses = enrich.new || 0;
            const forceRefresh = Boolean(enrich.force_refresh);
            const pct = total > 0 ? Math.round((checked / total) * 100) : 0;
            
            if (enrich.status === 'running') {
                badge.textContent = `${forceRefresh ? 'جاري التحديث من المصادر' : 'جاري الفحص'}... ${checked} / ${total} (${pct}%)`;
                badge.style.background = 'var(--warning)';
                badge.style.color = '#000';
            } else if (enrich.status === 'completed') {
                badge.textContent = forceRefresh
                    ? `اكتمل التحديث ✓ ${total} عنوان من المصادر الخارجية`
                    : `مكتمل ✓ ${total} عنوان — ${cached} محفوظة | ${newAddresses} جديدة`;
                badge.style.background = 'var(--success)';
                badge.style.color = '#fff';
            } else if (enrich.status === 'error') {
                badge.textContent = 'خطأ في الفحص';
                badge.style.background = 'var(--danger)';
                badge.style.color = '#fff';
            } else if (enrich.status === 'interrupted') {
                badge.textContent = 'توقف الفحص — يمكنك إعادة تشغيله';
                badge.style.background = 'var(--warning)';
                badge.style.color = '#000';
            } else if (enrich.status === 'cancelling') {
                badge.textContent = 'جاري إلغاء الفحص...';
                badge.style.background = 'var(--warning)';
                badge.style.color = '#000';
            } else if (enrich.status === 'cancelled') {
                badge.textContent = 'تم إلغاء الفحص';
                badge.style.background = 'var(--danger)';
                badge.style.color = '#fff';
            } else {
                badge.textContent = enrich.status;
            }

            let progressBarHtml = '';
            if (enrich.status === 'running') {
                progressBarHtml = `
                    <div class="enrich-progress-wrap">
                        <div class="enrich-progress-bar">
                            <div class="enrich-progress-fill ${total ? '' : 'is-indeterminate'}" style="width: ${total ? pct : 35}%"></div>
                        </div>
                        <span class="enrich-progress-text">${total ? (forceRefresh ? `${checked} من ${total} عنوان — تحديث مباشر — ${pct}%` : `${checked} من ${total} عنوان — ${cached} محفوظة | ${newAddresses} جديدة — ${pct}%`) : 'جاري إعداد قائمة الفحص...'}</span>
                    </div>
                `;
            }

            const provHtml = [];
            for (const [name, data] of Object.entries(enrich.providers || {})) {
                if (!data.enabled) continue;
                provHtml.push(`
                    <div class="provider-card">
                        <strong>${this.escapeHtml(name)}</strong>
                        <span>${Number(data.queries) || 0} استعلام جديد | ${Number(data.cache_hits) || 0} محفوظ | ${Number(data.errors) || 0} خطأ</span>
                    </div>
                `);
            }
            document.getElementById('providers-container').innerHTML = progressBarHtml + provHtml.join('');
        }

        this.renderTable();
    },

    renderModelAnalysis() {
        const panel = document.getElementById('model-analysis-panel');
        const analysis = this.analysisData?.model_analysis || {};
        if (!['queued', 'running', 'completed'].includes(analysis.status)) {
            panel.style.display = 'none';
            return;
        }
        panel.style.display = 'block';
        const status = document.getElementById('model-analysis-status');
        const summary = document.getElementById('model-analysis-summary');
        const patterns = document.getElementById('model-analysis-patterns');
        const recommendations = document.getElementById('model-analysis-recommendations');
        if (analysis.status !== 'completed') {
            status.textContent = analysis.status === 'queued' ? 'في قائمة الانتظار' : 'جارٍ الربط والتحليل…';
            summary.textContent = 'النتائج الأساسية متاحة الآن، ويجري إعداد قراءة مترابطة للأحداث والأدلة في الخلفية.';
            patterns.innerHTML = '';
            recommendations.innerHTML = '';
            return;
        }
        const result = analysis.result || {};
        status.textContent = `${result.overall_assessment || 'اكتمل'} · ثقة ${Number(result.confidence) || 0}%`;
        summary.textContent = result.executive_summary_ar || '';
        const patternItems = (result.patterns || []).map(item => `<div class="model-analysis-item">${this.escapeHtml(item)}</div>`).join('');
        patterns.innerHTML = patternItems ? `<b>الأنماط المترابطة</b>${patternItems}` : '';
        const recommendationItems = (result.recommendations || []).map(item => `<div class="model-analysis-item">${this.escapeHtml(item)}</div>`).join('');
        recommendations.innerHTML = recommendationItems ? `<b>الإجراءات المقترحة</b>${recommendationItems}` : '';
    },

    renderTable() {
        const meta = this.analysisData.metadata;
        const records = this.analysisData.records || [];
        const thead = document.getElementById('table-head');
        const tbody = document.getElementById('table-body');
        
        const enrichResults = (this.analysisData.enrichment || {}).results || {};

        const aiCell = (record) => {
            const assessment = record.ai_assessment;
            if (!assessment) return '<span class="ai-badge warming">قيد التعلّم</span>';
            const reasons = (assessment.reasons || []).join(' · ');
            const levelClass = assessment.score >= 70 ? 'high' : assessment.score >= 40 ? 'notable' : 'normal';
            return `<span class="ai-badge ${levelClass}" title="${this.escapeHtml(reasons)}">${Number(assessment.score) || 0}% · ${this.escapeHtml(assessment.level)}</span>`;
        };
        const feedbackCell = (record, index) => {
            const selected = record.analyst_feedback?.label || '';
            if (!this.can('flowscope.feedback')) return this.escapeHtml(selected || '—');
            const option = (value, label) => `<option value="${value}" ${selected === value ? 'selected' : ''}>${label}</option>`;
            return `<select class="feedback-select" aria-label="حكم المحلل" onchange="app.saveFeedback(${index}, this)">
                ${option('', 'أضف حكمًا')}${option('confirmed_threat', 'تهديد مؤكد')}${option('false_positive', 'إنذار كاذب')}${option('benign', 'نشاط سليم')}${option('needs_review', 'يحتاج مراجعة')}
            </select>`;
        };

        if (meta.data_type === 'ads_events') {
            thead.innerHTML = `<tr>
                <th>الدرجة</th>
                <th>الخطورة</th>
                <th>نوع الحدث</th>
                <th>المصدر</th>
                <th>الوجهة</th>
                <th>البروتوكول</th>
                <th>نتيجة التحليل المرتبطة</th>
                <th>تقدير النموذج</th>
                <th>حكم المحلل</th>
            </tr>`;
            
            tbody.innerHTML = records.map((r, index) => {
                let riskClass = 'pill-low';
                if (r.severity === 'حرج') riskClass = 'pill-critical';
                if (r.severity === 'مرتفع') riskClass = 'pill-high';
                if (r.severity === 'متوسط') riskClass = 'pill-medium';
                
                const intelHtml = this.intelligenceSummary(this.eventIntelligence(r, enrichResults));

                return `
                <tr>
                    <td><strong>${Number(r.risk_score) || 0}</strong></td>
                    <td><span class="risk-pill ${riskClass}">${this.escapeHtml(r.severity)}</span></td>
                    <td>${this.escapeHtml(r.event_type)}</td>
                    <td dir="ltr" style="text-align: right;">${this.escapeHtml(r.event_source)}</td>
                    <td dir="ltr" style="text-align: right;">${this.escapeHtml((r.event_targets || []).join(', '))}</td>
                    <td>${this.escapeHtml(this.protocolLabel(r))}</td>
                    <td class="intel-result-cell">${intelHtml}</td>
                    <td>${aiCell(r)}</td>
                    <td>${feedbackCell(r, index)}</td>
                </tr>
                `;
            }).join('');
            
        } else {
            thead.innerHTML = `<tr>
                <th>المصدر</th>
                <th>الوجهة</th>
                <th>البروتوكول</th>
                <th>منفذ الوجهة</th>
                <th>البايتات</th>
                <th>استخبارات المصدر</th>
                <th>تقدير النموذج</th>
                <th>حكم المحلل</th>
            </tr>`;
            
            tbody.innerHTML = records.map((r, index) => {
                let intelHtml = '-';
                if (enrichResults[r.src_ip] && !enrichResults[r.src_ip].reason) {
                    const vt = enrichResults[r.src_ip].virustotal || {};
                    const ab = enrichResults[r.src_ip].abuseipdb || {};
                    intelHtml = `VT: ${this.escapeHtml(vt.verdict || '-')} | Abuse: ${Number(ab.score) || 0}%`;
                }
                return `
                <tr>
                    <td dir="ltr" style="text-align: right;">${this.escapeHtml(r.src_ip)}</td>
                    <td dir="ltr" style="text-align: right;">${this.escapeHtml(r.dst_ip)}</td>
                    <td>${this.escapeHtml(r.protocol)}</td>
                    <td>${this.escapeHtml(r.dst_port)}</td>
                    <td>${Number(r.bytes) || 0}</td>
                    <td style="font-size: 0.85em; color: var(--text-muted);">${intelHtml}</td>
                    <td>${aiCell(r)}</td>
                    <td>${feedbackCell(r, index)}</td>
                </tr>
                `;
            }).join('');
        }
    },

    async saveFeedback(recordIndex, select) {
        const label = select.value;
        if (!label || !this.jobId) return;
        select.disabled = true;
        try {
            const response = await fetch(`${API_BASE}/feedback/${this.jobId}/${recordIndex}`, {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({label})
            });
            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || 'تعذر حفظ حكم المحلل');
            this.analysisData.records[recordIndex].analyst_feedback = payload.feedback;
            select.classList.add('saved');
        } catch (error) {
            alert(error.message);
        } finally {
            select.disabled = false;
        }
    },

    async previewReport() {
        if (!this.jobId) return;
        const overlay = document.getElementById('word-preview-overlay');
        const frame = document.getElementById('word-preview-frame');
        const snapshot = Array.from(crypto.getRandomValues(new Uint8Array(12)), value => value.toString(16).padStart(2, '0')).join('');
        overlay.hidden = false;
        overlay.classList.add('loading');
        document.body.style.overflow = 'hidden';
        document.getElementById('preview-download-word').href = `${API_BASE}/export/${this.jobId}.docx?snapshot=${snapshot}`;
        frame.src = 'about:blank';
        if (this.previewObjectUrl) URL.revokeObjectURL(this.previewObjectUrl);
        this.previewObjectUrl = null;
        try {
            const response = await fetch(`${API_BASE}/preview/${this.jobId}.pdf?snapshot=${snapshot}`, {cache: 'no-store'});
            if (!response.ok) {
                let message = `تعذر إنشاء المعاينة (${response.status})`;
                try { message = (await response.json()).error || message; } catch (_) {}
                throw new Error(message);
            }
            const blob = await response.blob();
            if (!blob.type.toLowerCase().includes('pdf')) throw new Error('استجابة المعاينة ليست ملف PDF صالحًا.');
            if (overlay.hidden) return;
            this.previewObjectUrl = URL.createObjectURL(new Blob([blob], {type: 'application/pdf'}));
            frame.onload = () => overlay.classList.remove('loading');
            frame.src = this.previewObjectUrl;
        } catch (error) {
            this.closeReportPreview();
            alert(error.message);
        }
    },

    closeReportPreview() {
        const overlay = document.getElementById('word-preview-overlay');
        overlay.hidden = true;
        overlay.classList.remove('loading');
        document.getElementById('word-preview-frame').src = 'about:blank';
        document.body.style.overflow = '';
        if (this.previewObjectUrl) URL.revokeObjectURL(this.previewObjectUrl);
        this.previewObjectUrl = null;
    },

    filterTable() {
        const input = document.getElementById("search-input").value.toLowerCase();
        const rows = document.getElementById("table-body").getElementsByTagName("tr");
        for (let i = 0; i < rows.length; i++) {
            const text = rows[i].textContent.toLowerCase();
            rows[i].style.display = text.includes(input) ? "" : "none";
        }
    },

    syncEnrichmentMode() {
        const toggle = document.getElementById('force-refresh-toggle');
        const button = document.getElementById('btn-enrich');
        const status = (this.analysisData?.enrichment || {}).status;
        const busy = ['running', 'cancelling'].includes(status);
        button.disabled = busy || (status === 'completed' && !toggle.checked);
        button.innerHTML = toggle.checked
            ? '<span class="icon shield-icon"></span> تحديث مباشر للـ IPs'
            : '<span class="icon shield-icon"></span> إثراء الـ IPs';
    },

    async startEnrichment() {
        if (!this.jobId) return;
        const refreshToggle = document.getElementById('force-refresh-toggle');
        const forceRefresh = refreshToggle.checked;
        if (forceRefresh && !confirm('سيتم تجاهل النتائج المحفوظة وإعادة الاستعلام من المصادر الخارجية. هل تريد المتابعة؟')) return;
        try {
            document.getElementById('btn-enrich').disabled = true;
            refreshToggle.disabled = true;
            const suffix = forceRefresh ? '?force=1' : '';
            const res = await fetch(`${API_BASE}/enrich/${this.jobId}${suffix}`, { method: 'POST' });
            if (!res.ok) throw new Error('فشل بدء الإثراء');
            this.startPolling(1000);
            await this.loadJobData();
        } catch (e) {
            alert(e.message);
            document.getElementById('btn-enrich').disabled = false;
            refreshToggle.disabled = false;
        }
    },

    async cancelEnrichment() {
        if (!this.jobId) return;
        const button = document.getElementById('btn-cancel-enrich');
        button.disabled = true;
        try {
            const response = await fetch(`${API_BASE}/enrich/${this.jobId}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('تعذر إلغاء الفحص');
            this.startPolling(500);
            await this.loadJobData();
        } catch (error) {
            alert(error.message);
            button.disabled = false;
        }
    },

    exportReport(type) {
        if (!this.jobId) return;
        // A unique query value prevents browsers and download managers from
        // reopening a previously cached report for the same analysis job.
        window.open(`${API_BASE}/export/${this.jobId}.${type}?v=${Date.now()}`, '_blank');
    },

    newAnalysis() {
        this.stopPolling();
        this.jobId = null;
        this.analysisData = null;
        this.busy = false;
        this.openedFromHistory = false;
        this.clearJobRoute();
        document.getElementById('upload-view').style.display = 'block';
        document.getElementById('dashboard-view').style.display = 'none';
        document.getElementById('file-input').value = '';
        document.getElementById('source-system').value = '';
        document.getElementById('enrichment-panel').style.display = 'none';
        document.getElementById('btn-enrich').disabled = false;
        document.getElementById('force-refresh-toggle').checked = false;
        document.getElementById('force-refresh-toggle').disabled = false;
        this.syncEnrichmentMode();
        this.hideProgress();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    },

    async reset() {
        if (this.openedFromHistory) {
            this.stopPolling();
            window.location.href = 'http://127.0.0.1:8080/?history=1';
            return;
        }
        if (this.jobId) {
            try {
                await fetch(`${API_BASE}/jobs/${this.jobId}`, { method: 'DELETE' });
            } catch (e) {}
        }
        this.stopPolling();
        
        this.jobId = null;
        this.analysisData = null;
        this.busy = false;
        this.openedFromHistory = false;
        this.clearJobRoute();
        document.getElementById('upload-view').style.display = 'block';
        document.getElementById('dashboard-view').style.display = 'none';
        document.getElementById('file-input').value = '';
        document.getElementById('source-system').value = '';
        document.getElementById('enrichment-panel').style.display = 'none';
        document.getElementById('btn-enrich').disabled = false;
        document.getElementById('force-refresh-toggle').checked = false;
        document.getElementById('force-refresh-toggle').disabled = false;
        this.syncEnrichmentMode();
        this.hideProgress();
    }
};

document.addEventListener('DOMContentLoaded', () => app.init());
