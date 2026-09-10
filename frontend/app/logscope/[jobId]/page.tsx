'use client';

import React, { useEffect, useRef, useState, use } from 'react';
import Link from 'next/link';
import { Navbar } from '../../../components/Navbar';
import { RiskBadge } from '../../../components/RiskBadge';
import { EnrichmentProgressBanner } from '../../../components/EnrichmentProgressBanner';
import {
  Activity,
  ArrowRight,
  Download,
  FileText,
  Search,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Eye,
  Info,
  CheckCircle,
  Network,
  Globe,
  Radio,
  Server,
  Terminal,
  Target,
  User,
  Laptop,
} from 'lucide-react';
import { fetchApi } from '../../../lib/api';
import { useTranslation } from '../../../lib/i18n';

// New SIEM / SOC Investigation Console Components
import { AnalysisMetadataBanner } from '../../../components/logscope/AnalysisMetadataBanner';
import { NavigationTabs, LogScopeTab } from '../../../components/logscope/NavigationTabs';
import { IncidentDashboard } from '../../../components/logscope/IncidentDashboard';
import { IncidentInvestigationDrawer } from '../../../components/logscope/IncidentInvestigationDrawer';
import { EntityInvestigationDrawer } from '../../../components/logscope/EntityInvestigationDrawer';
import { MitreMatrixView } from '../../../components/logscope/MitreMatrixView';
import { DetectionsView } from '../../../components/logscope/DetectionsView';
import { EntitiesView } from '../../../components/logscope/EntitiesView';
import { NetworkFlowView } from '../../../components/logscope/NetworkFlowView';
import { AdvancedFilterBar, ActiveFilters } from '../../../components/logscope/AdvancedFilterBar';
import { EventInvestigationPanel } from '../../../components/logscope/EventInvestigationPanel';
import { IncidentData } from '../../../components/logscope/IncidentCard';

export default function LogScopeJobPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { t } = useTranslation();
  const { jobId } = use(params);

  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [enriching, setEnriching] = useState(false);
  const [forceRefresh, setForceRefresh] = useState(false);

  // Investigation Navigation & Drawers State
  const [activeTab, setActiveTab] = useState<LogScopeTab>('events');
  const [selectedRecord, setSelectedRecord] = useState<any>(null);
  const [selectedIncident, setSelectedIncident] = useState<IncidentData | null>(null);
  const [selectedEntity, setSelectedEntity] = useState<{ type: 'user' | 'ip' | 'device'; value: string } | null>(null);

  // Advanced Filtering and Search State
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState<ActiveFilters>({});
  const [records, setRecords] = useState<any[]>([]);
  const [nextCursor, setNextCursor] = useState<number | null>(0);
  const [hasMore, setHasMore] = useState(true);
  const [recordsLoading, setRecordsLoading] = useState(false);

  const pollingActive = useRef(true);
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);
  const searchAbortController = useRef<AbortController | null>(null);
  const tabDefaultSetRef = useRef(false);

  const fetchRecords = async (
    cursor: number = 0,
    currentSearch: string = search,
    currentFilters: ActiveFilters = filters,
    replace: boolean = false
  ) => {
    if (searchAbortController.current) {
      searchAbortController.current.abort();
    }
    const abortController = new AbortController();
    searchAbortController.current = abortController;

    setRecordsLoading(true);
    try {
      const queryParams = new URLSearchParams({
        cursor: String(cursor),
        limit: '100',
      });
      if (currentSearch) queryParams.set('q', currentSearch);
      for (const [k, v] of Object.entries(currentFilters)) {
        if (v) queryParams.set(k, v);
      }

      const res = await fetch(`/api/logscope/jobs/${jobId}/records?${queryParams.toString()}`, {
        signal: abortController.signal,
      });
      if (!res.ok) throw new Error('Failed to fetch records');
      const apiData = await res.json();

      setRecords((prev) => (replace ? apiData.records : [...prev, ...apiData.records]));
      setNextCursor(apiData.pagination?.next_cursor ?? null);
      setHasMore(apiData.pagination?.has_more ?? false);
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        console.error('Records fetch error:', err);
      }
    } finally {
      setRecordsLoading(false);
    }
  };

  const recordsLoadedRef = useRef(false);

  const loadJobStatus = async () => {
    try {
      const res = await fetchApi(`/api/logscope/jobs/${jobId}`);
      setData(res);
      setError('');
      const isRunning =
        ['queued', 'running'].includes(res?.analysis?.status) || res?.enrichment?.status === 'running';
      pollingActive.current = isRunning;

      if (!tabDefaultSetRef.current && res?.incidents && res.incidents.length > 0) {
        tabDefaultSetRef.current = true;
        setActiveTab('incidents');
      }

      if (
        res?.analysis?.status === 'completed' &&
        (!recordsLoadedRef.current || records.length === 0) &&
        !recordsLoading
      ) {
        recordsLoadedRef.current = true;
        fetchRecords(0, search, filters, true);
      }
      return res;
    } catch (err: unknown) {
      setData((prev: any) => {
        if (!prev) {
          setError(err instanceof Error ? err.message : t('flowscope.load_fail'));
        }
        return prev;
      });
      return null;
    } finally {
      setLoading(false);
    }
  };

  const startPolling = (interval: number = 1000) => {
    pollingActive.current = true;
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current);
    }

    const poll = async () => {
      if (!pollingActive.current) return;
      const res = await loadJobStatus();
      const isRunning =
        ['queued', 'running'].includes(res?.analysis?.status) || res?.enrichment?.status === 'running';
      if (isRunning) {
        pollTimerRef.current = setTimeout(poll, interval);
      } else {
        pollingActive.current = false;
      }
    };

    pollTimerRef.current = setTimeout(poll, interval);
  };

  useEffect(() => {
    loadJobStatus().then((res) => {
      if (['queued', 'running'].includes(res?.analysis?.status) || res?.enrichment?.status === 'running') {
        startPolling(1200);
      }
    });

    return () => {
      pollingActive.current = false;
      if (pollTimerRef.current) {
        clearTimeout(pollTimerRef.current);
      }
    };
  }, [jobId]);

  useEffect(() => {
    if (
      data?.analysis?.status === 'completed' &&
      (!recordsLoadedRef.current || records.length === 0) &&
      !recordsLoading
    ) {
      recordsLoadedRef.current = true;
      fetchRecords(0, search, filters, true);
    }
  }, [data?.analysis?.status]);

  useEffect(() => {
    if (loading) return;
    const handler = setTimeout(() => {
      fetchRecords(0, search, filters, true);
    }, 400);
    return () => clearTimeout(handler);
  }, [search, filters]);

  const handleStartEnrichment = async () => {
    setEnriching(true);
    setData((prev: any) => {
      if (!prev) return prev;
      return {
        ...prev,
        enrichment: {
          ...(prev.enrichment || {}),
          status: 'running',
          checked: 0,
          total: prev.summary?.unique_ips || prev.unique_ips_count || 1,
          cached: 0,
          new: 0,
          stage: 'starting',
          force_refresh: forceRefresh,
        },
      };
    });

    startPolling(1000);

    try {
      await fetchApi(`/api/logscope/enrich/${jobId}?force=${forceRefresh ? '1' : '0'}`, {
        method: 'POST',
      });
      await loadJobStatus();
      startPolling(1000);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : t('flowscope.enrich_fail'));
      loadJobStatus();
    } finally {
      setEnriching(false);
    }
  };

  const handleSaveFeedback = async (idx: number, label: string) => {
    try {
      await fetchApi(`/api/logscope/feedback/${jobId}/${idx}`, {
        method: 'POST',
        body: JSON.stringify({ label }),
      });
      loadJobStatus();
      setRecords((prev) =>
        prev.map((r) => (r._sourceIndex === idx ? { ...r, analyst_feedback: { label } } : r))
      );
    } catch (err: unknown) {
      alert(t('flowscope.feedback_fail'));
    }
  };

  const handleFilterEntity = (type: 'user' | 'ip' | 'device', value: string) => {
    setFilters((prev) => ({ ...prev, [type]: value }));
    setActiveTab('events');
  };

  const handleFilterByIncidentEvents = (incidentId: string) => {
    setFilters((prev) => ({ ...prev, incident_id: incidentId }));
    setActiveTab('events');
  };

  const handleFilterTechnique = (tech: string) => {
    setSearch(tech);
    setActiveTab('events');
  };

  const handleFilterDetection = (detId: string) => {
    setSearch(detId);
    setActiveTab('events');
  };

  const handleFilterThreatFamily = (family: string) => {
    setSearch(family);
    setActiveTab('events');
  };

  const handleResetFilters = () => {
    setSearch('');
    setFilters({});
  };

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-10 h-10 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <div className="text-white font-bold text-sm">{t('logscope.loading_results')}</div>
          </div>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center p-4">
          <div className="glass-panel p-8 max-w-md text-center">
            <AlertTriangle className="w-12 h-12 text-rose-400 mx-auto mb-4" />
            <h2 className="text-lg font-bold text-white mb-2">{t('flowscope.load_error')}</h2>
            <p className="text-slate-400 text-xs mb-6">{error || t('flowscope.job_unavailable')}</p>
            <Link href="/logscope" className="px-4 py-2 rounded-xl bg-emerald-500 text-dark-950 font-bold text-xs">
              {t('flowscope.back_to_list')}
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const analysisStatus = data.analysis?.status;
  if (analysisStatus === 'queued' || analysisStatus === 'running') {
    const progress = Math.min(Math.max(Number(data.analysis?.progress) || 0, 0), 100);
    const processed = Number(data.analysis?.processed || 0);
    const total = Number(data.analysis?.total || 0);
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center p-4">
          <div className="glass-panel p-8 w-full max-w-xl text-center">
            <RefreshCw className="w-12 h-12 text-emerald-400 animate-spin mx-auto mb-5" />
            <h2 className="text-xl font-bold text-white mb-2">{t('logscope.analysis_in_progress')}</h2>
            <p className="text-slate-300 text-sm mb-2">{data.analysis?.stage || t('logscope.loading_results')}</p>
            {total > 0 && (
              <p className="text-emerald-400 text-xs font-mono mb-5">
                {processed.toLocaleString('en-US')} / {total.toLocaleString('en-US')} سجل
              </p>
            )}
            <div className="h-2.5 rounded-full bg-white/10 overflow-hidden" dir="ltr">
              <div
                className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="mt-3 text-sm font-mono text-emerald-300 font-bold">{progress}%</div>
          </div>
        </div>
      </div>
    );
  }

  if (analysisStatus === 'error') {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center p-4">
          <div className="glass-panel p-8 w-full max-w-xl text-center border-rose-500/30">
            <AlertTriangle className="w-12 h-12 text-rose-400 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-white mb-2">{t('logscope.analysis_failed')}</h2>
            <p className="text-slate-300 text-sm leading-7 mb-6">{data.analysis?.error || data.analysis?.stage}</p>
            <Link href="/logscope" className="inline-flex px-5 py-2.5 rounded-xl bg-emerald-500 text-dark-950 font-bold text-sm">
              {t('logscope.back_to_upload')}
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const summary = {
    total_records: data.summary?.records || data.total_records || 0,
    unique_ips: data.summary?.unique_ips || data.unique_ips_count || 0,
    unique_accounts: data.summary?.unique_accounts || data.unique_accounts_count || 0,
    unique_devices: data.summary?.unique_devices || data.unique_devices_count || 0,
    critical: data.summary?.critical || 0,
    high: data.summary?.high || 0,
    incidents_count: data.summary?.incidents_count || (data.incidents?.length || 0),
    detections_count: data.summary?.detections_count || (data.detections_summary?.length || 0),
    threat_findings_count: data.summary?.threat_findings_count || 0,
    avg_confidence: data.summary?.avg_confidence || 88,
  };
  const modelAnalysis = data.model_analysis?.result;

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Header Breadcrumb & Actions */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/logscope"
              className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <ArrowRight className="w-5 h-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-emerald-500 uppercase font-mono">{jobId.slice(0, 8)}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {data.metadata?.detected_source_label || data.metadata?.source_system_label || 'SIEM Log'}
                </span>
                <span className="text-xs text-slate-400">{data.metadata?.filename}</span>
              </div>
              <h1 className="text-2xl font-extrabold text-white mt-1">منصة التحقيق الجنائي LogScope SOC</h1>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-2">
            <div className="flex items-center gap-3 bg-white/5 border border-white/10 px-4 py-2 rounded-xl">
              <span className={`text-xs font-bold transition-colors ${!forceRefresh ? 'text-emerald-500' : 'text-slate-400'}`}>
                {t('flowscope.force_refresh_desc')}
              </span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  className="sr-only peer"
                  checked={forceRefresh}
                  onChange={(e) => setForceRefresh(e.target.checked)}
                />
                <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500"></div>
              </label>
              <span className={`text-xs font-bold transition-colors ${forceRefresh ? 'text-emerald-500' : 'text-slate-400'}`}>
                {t('flowscope.force_refresh')}
              </span>
            </div>

            <button
              onClick={handleStartEnrichment}
              disabled={enriching || data.enrichment?.status === 'running'}
              className="px-4 py-2 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 font-bold text-xs flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${data.enrichment?.status === 'running' ? 'animate-spin' : ''}`} />
              <span>
                {data.enrichment?.status === 'running' ? t('threatscope.enriching') : t('flowscope.start_enrich')}
              </span>
            </button>

            <a
              href={`/logscope/${jobId}/preview`}
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Eye className="w-4 h-4 text-amber-400" />
              <span>{t('flowscope.preview_word')}</span>
            </a>

            <a
              href={`/api/logscope/export/${jobId}.docx`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4 text-blue-400" />
              <span>{t('flowscope.report_word')}</span>
            </a>

            <a
              href={`/api/logscope/export/${jobId}.xlsx`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4 text-emerald-400" />
              <span>{t('flowscope.report_excel')}</span>
            </a>
          </div>
        </div>

        {/* Enhanced Executive Summary Cards (Distinguishing Events vs Findings vs Incidents) */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
          {/* 1. Critical Events */}
          <div className="glass-panel p-4 border-rose-500/20">
            <div className="text-[11px] font-bold text-slate-400">أحداث حرجة</div>
            <div className="text-2xl font-extrabold text-rose-400 mt-1 font-mono">
              {Number(summary.critical).toLocaleString('en-US')}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">عتبة الخطر ≥ 85%</div>
          </div>

          {/* 2. High Events */}
          <div className="glass-panel p-4 border-amber-500/20">
            <div className="text-[11px] font-bold text-slate-400">أحداث مرتفعة</div>
            <div className="text-2xl font-extrabold text-amber-400 mt-1 font-mono">
              {Number(summary.high).toLocaleString('en-US')}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">عتبة الخطر 70-84%</div>
          </div>

          {/* 3. Correlated Incidents */}
          <div className="glass-panel p-4 border-purple-500/30 bg-purple-950/15">
            <div className="text-[11px] font-bold text-purple-300 flex items-center justify-between">
              <span>حوادث أمنية مترابطة</span>
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            </div>
            <div className="text-2xl font-black text-rose-400 mt-1 font-mono">
              {Number(summary.incidents_count).toLocaleString('en-US')}
            </div>
            <div className="text-[10px] text-purple-400/80 mt-1">سلاسل هجوم مركبة</div>
          </div>

          {/* 4. Threat Findings & Detections */}
          <div className="glass-panel p-4 border-cyan-500/20">
            <div className="text-[11px] font-bold text-slate-400">كشفات القواعد</div>
            <div className="text-2xl font-extrabold text-cyan-400 mt-1 font-mono">
              {Number(summary.detections_count).toLocaleString('en-US')}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">قواعد كشف مطابقة</div>
          </div>

          {/* 5. Total Events */}
          <div className="glass-panel p-4">
            <div className="text-[11px] font-bold text-slate-400">إجمالي السجلات</div>
            <div className="text-2xl font-extrabold text-white mt-1 font-mono">
              {Number(summary.total_records).toLocaleString('en-US')}
            </div>
            <div className="text-[10px] text-slate-500 mt-1">سجلات مفحوصة</div>
          </div>

          {/* 6. Targeted Entities */}
          <div className="glass-panel p-4 border-emerald-500/20">
            <div className="text-[11px] font-bold text-slate-400">الكيانات النشطة</div>
            <div className="text-xl font-extrabold text-emerald-400 mt-1 font-mono truncate">
              {Number(summary.unique_accounts).toLocaleString('en-US')} <span className="text-xs text-slate-500">حساب</span> · {Number(summary.unique_ips).toLocaleString('en-US')} <span className="text-xs text-slate-500">IP</span>
            </div>
            <div className="text-[10px] text-slate-500 mt-1">{Number(summary.unique_devices).toLocaleString('en-US')} أجهزة وخوادم</div>
          </div>
        </div>

        {/* Source Detection & Analysis Metadata Banner */}
        <AnalysisMetadataBanner metadata={data.metadata} />

        {/* Threat Intelligence & Scan Progress Banner */}
        {data.enrichment && data.enrichment.status !== 'not_started' && (
          <EnrichmentProgressBanner
            enrichment={data.enrichment}
            colorScheme="emerald"
            onRetry={handleStartEnrichment}
          />
        )}

        {/* AI Advisory Box if completed */}
        {modelAnalysis && (
          <div className="glass-panel p-6 border-emerald-500/30 bg-gradient-to-r from-emerald-950/20 via-dark-850 to-dark-850">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="w-5 h-5 text-emerald-500" />
              <h3 className="text-base font-bold text-white">{t('flowscope.ai_advisor')}</h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-500 border border-emerald-500/30">
                {modelAnalysis.overall_assessment}
              </span>
            </div>
            <p className="text-slate-300 text-sm leading-relaxed mb-4">{modelAnalysis.executive_summary_ar}</p>
            {modelAnalysis.recommendations && (
              <div className="space-y-1.5 pt-3 border-t border-white/10">
                <div className="text-xs font-bold text-emerald-500">{t('flowscope.recommendations')}</div>
                <ul className="list-disc list-inside text-xs text-slate-400 space-y-1">
                  {modelAnalysis.recommendations.map((rec: string, i: number) => (
                    <li key={i}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* SIEM/SOC Investigation Navigation Tabs */}
        <NavigationTabs
          activeTab={activeTab}
          onChangeTab={setActiveTab}
          counts={{
            incidents: data.incidents?.length || 0,
            detections: data.detections_summary?.length || 0,
            events: summary.total_records,
            entities: (data.entities_summary?.top_users?.length || 0) + (data.entities_summary?.top_ips?.length || 0),
            mitre: data.mitre_matrix?.length || 0,
          }}
        />

        {/* TAB 1: INCIDENTS DASHBOARD */}
        {activeTab === 'incidents' && (
          <IncidentDashboard
            incidents={data.incidents || []}
            onSelectIncident={setSelectedIncident}
            onFilterEntity={handleFilterEntity}
          />
        )}

        {/* TAB 2: DETECTIONS & PATTERNS */}
        {activeTab === 'detections' && (
          <DetectionsView
            detections={data.detections_summary || []}
            patterns={data.patterns_summary || []}
            onFilterDetection={handleFilterDetection}
            onFilterThreatFamily={handleFilterThreatFamily}
          />
        )}

        {/* TAB 3: DETAILED EVENTS TABLE & ADVANCED FILTERING */}
        {activeTab === 'events' && (
          <div className="space-y-4">
            <AdvancedFilterBar
              searchQuery={search}
              onSearchChange={setSearch}
              filters={filters}
              onFilterChange={setFilters}
              onResetFilters={handleResetFilters}
              totalRecordsCount={summary.total_records}
            />

            <div className="glass-panel overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-right text-xs">
                  <thead>
                    <tr className="border-b border-white/10 bg-white/5 text-slate-400">
                      <th className="p-3">#</th>
                      <th className="p-3">{t('flowscope.col_time')}</th>
                      <th className="p-3">{t('flowscope.col_risk')}</th>
                      <th className="p-3">المصدر والوجهة (Source → Target)</th>
                      <th className="p-3">البروتوكول والمنفذ</th>
                      <th className="p-3">الحساب / الجهاز</th>
                      <th className="p-3">{t('logscope.col_event_id')}</th>
                      <th className="p-3">التوصيف الجنائي والإجراء</th>
                      <th className="p-3">{t('flowscope.col_feedback')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {records.map((rec, i) => {
                      const sourceIndex = rec._sourceIndex ?? i;
                      return (
                        <tr
                          key={sourceIndex}
                          onClick={() => setSelectedRecord(rec)}
                          className="hover:bg-white/5 cursor-pointer transition-colors"
                        >
                          <td className="p-3 font-mono text-slate-500">{sourceIndex + 1}</td>
                          <td className="p-3 font-mono text-slate-400 whitespace-nowrap">{rec.event_time || '—'}</td>
                          <td className="p-3 whitespace-nowrap">
                            <RiskBadge score={rec.risk_score} level={rec.severity} />
                          </td>

                          {/* Source & Destination with Clickable IP entity inspection */}
                          <td className="p-3 font-mono text-slate-300">
                            <div className="flex flex-col gap-0.5">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (rec.src_ip && rec.src_ip !== '-') {
                                    setSelectedEntity({ type: 'ip', value: rec.src_ip });
                                  }
                                }}
                                className="text-right text-white hover:text-cyan-300 transition-colors font-bold"
                              >
                                {rec.src_ip || '—'}
                              </button>
                              {rec.destination && rec.destination !== '-' && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedEntity({ type: 'ip', value: rec.destination });
                                  }}
                                  className="text-right text-amber-400 hover:text-amber-300 transition-colors text-[11px]"
                                >
                                  → {rec.destination}
                                </button>
                              )}
                            </div>
                          </td>

                          {/* Protocol & Port */}
                          <td className="p-3 font-mono text-slate-300">
                            <div className="flex items-center gap-1">
                              <span className="text-cyan-400 font-bold">{rec.protocol || '—'}</span>
                              {rec.dst_port ? <span className="text-slate-400">:{rec.dst_port}</span> : null}
                            </div>
                            {rec.service_name && <div className="text-[10px] text-slate-500">{rec.service_name}</div>}
                          </td>

                          {/* User Account / Device */}
                          <td className="p-3 text-slate-300">
                            <div className="flex flex-col gap-0.5">
                              {rec.user_account ? (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedEntity({ type: 'user', value: rec.user_account });
                                  }}
                                  className="text-right text-emerald-300 font-medium hover:underline truncate max-w-[140px]"
                                >
                                  {rec.user_account}
                                </button>
                              ) : (
                                <span className="text-slate-500">—</span>
                              )}
                              {rec.device && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedEntity({ type: 'device', value: rec.device });
                                  }}
                                  className="text-right text-[10px] text-slate-400 font-mono hover:underline truncate max-w-[140px]"
                                >
                                  {rec.device}
                                </button>
                              )}
                            </div>
                          </td>

                          {/* Event ID and Incident Badge */}
                          <td className="p-3 font-mono text-slate-300">
                            <div className="flex flex-col gap-1">
                              <span className="font-bold">{rec.event_id || '—'}</span>
                              {rec.incident_id && (
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const matchInc = data.incidents?.find(
                                      (inc: any) => inc.incident_id === rec.incident_id
                                    );
                                    if (matchInc) setSelectedIncident(matchInc);
                                  }}
                                  className="px-1.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/30 text-rose-300 text-[10px] font-bold text-right"
                                >
                                  {rec.incident_id}
                                </button>
                              )}
                            </div>
                          </td>

                          {/* Description & Arabic Forensic Explanation */}
                          <td className="p-3 max-w-md text-slate-300" title={rec.description_ar || rec.description}>
                            <div className="flex flex-col gap-1">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {rec.action && (
                                  <span
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      rec.action.toLowerCase() === 'block' || rec.action.toLowerCase() === 'discard'
                                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                        : rec.action.toLowerCase() === 'alert'
                                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                        : 'bg-slate-500/20 text-slate-400 border border-slate-500/30'
                                    }`}
                                  >
                                    {rec.action_ar || rec.action.toUpperCase()}
                                  </span>
                                )}
                                {rec.threat_family && (
                                  <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 text-[10px] font-medium">
                                    {rec.threat_family}
                                  </span>
                                )}
                              </div>
                              <span className="text-white/90 font-medium leading-relaxed" dir="auto">
                                {rec.description_ar || rec.description || '—'}
                              </span>
                              {rec.description_ar && rec.description && rec.description !== rec.description_ar && (
                                <span className="text-[10px] text-slate-500 font-mono truncate" dir="ltr">
                                  {rec.description}
                                </span>
                              )}
                            </div>
                          </td>

                          {/* Analyst Feedback */}
                          <td className="p-3">
                            <select
                              onClick={(event) => event.stopPropagation()}
                              value={rec.analyst_feedback?.label || ''}
                              onChange={(e) => handleSaveFeedback(sourceIndex, e.target.value)}
                              className="bg-dark-950 border border-white/10 rounded px-2 py-1 text-[11px] text-slate-300"
                            >
                              <option value="">{t('flowscope.fb_unspecified')}</option>
                              <option value="confirmed_threat">{t('flowscope.fb_confirmed')}</option>
                              <option value="false_positive">{t('flowscope.fb_false_pos')}</option>
                              <option value="benign">{t('flowscope.fb_benign')}</option>
                              <option value="needs_review">{t('flowscope.fb_review')}</option>
                            </select>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {records.length === 0 && !recordsLoading && (
                  <div className="p-8 text-center text-slate-400 text-xs">
                    {search || Object.keys(filters).length > 0
                      ? 'لم يتم العثور على سجلات تطابق معايير الفلترة المحددة'
                      : t('logscope.no_records_found', 'No records found')}
                  </div>
                )}
              </div>

              {(hasMore || recordsLoading) && records.length > 0 && (
                <div className="p-4 border-t border-white/10 flex items-center justify-center">
                  <button
                    type="button"
                    disabled={recordsLoading || !hasMore}
                    onClick={() => fetchRecords(nextCursor || 0, search, filters, false)}
                    className="px-6 py-2.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-200 disabled:opacity-30 flex items-center gap-2 transition-all"
                  >
                    {recordsLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin text-emerald-500" />
                        <span>جاري التحميل...</span>
                      </>
                    ) : (
                      <span>تحميل المزيد من السجلات</span>
                    )}
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: ENTITIES VIEW */}
        {activeTab === 'entities' && (
          <EntitiesView
            entitiesSummary={data.entities_summary}
            onSelectEntity={(type, val) => setSelectedEntity({ type, value: val })}
            onFilterEntity={handleFilterEntity}
          />
        )}

        {/* TAB 5: MITRE ATT&CK MATRIX */}
        {activeTab === 'mitre' && (
          <MitreMatrixView
            mitreMatrix={data.mitre_matrix || []}
            onFilterTechnique={handleFilterTechnique}
          />
        )}

        {/* TAB 6: NETWORK FLOWS & ANALYTICS */}
        {activeTab === 'analytics' && (
          <NetworkFlowView
            ips={data.entities_summary?.top_ips || []}
            onFilterEntity={handleFilterEntity}
          />
        )}

        {/* FORENSIC INVESTIGATION DRAWERS & MODALS */}
        {selectedIncident && (
          <IncidentInvestigationDrawer
            incident={selectedIncident}
            onClose={() => setSelectedIncident(null)}
            onFilterByIncidentEvents={handleFilterByIncidentEvents}
            onFilterEntity={handleFilterEntity}
            onSelectEventRecord={(rec) => setSelectedRecord(rec)}
          />
        )}

        {selectedEntity && (
          <EntityInvestigationDrawer
            jobId={jobId}
            entity={selectedEntity}
            enrichment={data.enrichment?.results?.[selectedEntity.value]}
            onClose={() => setSelectedEntity(null)}
            onFilterByEntity={handleFilterEntity}
          />
        )}

        {selectedRecord && (
          <EventInvestigationPanel
            record={selectedRecord}
            enrichmentResults={data.enrichment?.results}
            onClose={() => setSelectedRecord(null)}
            onSelectIncident={(incId) => {
              const matchInc = data.incidents?.find((inc: any) => inc.incident_id === incId);
              if (matchInc) setSelectedIncident(matchInc);
            }}
            onFilterEntity={handleFilterEntity}
          />
        )}
      </main>
    </div>
  );
}
