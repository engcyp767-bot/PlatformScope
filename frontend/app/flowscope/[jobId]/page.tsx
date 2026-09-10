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
  Globe,
} from 'lucide-react';
import { fetchApi } from '../../../lib/api';
import { useTranslation } from '../../../lib/i18n';

export default function FlowScopeJobPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { t } = useTranslation();
  const { jobId } = use(params);

  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [enriching, setEnriching] = useState(false);
  const [forceRefresh, setForceRefresh] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<any>(null);
  
  // Pagination and Search State
  const [search, setSearch] = useState('');
  const [records, setRecords] = useState<any[]>([]);
  const [nextCursor, setNextCursor] = useState<number | null>(0);
  const [hasMore, setHasMore] = useState(true);
  const [recordsLoading, setRecordsLoading] = useState(false);
  
  const pollingActive = useRef(true);
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);
  const searchAbortController = useRef<AbortController | null>(null);

  const fetchRecords = async (cursor: number = 0, currentSearch: string = search, replace: boolean = false) => {
    if (searchAbortController.current) {
      searchAbortController.current.abort();
    }
    const abortController = new AbortController();
    searchAbortController.current = abortController;

    setRecordsLoading(true);
    try {
      const qParam = currentSearch ? `&q=${encodeURIComponent(currentSearch)}` : '';
      const res = await fetch(`/api/flowscope/jobs/${jobId}/records?cursor=${cursor}&limit=100${qParam}`, {
        signal: abortController.signal
      });
      if (!res.ok) throw new Error('Failed to fetch records');
      const apiData = await res.json();
      
      setRecords(prev => replace ? apiData.records : [...prev, ...apiData.records]);
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
      const res = await fetchApi(`/api/flowscope/jobs/${jobId}`);
      setData(res);
      setError('');
      const isRunning = ['queued', 'running'].includes(res?.analysis?.status)
        || res?.enrichment?.status === 'running';
      pollingActive.current = isRunning;
      if (res?.analysis?.status === 'completed' && (!recordsLoadedRef.current || records.length === 0) && !recordsLoading) {
        recordsLoadedRef.current = true;
        fetchRecords(0, search, true);
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
      const isRunning = ['queued', 'running'].includes(res?.analysis?.status)
        || res?.enrichment?.status === 'running';
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
    if (data?.analysis?.status === 'completed' && (!recordsLoadedRef.current || records.length === 0) && !recordsLoading) {
      recordsLoadedRef.current = true;
      fetchRecords(0, search, true);
    }
  }, [data?.analysis?.status]);

  useEffect(() => {
    if (loading) return;
    const handler = setTimeout(() => {
      fetchRecords(0, search, true);
    }, 400);
    return () => clearTimeout(handler);
  }, [search]);

  const handleStartEnrichment = async () => {
    setEnriching(true);
    // Optimistically show progress banner immediately
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
      await fetchApi(`/api/flowscope/enrich/${jobId}?force=${forceRefresh ? '1' : '0'}`, {
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
      await fetchApi(`/api/flowscope/feedback/${jobId}/${idx}`, {
        method: 'POST',
        body: JSON.stringify({ label }),
      });
      // Optionally reload job status to update stats if necessary
      loadJobStatus();
      
      // Optimistically update the record in the UI
      setRecords(prev => prev.map(r => r._sourceIndex === idx ? { ...r, analyst_feedback: { label } } : r));
    } catch (err: unknown) {
      alert(t('flowscope.feedback_fail'));
    }
  };

  const renderReputationBadge = (intel: any) => {
    if (!intel) return null;
    if (intel.reason) {
      return (
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30 font-sans">
          داخلي
        </span>
      );
    }
    const vt = intel.virustotal;
    const abuse = intel.abuseipdb;
    if (vt?.malicious > 0) {
      return (
        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono">
          VT: {vt.malicious} كشف
        </span>
      );
    }
    if (vt?.suspicious > 0) {
      return (
        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">
          VT: {vt.suspicious} مشبوه
        </span>
      );
    }
    if (abuse?.score > 0) {
      return (
        <span
          className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
            abuse.score >= 50 ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
          } border font-mono`}
        >
          Abuse: {abuse.score}%
        </span>
      );
    }
    if (vt?.verdict === 'benign' || vt?.verdict === 'clean' || (abuse && abuse.score === 0)) {
      return (
        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-sans">
          سليم
        </span>
      );
    }
    return null;
  };

  const getRecordSource = (rec: any): string => {
    if (!rec) return '';
    if (rec.src_ip && String(rec.src_ip).trim()) return String(rec.src_ip).trim();
    if (rec.event_source && String(rec.event_source).trim()) return String(rec.event_source).trim();
    if (rec.source_ip && String(rec.source_ip).trim()) return String(rec.source_ip).trim();
    if (Array.isArray(rec.extracted_ips) && rec.extracted_ips.length > 0) return String(rec.extracted_ips[0]).trim();
    return '';
  };

  const getRecordTargets = (rec: any): string[] => {
    if (!rec) return [];
    if (Array.isArray(rec.event_targets) && rec.event_targets.length > 0) {
      return rec.event_targets.map((t: any) => String(t).trim()).filter(Boolean);
    }
    if (typeof rec.event_targets === 'string' && rec.event_targets.trim()) {
      return rec.event_targets.split(',').map((t: string) => t.trim()).filter(Boolean);
    }
    if (rec.dst_ip && String(rec.dst_ip).trim()) return [String(rec.dst_ip).trim()];
    if (rec.dest_ip && String(rec.dest_ip).trim()) return [String(rec.dest_ip).trim()];
    if (Array.isArray(rec.extracted_ips) && rec.extracted_ips.length > 1) {
      return rec.extracted_ips.slice(1).map((t: any) => String(t).trim()).filter(Boolean);
    }
    return [];
  };

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <div className="text-white font-bold text-sm">{t('flowscope.loading_results')}</div>
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
            <Link href="/flowscope" className="px-4 py-2 rounded-xl bg-cyan-500 text-dark-950 font-bold text-xs">
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
            <RefreshCw className="w-12 h-12 text-cyan-400 animate-spin mx-auto mb-5" />
            <h2 className="text-xl font-bold text-white mb-2">{t('flowscope.analysis_in_progress')}</h2>
            <p className="text-slate-300 text-sm mb-2">{data.analysis?.stage || t('flowscope.loading_results')}</p>
            {total > 0 && (
              <p className="text-cyan-400 text-xs font-mono mb-5">
                {processed.toLocaleString('en-US')} / {total.toLocaleString('en-US')} سجل
              </p>
            )}
            <div className="h-2.5 rounded-full bg-white/10 overflow-hidden" dir="ltr">
              <div className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-400 transition-all duration-300" style={{ width: `${progress}%` }} />
            </div>
            <div className="mt-3 text-sm font-mono text-cyan-300 font-bold">{progress}%</div>
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
            <h2 className="text-xl font-bold text-white mb-2">{t('flowscope.analysis_failed')}</h2>
            <p className="text-slate-300 text-sm leading-7 mb-6">{data.analysis?.error || data.analysis?.stage}</p>
            <Link href="/flowscope" className="inline-flex px-5 py-2.5 rounded-xl bg-cyan-500 text-dark-950 font-bold text-sm">
              {t('flowscope.back_to_upload')}
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const summary = data.summary || {};
  const modelAnalysis = data.model_analysis?.result;

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Header Breadcrumb & Actions */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/flowscope"
              className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <ArrowRight className="w-5 h-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-cyan-400 uppercase font-mono">{jobId.slice(0, 8)}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  {data.metadata?.source_system_label || 'Flow'}
                </span>
                <span className="text-xs text-slate-400">{data.metadata?.filename}</span>
              </div>
              <h1 className="text-2xl font-extrabold text-white mt-1">{t('flowscope.results_title')}</h1>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-2">
            <div className="flex items-center gap-3 bg-white/5 border border-white/10 px-4 py-2 rounded-xl">
              <span className={`text-xs font-bold transition-colors ${!forceRefresh ? 'text-cyan-400' : 'text-slate-400'}`}>{t('flowscope.force_refresh_desc')}</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  className="sr-only peer"
                  checked={forceRefresh}
                  onChange={(e) => setForceRefresh(e.target.checked)}
                />
                <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500"></div>
              </label>
              <span className={`text-xs font-bold transition-colors ${forceRefresh ? 'text-cyan-400' : 'text-slate-400'}`}>{t('flowscope.force_refresh')}</span>
            </div>

            <button
              onClick={handleStartEnrichment}
              disabled={enriching || data.enrichment?.status === 'running'}
              className="px-4 py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 font-bold text-xs flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${data.enrichment?.status === 'running' ? 'animate-spin' : ''}`} />
              <span>
                {data.enrichment?.status === 'running' ? t('flowscope.enriching') : t('flowscope.start_enrich')}
              </span>
            </button>

            <a
              href={`/flowscope/${jobId}/preview`}
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Eye className="w-4 h-4 text-amber-400" />
              <span>{t('flowscope.preview_word')}</span>
            </a>

            <a
              href={`/api/flowscope/export/${jobId}.docx`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4 text-blue-400" />
              <span>{t('flowscope.report_word')}</span>
            </a>

            <a
              href={`/api/flowscope/export/${jobId}.xlsx`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4 text-emerald-400" />
              <span>{t('flowscope.report_excel')}</span>
            </a>
          </div>
        </div>

        {/* Executive Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="glass-panel p-5">
            <div className="text-xs text-slate-400">{t('flowscope.critical_threats')}</div>
            <div className="text-2xl font-extrabold text-rose-400 mt-2 font-heading">{Number(summary.critical || 0).toLocaleString('en-US')}</div>
            <div className="text-[11px] text-slate-500 mt-1">درجة خطورة ≥ 85</div>
          </div>
          <div className="glass-panel p-5">
            <div className="text-xs text-slate-400">{t('flowscope.high_threats')}</div>
            <div className="text-2xl font-extrabold text-orange-400 mt-2 font-heading">{Number(summary.high || 0).toLocaleString('en-US')}</div>
            <div className="text-[11px] text-slate-500 mt-1">درجة خطورة 70 - 84</div>
          </div>
          <div className="glass-panel p-5">
            <div className="text-xs text-slate-400">{t('flowscope.total_events')}</div>
            <div className="text-2xl font-extrabold text-white mt-2 font-heading">{Number(summary.records || 0).toLocaleString('en-US')}</div>
            <div className="text-[11px] text-slate-500 mt-1">سجلات مفحوصة</div>
          </div>
          <div className="glass-panel p-5">
            <div className="text-xs text-slate-400">{t('flowscope.unique_ips')}</div>
            <div className="text-2xl font-extrabold text-cyan-400 mt-2 font-heading">{Number(summary.unique_ips || 0).toLocaleString('en-US')}</div>
            <div className="text-[11px] text-slate-500 mt-1">مفحوصة استخباراتيًا</div>
          </div>
        </div>

        {/* Threat Intelligence & Scan Progress Banner */}
        {data.enrichment && data.enrichment.status !== 'not_started' && (
          <EnrichmentProgressBanner
            enrichment={data.enrichment}
            colorScheme="cyan"
            onRetry={handleStartEnrichment}
          />
        )}

        {/* AI Advisory Box if completed */}
        {modelAnalysis && (
          <div className="glass-panel p-6 border-cyan-500/30 bg-gradient-to-r from-cyan-950/20 via-dark-850 to-dark-850">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white">{t('flowscope.ai_advisor')}</h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-500 border border-cyan-500/30">
                {modelAnalysis.overall_assessment}
              </span>
            </div>
            <p className="text-slate-300 text-sm leading-relaxed mb-4">
              {modelAnalysis.executive_summary_ar}
            </p>
            {modelAnalysis.recommendations && (
              <div className="space-y-1.5 pt-3 border-t border-white/10">
                <div className="text-xs font-bold text-cyan-400">{t('flowscope.recommendations')}</div>
                <ul className="list-disc list-inside text-xs text-slate-400 space-y-1">
                  {modelAnalysis.recommendations.map((rec: string, i: number) => (
                    <li key={i}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Table & Search */}
        <div className="glass-panel overflow-hidden">
          <div className="p-4 border-b border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <h3 className="font-bold text-white text-base">{t('flowscope.table_title')}</h3>
            </div>

            <div className="relative min-w-[280px]">
              <input
                type="text"
                placeholder={t('flowscope.search_placeholder')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full px-3 py-1.5 pr-8 rounded-lg bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-cyan-500"
              />
              <Search className="w-4 h-4 text-slate-500 absolute right-2.5 top-2" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead className="bg-white/5 text-slate-400 border-b border-white/5 font-semibold">
                <tr>
                  <th className="p-3">درجة الخطورة</th>
                  <th className="p-3">نوع الحدث (Event)</th>
                  <th className="p-3">المصدر (Source)</th>
                  <th className="p-3">الوجهة (Destination)</th>
                  <th className="p-3">التفاصيل والتصنيف</th>
                  <th className="p-3">تقييم المحلل</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {records.map((rec: any) => {
                  const hasDetails = rec.country || rec.asn || rec.enrichment_details;
                  const sourceIndex = rec._sourceIndex;
                  return (
                    <tr key={sourceIndex} onClick={() => setSelectedRecord(rec)} className="hover:bg-white/5 transition-colors cursor-pointer">
                      <td className="p-3">
                        <RiskBadge score={rec.risk_score} />
                      </td>
                      <td className="p-3 font-medium text-white">
                        <div className="flex flex-col gap-0.5">
                          <span>{rec.event_type || '—'}</span>
                          {rec.action && (
                            <span className="text-[10px] text-slate-500">{rec.action}</span>
                          )}
                        </div>
                      </td>
                      {/* Source Column */}
                      {(() => {
                        const src = getRecordSource(rec);
                        return (
                          <td className="p-3 font-mono">
                            <div className="flex flex-col gap-1 items-start">
                              <span className="text-slate-200">{src || '—'}</span>
                              <div className="flex items-center gap-1.5 flex-wrap">
                                {rec.src_port && (
                                  <span className="text-[10px] text-slate-500">Port: {rec.src_port}</span>
                                )}
                                {src && renderReputationBadge(data?.enrichment?.results?.[src])}
                              </div>
                            </div>
                          </td>
                        );
                      })()}

                      {/* Destination Column */}
                      {(() => {
                        const targets = getRecordTargets(rec);
                        const primaryTarget = targets[0] || '';
                        return (
                          <td className="p-3 font-mono">
                            <div className="flex flex-col gap-1 items-start">
                              {targets.length === 0 ? (
                                <span className="text-slate-500">—</span>
                              ) : targets.length === 1 ? (
                                <>
                                  <span className="text-amber-400">{targets[0]}</span>
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    {rec.dst_port && (
                                      <span className="text-[10px] text-slate-500">Port: {rec.dst_port}</span>
                                    )}
                                    {renderReputationBadge(data?.enrichment?.results?.[targets[0]])}
                                  </div>
                                </>
                              ) : (
                                <>
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    <span className="text-amber-400">{targets[0]}</span>
                                    <span
                                      className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 font-sans border border-amber-500/20"
                                      title={targets.join(', ')}
                                    >
                                      +{targets.length - 1} وجهات
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    {rec.dst_port && (
                                      <span className="text-[10px] text-slate-500">Port: {rec.dst_port}</span>
                                    )}
                                    {renderReputationBadge(data?.enrichment?.results?.[targets[0]])}
                                  </div>
                                </>
                              )}
                            </div>
                          </td>
                        );
                      })()}
                      <td className="p-3 max-w-xs truncate" title={rec.detail}>
                        <div className="flex flex-col gap-1">
                          <span className="text-slate-300">{rec.detail || '—'}</span>
                          {rec.classification && (
                            <span className="inline-flex px-1.5 py-0.5 rounded bg-white/5 text-[10px] text-slate-400 w-fit">
                              {rec.classification}
                            </span>
                          )}
                        </div>
                      </td>
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
                {search ? t('logscope.no_matching_records_found', 'No matching records found') : t('logscope.no_records_found', 'No records found')}
              </div>
            )}
          </div>
          
          {(hasMore || recordsLoading) && records.length > 0 && (
            <div className="p-4 border-t border-white/10 flex items-center justify-center">
              <button
                type="button"
                disabled={recordsLoading || !hasMore}
                onClick={() => fetchRecords(nextCursor || 0, search, false)}
                className="px-6 py-2.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-200 disabled:opacity-30 flex items-center gap-2 transition-all"
              >
                {recordsLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                    <span>جاري التحميل...</span>
                  </>
                ) : (
                  <span>تحميل المزيد</span>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Record Details Modal */}
        {selectedRecord && (() => {
          const srcIp = getRecordSource(selectedRecord);
          const targets = getRecordTargets(selectedRecord);
          const primaryDst = targets[0] || '';
          const srcIntel = srcIp ? data?.enrichment?.results?.[srcIp] : null;
          const dstIntel = primaryDst ? data?.enrichment?.results?.[primaryDst] : null;

          return (
            <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm p-4 flex items-center justify-center" onClick={() => setSelectedRecord(null)}>
              <div className="glass-panel w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col" onClick={(event) => event.stopPropagation()}>
                <div className="p-4 border-b border-white/10 flex items-center justify-between">
                  <h3 className="font-bold text-white flex items-center gap-2">
                    <Info className="w-4 h-4 text-cyan-400" />
                    {t('flowscope.record_details_title')}
                  </h3>
                  <button
                    type="button"
                    onClick={() => setSelectedRecord(null)}
                    className="px-3 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 text-xs transition-colors"
                  >
                    {t('flowscope.close')}
                  </button>
                </div>
                <div className="p-4 overflow-y-auto space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-black/20 p-3 rounded-lg border border-white/5">
                      <div className="text-[10px] text-slate-500 mb-1">{t('flowscope.th_event')}</div>
                      <div className="font-mono text-sm text-white">{selectedRecord.event_type || '—'}</div>
                    </div>
                    <div className="bg-black/20 p-3 rounded-lg border border-white/5">
                      <div className="text-[10px] text-slate-500 mb-1">{t('flowscope.th_risk')}</div>
                      <RiskBadge score={selectedRecord.risk_score} />
                    </div>
                    <div className="bg-black/20 p-3 rounded-lg border border-white/5">
                      <div className="text-[10px] text-slate-500 mb-1">{t('flowscope.th_source')}</div>
                      <div className="font-mono text-sm text-cyan-400 flex items-center justify-between gap-1 flex-wrap">
                        <span>{srcIp || '—'} {selectedRecord.src_port ? `:${selectedRecord.src_port}` : ''}</span>
                        {renderReputationBadge(srcIntel)}
                      </div>
                    </div>
                    <div className="bg-black/20 p-3 rounded-lg border border-white/5">
                      <div className="text-[10px] text-slate-500 mb-1">{t('flowscope.th_target')}</div>
                      <div className="font-mono text-sm text-amber-400 flex items-center justify-between gap-1 flex-wrap">
                        <span>{targets.length > 0 ? targets.join(', ') : '—'} {selectedRecord.dst_port ? `:${selectedRecord.dst_port}` : ''}</span>
                        {renderReputationBadge(dstIntel)}
                      </div>
                    </div>
                  </div>

                  {/* Threat Intelligence & Reputation Section */}
                  {(srcIntel || dstIntel) && (
                    <div className="rounded-2xl border border-cyan-500/20 bg-cyan-950/15 p-4 space-y-3">
                      <div className="flex items-center gap-2 border-b border-cyan-500/15 pb-2 text-cyan-400 font-bold text-xs">
                        <Globe className="w-4 h-4" />
                        <span>استخبارات وسمعة العناوين (Threat Intelligence)</span>
                      </div>

                      <div className="grid sm:grid-cols-2 gap-3">
                        {/* Source IP Intel */}
                        {srcIp && srcIntel && (
                          <div className="p-3 rounded-xl bg-black/40 border border-white/10 space-y-2">
                            <div className="flex items-center justify-between border-b border-white/5 pb-1.5">
                              <span className="font-mono text-cyan-300 font-bold text-xs" dir="ltr">
                                {srcIp} <span className="font-sans text-[10px] text-slate-400">(المصدر)</span>
                              </span>
                              {renderReputationBadge(srcIntel)}
                            </div>
                            {srcIntel.reason ? (
                              <div className="text-[11px] text-slate-400 font-sans">
                                {srcIntel.reason} (نطاق داخلي خاص مستثنى من الاستعلام الخارجي)
                              </div>
                            ) : (
                              <div className="space-y-1.5 text-[11px] text-slate-300">
                                {/* VirusTotal */}
                                {srcIntel.virustotal ? (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                    <span className="text-slate-400 font-bold">VirusTotal:</span>
                                    <span className="font-mono font-bold text-white">
                                      {srcIntel.virustotal.malicious ?? 0} ضار / {srcIntel.virustotal.suspicious ?? 0} مشبوه
                                    </span>
                                  </div>
                                ) : (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                    <span className="text-slate-500">VirusTotal:</span>
                                    <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                  </div>
                                )}

                                {/* Shodan InternetDB */}
                                {srcIntel.shodan ? (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                    <span className="text-slate-400 font-bold">Shodan:</span>
                                    {srcIntel.shodan.ports?.length > 0 ? (
                                      <span className="font-mono text-cyan-300 font-bold text-[10px]">
                                        {srcIntel.shodan.ports.slice(0, 5).join(', ')} (مفتوحة)
                                        {srcIntel.shodan.vulns?.length > 0 ? ` · ${srcIntel.shodan.vulns.length} ثغرة` : ''}
                                      </span>
                                    ) : (
                                      <span className="text-emerald-400 text-[10px] font-sans">
                                        سليم (لا توجد منافذ أو ثغرات مكشوفة)
                                      </span>
                                    )}
                                  </div>
                                ) : (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                    <span className="text-slate-500">Shodan:</span>
                                    <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                  </div>
                                )}

                                {/* AbuseIPDB */}
                                {srcIntel.abuseipdb ? (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                    <span className="text-slate-400 font-bold">AbuseIPDB:</span>
                                    <span className="font-mono font-bold text-white">
                                      {srcIntel.abuseipdb.score ?? 0}% ثقة ({srcIntel.abuseipdb.total_reports ?? 0} بلاغ)
                                    </span>
                                  </div>
                                ) : (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                    <span className="text-slate-500">AbuseIPDB:</span>
                                    <span className="text-slate-400 text-[10px] font-sans">غير مفعّل في المنصة (يتطلب مفتاح API)</span>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Destination IP Intel */}
                        {primaryDst && dstIntel && (
                          <div className="p-3 rounded-xl bg-black/40 border border-white/10 space-y-2">
                            <div className="flex items-center justify-between border-b border-white/5 pb-1.5">
                              <span className="font-mono text-amber-300 font-bold text-xs" dir="ltr">
                                {primaryDst} <span className="font-sans text-[10px] text-slate-400">(الوجهة)</span>
                              </span>
                              {renderReputationBadge(dstIntel)}
                            </div>
                            {dstIntel.reason ? (
                              <div className="text-[11px] text-slate-400 font-sans">
                                {dstIntel.reason} (نطاق داخلي خاص مستثنى من الاستعلام الخارجي)
                              </div>
                            ) : (
                              <div className="space-y-1.5 text-[11px] text-slate-300">
                                {/* VirusTotal */}
                                {dstIntel.virustotal ? (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                    <span className="text-slate-400 font-bold">VirusTotal:</span>
                                    <span className="font-mono font-bold text-white">
                                      {dstIntel.virustotal.malicious ?? 0} ضار / {dstIntel.virustotal.suspicious ?? 0} مشبوه
                                    </span>
                                  </div>
                                ) : (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                    <span className="text-slate-500">VirusTotal:</span>
                                    <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                  </div>
                                )}

                                {/* Shodan InternetDB */}
                                {dstIntel.shodan ? (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                    <span className="text-slate-400 font-bold">Shodan:</span>
                                    {dstIntel.shodan.ports?.length > 0 ? (
                                      <span className="font-mono text-amber-300 font-bold text-[10px]">
                                        {dstIntel.shodan.ports.slice(0, 5).join(', ')} (مفتوحة)
                                        {dstIntel.shodan.vulns?.length > 0 ? ` · ${dstIntel.shodan.vulns.length} ثغرة` : ''}
                                      </span>
                                    ) : (
                                      <span className="text-emerald-400 text-[10px] font-sans">
                                        سليم (لا توجد منافذ أو ثغرات مكشوفة)
                                      </span>
                                    )}
                                  </div>
                                ) : (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                    <span className="text-slate-500">Shodan:</span>
                                    <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                  </div>
                                )}

                                {/* AbuseIPDB */}
                                {dstIntel.abuseipdb ? (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                    <span className="text-slate-400 font-bold">AbuseIPDB:</span>
                                    <span className="font-mono font-bold text-white">
                                      {dstIntel.abuseipdb.score ?? 0}% ثقة ({dstIntel.abuseipdb.total_reports ?? 0} بلاغ)
                                    </span>
                                  </div>
                                ) : (
                                  <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                    <span className="text-slate-500">AbuseIPDB:</span>
                                    <span className="text-slate-400 text-[10px] font-sans">غير مفعّل في المنصة (يتطلب مفتاح API)</span>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="bg-black/20 p-3 rounded-lg border border-white/5">
                    <div className="text-[10px] text-slate-500 mb-1">{t('flowscope.th_details')}</div>
                    <div className="text-sm text-slate-300">{selectedRecord.detail || '—'}</div>
                  </div>
                  {selectedRecord.raw_data && Object.keys(selectedRecord.raw_data).length > 0 && (
                    <div className="bg-black/20 p-3 rounded-lg border border-white/5">
                      <div className="text-[10px] text-slate-500 mb-2">{t('flowscope.raw_data_title')}</div>
                      <pre className="text-[10px] text-slate-400 font-mono whitespace-pre-wrap break-all" dir="ltr">
                        {JSON.stringify(selectedRecord.raw_data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })()}
      </main>
    </div>
  );
}
