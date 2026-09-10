'use client';

import React, { useEffect, useRef, useState, use } from 'react';
import Link from 'next/link';
import { Navbar } from '../../../components/Navbar';
import { RiskBadge } from '../../../components/RiskBadge';
import { EnrichmentProgressBanner } from '../../../components/EnrichmentProgressBanner';
import {
  ShieldAlert,
  ArrowRight,
  Download,
  Search,
  Sparkles,
  RefreshCw,
  AlertTriangle,
  FileCheck,
  Eye,
  Globe,
  ShieldCheck,
  CheckCircle,
  Info,
} from 'lucide-react';
import { fetchApi } from '../../../lib/api';
import { useTranslation } from '../../../lib/i18n';

export default function ThreatScopeJobPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { t } = useTranslation();
  const { jobId } = use(params);

  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [enriching, setEnriching] = useState(false);
  const [forceRefresh, setForceRefresh] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<any>(null);
  
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
      const res = await fetch(`/api/threatscope/jobs/${jobId}/records?cursor=${cursor}&limit=100${qParam}`, {
        signal: abortController.signal
      });
      if (!res.ok) throw new Error('Failed to fetch records');
      const apiData = await res.json();
      
      const newRecords = Array.isArray(apiData?.records) ? apiData.records : [];
      setRecords(prev => replace ? newRecords : [...prev, ...newRecords]);
      setNextCursor(apiData?.pagination?.next_cursor ?? null);
      setHasMore(apiData?.pagination?.has_more ?? false);
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        console.error('Records fetch error:', err);
      }
    } finally {
      setRecordsLoading(false);
    }
  };

  const loadJobStatus = async () => {
    try {
      const res = await fetchApi(`/api/threatscope/jobs/${jobId}`);
      const jobData = res.analysis || res;
      setData(jobData);
      const isRunning = ['queued', 'running'].includes(jobData?.analysis?.status)
        || jobData?.enrichment?.status === 'running'
        || res?.enrichment?.status === 'running';
      pollingActive.current = isRunning;
      return jobData;
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('flowscope.load_fail'));
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
      const jobData = await loadJobStatus();
      const isRunning = ['queued', 'running'].includes(jobData?.analysis?.status)
        || jobData?.enrichment?.status === 'running';
      if (isRunning) {
        pollTimerRef.current = setTimeout(poll, interval);
      } else {
        pollingActive.current = false;
      }
    };

    pollTimerRef.current = setTimeout(poll, interval);
  };

  useEffect(() => {
    loadJobStatus().then((jobData) => {
      if (['queued', 'running'].includes(jobData?.analysis?.status) || jobData?.enrichment?.status === 'running') {
        startPolling(1200);
      }
    });
    // Initial fetch of records
    fetchRecords(0, '', true);

    return () => {
      pollingActive.current = false;
      if (pollTimerRef.current) {
        clearTimeout(pollTimerRef.current);
      }
    };
  }, [jobId]);

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
          total: prev.summary?.unique_hashes || prev.summary?.records || 1,
          cached: 0,
          new: 0,
          stage: 'starting',
          force_refresh: forceRefresh,
        },
      };
    });

    startPolling(1000);

    try {
      await fetchApi(`/api/threatscope/enrich/${jobId}?force=${forceRefresh ? '1' : '0'}`, {
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
      await fetchApi(`/api/threatscope/feedback/${jobId}/${idx}`, {
        method: 'POST',
        body: JSON.stringify({ label }),
      });
      loadJobStatus();
      
      // Optimistically update the record in the UI
      setRecords(prev => prev.map(r => r._sourceIndex === idx ? { ...r, analyst_feedback: { label } } : r));
    } catch (err: unknown) {
      alert(t('flowscope.feedback_fail'));
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <div className="w-10 h-10 border-4 border-accent border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <div className="text-white font-bold text-sm">{t('threatscope.loading_results')}</div>
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
            <Link href="/threatscope" className="px-4 py-2 rounded-xl bg-accent text-white font-bold text-xs">
              {t('flowscope.back_to_list')}
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
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              href="/threatscope"
              className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <ArrowRight className="w-5 h-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-accent uppercase font-mono">{jobId.slice(0, 8)}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  {data.metadata?.source_system_label || 'XDR'}
                </span>
                <span className="text-xs text-slate-400">{data.metadata?.filename}</span>
              </div>
              <h1 className="text-2xl font-extrabold text-white mt-1">{t('threatscope.results_title')}</h1>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-2">
            <div className="flex items-center gap-3 bg-white/5 border border-white/10 px-4 py-2 rounded-xl">
              <span className={`text-xs font-bold transition-colors ${!forceRefresh ? 'text-accent' : 'text-slate-400'}`}>{t('flowscope.force_refresh_desc')}</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  className="sr-only peer"
                  checked={forceRefresh}
                  onChange={(e) => setForceRefresh(e.target.checked)}
                />
                <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:right-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-accent"></div>
              </label>
              <span className={`text-xs font-bold transition-colors ${forceRefresh ? 'text-accent' : 'text-slate-400'}`}>{t('flowscope.force_refresh')}</span>
            </div>

            <button
              onClick={handleStartEnrichment}
              disabled={enriching || data.enrichment?.status === 'running'}
              className="px-4 py-2 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 font-bold text-xs flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${data.enrichment?.status === 'running' ? 'animate-spin' : ''}`} />
              <span>
                {data.enrichment?.status === 'running' ? t('threatscope.enriching') : t('flowscope.start_enrich')}
              </span>
            </button>

            <a
              href={`/threatscope/${jobId}/preview`}
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Eye className="w-4 h-4 text-amber-400" />
              <span>{t('flowscope.preview_word')}</span>
            </a>

            <a
              href={`/api/threatscope/export/${jobId}.docx`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4 text-blue-400" />
              <span>{t('flowscope.report_word')}</span>
            </a>

            <a
              href={`/api/threatscope/export/${jobId}.xlsx`}
              target="_blank"
              rel="noreferrer"
              className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4 text-emerald-400" />
              <span>{t('flowscope.report_excel')}</span>
            </a>
          </div>
        </div>

        {/* Summary Cards */}
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
            <div className="text-xs text-slate-400">{t('threatscope.total_events')}</div>
            <div className="text-2xl font-extrabold text-white mt-2 font-heading">{Number(summary.records || 0).toLocaleString('en-US')}</div>
            <div className="text-[11px] text-slate-500 mt-1">سجلات مفحوصة</div>
          </div>
          <div className="glass-panel p-5">
            <div className="text-xs text-slate-400">{t('threatscope.unique_hashes')}</div>
            <div className="text-2xl font-extrabold text-accent mt-2 font-heading">{Number(summary.unique_hashes || 0).toLocaleString('en-US')}</div>
            <div className="text-[11px] text-slate-500 mt-1">{t('threatscope.unique_hashes_desc')}</div>
          </div>
        </div>

        {/* Threat Intelligence & Scan Progress Banner */}
        {data.enrichment && data.enrichment.status !== 'not_started' && (
          <EnrichmentProgressBanner
            enrichment={data.enrichment}
            colorScheme="rose"
            onRetry={handleStartEnrichment}
          />
        )}

        {/* AI Advisory Box */}
        {modelAnalysis && (
          <div className="glass-panel p-6 border-rose-500/30 bg-gradient-to-r from-rose-950/20 via-dark-850 to-dark-850">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="w-5 h-5 text-accent" />
              <h3 className="text-base font-bold text-white">{t('flowscope.ai_advisor')}</h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-accent/20 text-accent border border-accent/30">
                {modelAnalysis.overall_assessment}
              </span>
            </div>
            <p className="text-slate-300 text-sm leading-relaxed mb-4">
              {modelAnalysis.executive_summary_ar}
            </p>
            {modelAnalysis.recommendations && (
              <div className="space-y-1.5 pt-3 border-t border-white/10">
                <div className="text-xs font-bold text-accent">{t('flowscope.recommendations')}</div>
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
              <h3 className="font-bold text-white text-base">{t('threatscope.table_title')}</h3>
            </div>

            <div className="relative min-w-[240px]">
              <input
                type="text"
                placeholder={t('threatscope.search_placeholder')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full px-3 py-1.5 pr-8 rounded-lg bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-accent"
              />
              <Search className="w-4 h-4 text-slate-500 absolute right-2.5 top-2" />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead className="bg-white/5 text-slate-400 border-b border-white/5 font-semibold">
                <tr>
                  <th className="p-3">#</th>
                  <th className="p-3">{t('flowscope.th_severity')}</th>
                  <th className="p-3">{t('threatscope.th_threat_name')}</th>
                  <th className="p-3">{t('threatscope.th_endpoint')}</th>
                  <th className="p-3">{t('threatscope.th_hash')}</th>
                  <th className="p-3">استخبارات الهاش (VT)</th>
                  <th className="p-3">{t('threatscope.th_classification')}</th>
                  <th className="p-3">{t('flowscope.th_analyst')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {records.map((rec: any, idx: number) => {
                  const sourceIndex = rec._sourceIndex ?? idx;
                  const intel = rec.hash ? data?.enrichment?.results?.[rec.hash] : null;
                  const vt = intel?.virustotal;
                  const mb = intel?.malwarebazaar;

                  return (
                    <tr
                      key={sourceIndex}
                      onClick={() => setSelectedThreat(rec)}
                      className="hover:bg-white/5 transition-colors cursor-pointer group"
                    >
                      <td className="p-3 font-mono text-slate-500">{idx + 1}</td>
                      <td className="p-3">
                        <RiskBadge score={rec.risk_score} level={rec.risk_level} />
                      </td>
                      <td className="p-3 font-bold text-white max-w-[200px] truncate group-hover:text-rose-300 transition-colors" title={rec.threat_name}>
                        {rec.threat_name || t('threatscope.unnamed_threat')}
                      </td>
                      <td className="p-3 font-mono text-slate-300">
                        {rec.endpoint || t('threatscope.unknown_endpoint')}
                      </td>
                      <td className="p-3 font-mono text-[11px] text-accent max-w-[140px] truncate" title={rec.hash}>
                        {rec.hash || '—'}
                      </td>
                      <td className="p-3">
                        {(() => {
                          if (!intel) return <span className="text-slate-500 text-[10px]">—</span>;
                          if (vt?.malicious > 0) {
                            return (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-bold font-mono text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                <ShieldAlert className="w-3 h-3" />
                                <span>{vt.malicious} كشف ضار</span>
                              </span>
                            );
                          }
                          if (vt?.suspicious > 0) {
                            return (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-bold font-mono text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                <span>{vt.suspicious} مشبوه</span>
                              </span>
                            );
                          }
                          if (vt?.verdict === 'benign' || (vt && vt.malicious === 0)) {
                            return (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-bold font-mono text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                                <ShieldCheck className="w-3 h-3" />
                                <span>سليم</span>
                              </span>
                            );
                          }
                          if (mb?.verdict === 'malicious') {
                            return (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-bold font-mono text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                <span>MB: ضار</span>
                              </span>
                            );
                          }
                          if (vt?.source_status === 'not_found') {
                            return <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-400">غير مفهرس</span>;
                          }
                          return <span className="text-slate-500 text-[10px]">—</span>;
                        })()}
                      </td>
                      <td className="p-3 text-slate-400">
                        {rec.classification || '—'}
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
                    <RefreshCw className="w-4 h-4 animate-spin text-accent" />
                    <span>جاري التحميل...</span>
                  </>
                ) : (
                  <span>تحميل المزيد</span>
                )}
              </button>
            </div>
          )}
        </div>

        {/* Threat Investigation Modal */}
        {selectedThreat && (() => {
          const intel = selectedThreat.hash ? data?.enrichment?.results?.[selectedThreat.hash] : null;
          const vt = intel?.virustotal;
          const mb = intel?.malwarebazaar;

          return (
            <div
              className="fixed inset-0 z-50 bg-black/70 backdrop-blur-md p-3 sm:p-6 grid place-items-center animate-in fade-in duration-200"
              onClick={() => setSelectedThreat(null)}
            >
              <div
                className="glass-panel w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col border-rose-500/30 bg-dark-900/95 shadow-2xl rounded-2xl"
                onClick={(e) => e.stopPropagation()}
              >
                {/* Modal Header */}
                <div className="p-4 sm:p-5 border-b border-white/10 flex items-center justify-between gap-4 bg-gradient-to-r from-rose-950/30 via-dark-850 to-dark-850">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-bold text-white text-base truncate">
                          {selectedThreat.threat_name || 'تهديد غير مسمى'}
                        </h3>
                        <RiskBadge score={selectedThreat.risk_score} level={selectedThreat.risk_level} />
                      </div>
                      <div className="text-xs text-slate-400 font-mono flex items-center gap-2 mt-0.5">
                        <span>الجهاز: {selectedThreat.endpoint || 'غير محدد'}</span>
                        <span>·</span>
                        <span className="truncate max-w-[240px]" title={selectedThreat.hash}>الهاش: {selectedThreat.hash || '—'}</span>
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedThreat(null)}
                    className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs transition-colors"
                  >
                    إغلاق
                  </button>
                </div>

                {/* Modal Body */}
                <div className="p-4 sm:p-6 overflow-y-auto space-y-5">
                  {/* VirusTotal Threat Intelligence Card */}
                  <div className="rounded-2xl border border-rose-500/20 bg-rose-950/15 p-4 sm:p-5 space-y-4">
                    <div className="flex items-center justify-between border-b border-rose-500/15 pb-3">
                      <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                        <Globe className="w-4 h-4" />
                        <span>استخبارات البصمة الرقمية (VirusTotal Intelligence)</span>
                      </div>
                      {vt ? (
                        <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${vt.malicious > 0 ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'}`}>
                          {vt.verdict === 'malicious' ? 'تهديد مؤكد (خبيث)' : vt.verdict === 'suspicious' ? 'مشبوه' : vt.verdict === 'benign' ? 'سليم (Clean)' : 'غير معروف'}
                        </span>
                      ) : (
                        <span className="text-xs text-slate-500">لم يتم الفحص أو غير متاح</span>
                      )}
                    </div>

                    {vt ? (
                      <div className="space-y-4">
                        {/* Engines Consensus Grid */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center font-mono">
                          <div className="p-3 rounded-xl bg-black/40 border border-rose-500/20">
                            <div className="text-[10px] text-slate-400 font-sans">كشف ضار</div>
                            <div className="text-lg font-bold text-rose-400">{vt.malicious ?? 0}</div>
                          </div>
                          <div className="p-3 rounded-xl bg-black/40 border border-amber-500/20">
                            <div className="text-[10px] text-slate-400 font-sans">مشبوه</div>
                            <div className="text-lg font-bold text-amber-400">{vt.suspicious ?? 0}</div>
                          </div>
                          <div className="p-3 rounded-xl bg-black/40 border border-emerald-500/20">
                            <div className="text-[10px] text-slate-400 font-sans">سليم</div>
                            <div className="text-lg font-bold text-emerald-400">{vt.harmless ?? 0}</div>
                          </div>
                          <div className="p-3 rounded-xl bg-black/40 border border-white/10">
                            <div className="text-[10px] text-slate-400 font-sans">لم يرصد</div>
                            <div className="text-lg font-bold text-slate-400">{vt.undetected ?? 0}</div>
                          </div>
                        </div>

                        {/* Detection Names */}
                        {vt.detection_names && vt.detection_names.length > 0 && (
                          <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-1.5">
                            <div className="text-xs font-bold text-slate-300">مسميات الكشف من المحركات العالمية:</div>
                            <div className="flex flex-wrap gap-1.5">
                              {vt.detection_names.slice(0, 10).map((item: any, i: number) => {
                                const name = typeof item === 'string' ? item : item?.name || String(item);
                                return (
                                  <span key={i} className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 font-mono text-[11px] border border-rose-500/20">
                                    {name}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {/* YARA & Reputation */}
                        <div className="grid sm:grid-cols-2 gap-3">
                          {vt.yara_rules && vt.yara_rules.length > 0 && (
                            <div className="p-3 rounded-xl bg-black/30 border border-white/10 space-y-1">
                              <div className="text-xs font-bold text-amber-400">قواعد YARA المرصودة:</div>
                              <div className="text-[11px] text-slate-300 font-mono">
                                {vt.yara_rules.join(', ')}
                              </div>
                            </div>
                          )}
                          {vt.reputation !== undefined && (
                            <div className="p-3 rounded-xl bg-black/30 border border-white/10 flex items-center justify-between">
                              <span className="text-xs font-bold text-slate-400">درجة السمعة العامة:</span>
                              <span className={`text-sm font-bold font-mono ${vt.reputation < 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                                {vt.reputation}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs text-slate-400 py-2">
                        {data?.enrichment?.status === 'running' ? 'جاري فحص سمعة هذا الهاش عبر استخبارات التهديدات...' : 'لم يتم تشغيل فحص استخبارات التهديدات لهذا الملف أو الهاش غير مسجل عالمياً.'}
                      </div>
                    )}
                  </div>

                  {/* MalwareBazaar (if available) */}
                  {mb && mb.verdict === 'malicious' && (
                    <div className="rounded-2xl border border-amber-500/20 bg-amber-950/15 p-4 space-y-2">
                      <div className="flex items-center justify-between border-b border-amber-500/15 pb-2">
                        <span className="text-xs font-bold text-amber-400">MalwareBazaar Database</span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">برمجية خبيثة مؤكدة</span>
                      </div>
                      <div className="grid sm:grid-cols-3 gap-2 text-xs text-slate-300">
                        {mb.signature && <div><span className="text-slate-400">التوقيع:</span> <span className="font-mono text-white">{mb.signature}</span></div>}
                        {mb.file_type && <div><span className="text-slate-400">نوع الملف:</span> <span className="font-mono text-cyan-300">{mb.file_type}</span></div>}
                        {mb.tags?.length > 0 && <div><span className="text-slate-400">الوسوم:</span> <span className="text-slate-200">{mb.tags.join(', ')}</span></div>}
                      </div>
                    </div>
                  )}

                  {/* Local Forensic Context */}
                  <div className="rounded-2xl border border-white/10 bg-black/20 p-4 space-y-3">
                    <div className="text-xs font-bold text-slate-300 border-b border-white/5 pb-2">
                      السياق الجنائي والمحلي على النظام المستهدف
                    </div>
                    <div className="grid sm:grid-cols-2 gap-3 text-xs">
                      <div className="p-2.5 rounded-lg bg-white/5">
                        <div className="text-[10px] text-slate-400 mb-0.5">الجهاز المستهدف (Endpoint)</div>
                        <div className="font-mono text-slate-200">{selectedThreat.endpoint || '—'}</div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white/5">
                        <div className="text-[10px] text-slate-400 mb-0.5">التصنيف الأولي للحدث</div>
                        <div className="text-slate-200">{selectedThreat.classification || '—'}</div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white/5 sm:col-span-2">
                        <div className="text-[10px] text-slate-400 mb-0.5">بصمة التجزئة الكاملة (Hash)</div>
                        <div className="font-mono text-accent text-[11px] break-all select-all">{selectedThreat.hash || '—'}</div>
                      </div>
                    </div>
                  </div>

                  {/* Raw Data (if available) */}
                  {selectedThreat.raw_data && Object.keys(selectedThreat.raw_data).length > 0 && (
                    <div className="rounded-2xl border border-white/10 bg-black/30 p-4 space-y-2">
                      <div className="text-[10px] text-slate-400 font-bold">البيانات الخام للسجل (Raw Record Payload)</div>
                      <pre className="text-[10px] text-slate-400 font-mono whitespace-pre-wrap break-all max-h-48 overflow-y-auto" dir="ltr">
                        {JSON.stringify(selectedThreat.raw_data, null, 2)}
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
