'use client';

import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  HardDrive,
  HeartPulse,
  Layers,
  Network,
  RefreshCw,
  Server,
  ShieldCheck,
  Terminal,
  XCircle,
} from 'lucide-react';
import { Navbar } from '../../../components/Navbar';
import { getPlatformDetailedHealth, getPlatformPerformance, getPlatformHealthHistory } from '../../../lib/api';
import {
  PlatformHealthComponent,
  PlatformHealthResponse,
  PlatformHealthSample,
  PlatformPerformanceResponse,
} from '../../../lib/types';

const COMPONENT_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  backend: Server,
  gateway: Network,
  logs_db: Database,
  audit_chain: ShieldCheck,
  threatscope: AlertTriangle,
  flowscope: Activity,
  logscope: Terminal,
  memory: Cpu,
  disk: HardDrive,
  log_worker: HeartPulse,
};

export default function PlatformHealthPage() {
  const [health, setHealth] = useState<PlatformHealthResponse | null>(null);
  const [perf, setPerf] = useState<PlatformPerformanceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [history, setHistory] = useState<PlatformHealthSample[]>([]);
  const [filterStatus, setFilterStatus] = useState<'all' | 'healthy' | 'degraded' | 'unhealthy'>('all');

  const fetchStatus = useCallback(async () => {
    setLoading(true);
    try {
      const [h, p, hist] = await Promise.all([
        getPlatformDetailedHealth(),
        getPlatformPerformance().catch(() => null),
        getPlatformHealthHistory().catch(() => null),
      ]);
      setHealth(h);
      if (p) setPerf(p);
      if (hist && Array.isArray(hist.samples)) setHistory(hist.samples);
    } catch (err) {
      console.error('Failed to load platform health:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // 10s auto-refresh
  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      fetchStatus();
    }, 10000);
    return () => clearInterval(timer);
  }, [autoRefresh, fetchStatus]);

  const overallStatus = health?.status || 'healthy';
  const isHealthy = overallStatus === 'healthy';
  const isDegraded = overallStatus === 'degraded';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-emerald-500/30">
      <Navbar />

      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <div className="inline-flex items-center gap-2 text-emerald-400 text-xs font-bold tracking-wider mb-2">
              <Activity className="w-4 h-4" /> COMPONENT HEALTH & RUNTIME METRICS
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white flex items-center gap-3">
              صحة المنصة والمكونات التشغيلية
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              مراقبة حية لسلامة الخدمات الأساسية، خوادم التحليل، اتصالات التخزين، وحلقات التدقيق التشفيرية.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold border transition-colors ${
                autoRefresh
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Activity className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-pulse' : ''}`} />
              {autoRefresh ? 'تحديث تلقائي: نشط (10 ث)' : 'تحديث تلقائي: متوقف'}
            </button>

            <button
              onClick={() => fetchStatus()}
              disabled={loading}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-bold transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              فحص الآن
            </button>

            <Link
              href="/operations/logs"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 text-xs font-bold transition-colors"
            >
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              سجلات المنصة
            </Link>
          </div>
        </div>

        {/* Overall Status Banner */}
        <section
          className={`rounded-2xl border p-6 mb-8 transition-all ${
            isHealthy
              ? 'bg-gradient-to-r from-emerald-950/40 via-slate-900/80 to-slate-900/80 border-emerald-500/30'
              : isDegraded
              ? 'bg-gradient-to-r from-amber-950/40 via-slate-900/80 to-slate-900/80 border-amber-500/30'
              : 'bg-gradient-to-r from-rose-950/50 via-slate-900/80 to-slate-900/80 border-rose-500/40'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div
                className={`p-4 rounded-2xl border ${
                  isHealthy
                    ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400 ring-4 ring-emerald-500/10'
                    : isDegraded
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-400 ring-4 ring-amber-500/10'
                    : 'bg-rose-500/20 border-rose-500/40 text-rose-400 ring-4 ring-rose-500/15'
                }`}
              >
                {isHealthy ? (
                  <CheckCircle2 className="w-8 h-8" />
                ) : isDegraded ? (
                  <AlertTriangle className="w-8 h-8" />
                ) : (
                  <XCircle className="w-8 h-8" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    الحالة العامة للمنصة (Overall Platform Status)
                  </span>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[11px] font-black border ${
                      isHealthy
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                        : isDegraded
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                        : 'bg-rose-500/20 text-rose-300 border-rose-500/30 animate-pulse'
                    }`}
                  >
                    {isHealthy ? 'سليمة وتعمل بكفاءة' : isDegraded ? 'متدهورة جزئياً' : 'غير مستقرة'}
                  </span>
                </div>
                <div className="text-lg font-black text-white mt-1">
                  {isHealthy
                    ? 'جميع مكونات المنصة العشرة (10/10) تعمل بحالة طبيعية ومستقرة'
                    : 'يوجد مكون أو أكثر يتطلب المراجعة أو الفحص الفوري'}
                </div>
                <div className="text-xs text-slate-400 mt-0.5">
                  آخر فحص تشغيلي:{' '}
                  <span className="font-mono text-slate-300">
                    {health?.timestamp ? new Date(health.timestamp).toLocaleTimeString() : '—'}
                  </span>
                </div>
              </div>
            </div>

            {/* Quick Metrics */}
            <div className="flex items-center gap-4 text-xs">
              <div className="px-4 py-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[10px]">الذاكرة المستخدمة</div>
                <div className="font-bold text-slate-200 mt-0.5 tabular-nums">
                  {perf?.memory_mb ? `${perf.memory_mb.toFixed(1)} MB` : '—'}
                </div>
              </div>
              <div className="px-4 py-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[10px]">خيوط المعالجة</div>
                <div className="font-bold text-slate-200 mt-0.5 tabular-nums">
                  {perf?.active_threads || '—'} Thread
                </div>
              </div>
              <div className="px-4 py-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
                <div className="text-slate-400 text-[10px]">عمق طابور السجلات</div>
                <div className="font-bold text-cyan-300 mt-0.5 tabular-nums">
                  {perf?.metrics?.queue_depth || 0}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Real-time Hardware Telemetry & Sparklines */}
        <section className="mb-8 space-y-4">
          <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-slate-800/70 border border-white/10 shadow-xs">
            <Cpu className="w-5 h-5 text-emerald-400 shrink-0" />
            <h2 className="text-lg font-black text-white">
              المقاييس الحيوية وموارد الخادم (Hardware & Telemetry)
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            {/* CPU Metric Card */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
              <div className="flex items-center justify-between text-slate-400">
                <span className="flex items-center gap-2 font-bold text-slate-200">
                  <Cpu className="w-4 h-4 text-emerald-400" />
                  استهلاك المعالج (CPU)
                </span>
                <span className="font-mono text-emerald-400 font-bold text-sm">
                  {health?.system_metrics ? `${health.system_metrics.cpu_percent}%` : '—'}
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    (health?.system_metrics?.cpu_percent || 0) > 80
                      ? 'bg-rose-500'
                      : (health?.system_metrics?.cpu_percent || 0) > 50
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, health?.system_metrics?.cpu_percent || 0)}%` }}
                />
              </div>
              <div className="text-[11px] text-slate-500 flex justify-between">
                <span>خيوط المعالجة: {health?.system_metrics?.active_threads || 1} Threads</span>
                <span className="text-emerald-400 font-mono">طبيعي</span>
              </div>
            </div>

            {/* RAM Metric Card */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
              <div className="flex items-center justify-between text-slate-400">
                <span className="flex items-center gap-2 font-bold text-slate-200">
                  <Activity className="w-4 h-4 text-blue-400" />
                  ذاكرة النظام (RAM)
                </span>
                <span className="font-mono text-blue-400 font-bold text-sm">
                  {health?.system_metrics ? `${health.system_metrics.ram_percent}%` : '—'}
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-blue-500 transition-all duration-500"
                  style={{ width: `${Math.min(100, health?.system_metrics?.ram_percent || 0)}%` }}
                />
              </div>
              <div className="text-[11px] text-slate-500 flex justify-between">
                <span>المستخدم: {health?.system_metrics?.ram_used_gb || 0} GB</span>
                <span>الإجمالي: {health?.system_metrics?.ram_total_gb || 0} GB</span>
              </div>
            </div>

            {/* Disk Metric Card */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
              <div className="flex items-center justify-between text-slate-400">
                <span className="flex items-center gap-2 font-bold text-slate-200">
                  <HardDrive className="w-4 h-4 text-purple-400" />
                  سعة التخزين والقرص
                </span>
                <span className="font-mono text-purple-400 font-bold text-sm">
                  {health?.system_metrics ? `${health.system_metrics.disk_percent}%` : '—'}
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className="h-full bg-purple-500 transition-all duration-500"
                  style={{ width: `${Math.min(100, health?.system_metrics?.disk_percent || 0)}%` }}
                />
              </div>
              <div className="text-[11px] text-slate-500 flex justify-between">
                <span>المتاح: {health?.system_metrics?.disk_free_gb || 0} GB</span>
                <span>السعة: {health?.system_metrics?.disk_total_gb || 0} GB</span>
              </div>
            </div>

            {/* Process & Uptime */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 space-y-3">
              <div className="flex items-center justify-between text-slate-400">
                <span className="flex items-center gap-2 font-bold text-slate-200">
                  <Server className="w-4 h-4 text-amber-400" />
                  ذاكرة العملية والخادم
                </span>
                <span className="font-mono text-amber-400 font-bold text-sm">
                  {health?.system_metrics?.process_memory_mb || 0} MB
                </span>
              </div>
              <div className="text-[11px] text-slate-400 pt-1">
                وقت التشغيل المتواصل:{' '}
                <span className="font-bold text-white font-mono">
                  {health?.system_metrics ? `${Math.floor(health.system_metrics.uptime_seconds / 60)} دقيقة` : '—'}
                </span>
              </div>
              <div className="text-[10px] text-slate-500 font-mono">
                عقدة التشغيل: {health?.system_metrics?.timestamp ? new Date(health.system_metrics.timestamp).toLocaleTimeString() : '—'}
              </div>
            </div>
          </div>

          {/* Historical Telemetry Sparklines */}
          {history.length > 1 && (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-400" />
                  <span>مخطط الاتجاه الزمني للموارد الحيوية (آخر {history.length} عينة)</span>
                </div>
                <div className="flex items-center gap-4 text-[11px] text-slate-400">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block" />
                    استهلاك المعالج (CPU %)
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-blue-400 inline-block" />
                    استهلاك الذاكرة (RAM %)
                  </span>
                </div>
              </div>

              <div className="w-full h-24 relative overflow-hidden flex items-end">
                <svg className="w-full h-full overflow-visible" preserveAspectRatio="none" viewBox="0 0 400 100">
                  {/* CPU Sparkline */}
                  <polyline
                    fill="none"
                    stroke="#10b981"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={history
                      .map((s, idx) => {
                        const x = (idx / Math.max(1, history.length - 1)) * 400;
                        const y = 100 - Math.min(100, Math.max(0, s.cpu_percent));
                        return `${x.toFixed(1)},${y.toFixed(1)}`;
                      })
                      .join(' ')}
                  />
                  {/* RAM Sparkline */}
                  <polyline
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={history
                      .map((s, idx) => {
                        const x = (idx / Math.max(1, history.length - 1)) * 400;
                        const y = 100 - Math.min(100, Math.max(0, s.ram_percent));
                        return `${x.toFixed(1)},${y.toFixed(1)}`;
                      })
                      .join(' ')}
                  />
                </svg>
              </div>
            </div>
          )}
        </section>

        {/* 10 Component Health Cards Grid */}
        <div className="mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-4 py-2.5 rounded-xl bg-slate-800/70 border border-white/10 mb-4 shadow-xs">
            <div className="flex items-center gap-2.5">
              <Layers className="w-5 h-5 text-emerald-400 shrink-0" />
              <h2 className="text-lg font-black text-white">
                فحص المكونات التشغيلية العشرة (Components Health Grid)
              </h2>
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center gap-1.5 text-xs">
              {(
                [
                  { id: 'all', label: 'الكل' },
                  { id: 'healthy', label: 'سليم' },
                  { id: 'degraded', label: 'متدهور' },
                  { id: 'unhealthy', label: 'معطل' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setFilterStatus(tab.id)}
                  className={`px-3 py-1 rounded-lg font-bold transition-colors ${
                    filterStatus === tab.id
                      ? 'bg-emerald-600 text-white shadow-sm'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {(health?.components || [])
              .filter((comp) => filterStatus === 'all' || comp.status === filterStatus)
              .map((comp) => {
              const IconComp = COMPONENT_ICONS[comp.id] || Server;
              const ok = comp.status === 'healthy';
              const deg = comp.status === 'degraded';
              return (
                <div
                  key={comp.id}
                  className={`rounded-2xl border p-5 transition-all flex flex-col justify-between ${
                    ok
                      ? 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                      : deg
                      ? 'bg-amber-950/15 border-amber-500/30'
                      : 'bg-rose-950/20 border-rose-500/35'
                  }`}
                >
                  <div>
                    {/* Top Row: Icon & Status */}
                    <div className="flex items-center justify-between mb-3">
                      <div
                        className={`p-2.5 rounded-xl border ${
                          ok
                            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                            : deg
                            ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                            : 'bg-rose-500/20 border-rose-500/40 text-rose-300'
                        }`}
                      >
                        <IconComp className="w-5 h-5" />
                      </div>
                      <span
                        className={`px-2.5 py-1 rounded-full text-[10px] font-black border ${
                          ok
                            ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            : deg
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-rose-500/20 text-rose-300 border-rose-500/30 animate-pulse'
                        }`}
                      >
                        {ok ? 'سليم (Healthy)' : deg ? 'متدهور (Degraded)' : 'معطّل (Failed)'}
                      </span>
                    </div>

                    {/* Titles */}
                    <div className="font-bold text-white text-sm">{comp.name_ar}</div>
                    <div className="text-[11px] font-mono text-slate-400 mt-0.5">{comp.name_en}</div>

                    {/* Latency badge */}
                    {comp.latency_ms !== null && (
                      <div className="mt-2 text-[11px] text-emerald-400 font-mono flex items-center gap-1">
                        <span>⚡ الاستجابة:</span>
                        <span className="font-bold">{comp.latency_ms.toFixed(1)} ms</span>
                      </div>
                    )}
                  </div>

                  {/* Diagnostic Details */}
                  <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px] font-mono">
                    {Object.entries(comp.details).map(([key, val]) => (
                      <div key={key} className="flex items-center justify-between text-slate-400">
                        <span className="text-slate-500">{key}:</span>
                        <span className="font-semibold text-slate-200 truncate max-w-[180px]">
                          {typeof val === 'boolean'
                            ? val
                              ? 'true'
                              : 'false'
                            : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* System & Telemetry Performance Cards */}
        {perf && (
          <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-slate-800/70 dark:bg-white/[0.04] border border-white/10 mb-4 shadow-xs">
              <Cpu className="w-5 h-5 text-cyan-400 shrink-0" />
              <h3 className="text-base font-black text-white">
                مؤشرات أداء طبقة السجلات والمراقبة (Logging Telemetry)
              </h3>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-slate-400">السجلات المكتوبة (Written Total)</div>
                <div className="text-2xl font-black text-cyan-300 mt-1 tabular-nums">
                  {(perf.metrics.written_total || 0).toLocaleString()}
                </div>
                <div className="text-[10px] text-slate-500 mt-1">عبر المعالج غير المتزامن</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-slate-400">السجلات المسقطة (Dropped Total)</div>
                <div
                  className={`text-2xl font-black mt-1 tabular-nums ${
                    perf.metrics.dropped_total > 0 ? 'text-rose-400' : 'text-emerald-400'
                  }`}
                >
                  {(perf.metrics.dropped_total || 0).toLocaleString()}
                </div>
                <div className="text-[10px] text-slate-500 mt-1">بسبب الضغط العكسي</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-slate-400">سجلات الأخطاء التراكمية</div>
                <div className="text-2xl font-black text-amber-300 mt-1 tabular-nums">
                  {(perf.kpis?.errors || 0).toLocaleString()}
                </div>
                <div className="text-[10px] text-slate-500 mt-1">ضمن قاعدة البيانات</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                <div className="text-slate-400">استهلاك الذاكرة (Working Set)</div>
                <div className="text-2xl font-black text-purple-300 mt-1 tabular-nums">
                  {perf.memory_mb.toFixed(1)} MB
                </div>
                <div className="text-[10px] text-slate-500 mt-1">الذاكرة الفيزيائية للخادم</div>
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

