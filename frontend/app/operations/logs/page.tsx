'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock,
  Code,
  Copy,
  Download,
  ExternalLink,
  Filter,
  Flame,
  Layers,
  Network,
  RefreshCw,
  Search,
  Sliders,
  Terminal,
  X,
  XCircle,
} from 'lucide-react';
import { Navbar } from '../../../components/Navbar';
import {
  getCorrelationTimeline,
  getPlatformLogs,
  setPlatformLogLevel,
} from '../../../lib/api';
import {
  CorrelationTimelineItem,
  PlatformLogItem,
  PlatformLogLevel,
  PlatformLogsKPIs,
  PlatformLoggingMetrics,
} from '../../../lib/types';

// Arabic level translations & badges
const LEVEL_CONFIG: Record<
  PlatformLogLevel,
  { labelAr: string; badgeClass: string; rowClass: string }
> = {
  CRITICAL: {
    labelAr: 'حرج جداً',
    badgeClass:
      'bg-rose-500/20 text-rose-300 border-rose-500/40 ring-1 ring-rose-500/30 animate-pulse',
    rowClass: 'border-l-4 border-l-rose-500 bg-rose-950/10 hover:bg-rose-950/20',
  },
  ERROR: {
    labelAr: 'خطأ',
    badgeClass: 'bg-red-500/20 text-red-300 border-red-500/35',
    rowClass: 'border-l-4 border-l-red-500 hover:bg-red-950/10',
  },
  WARNING: {
    labelAr: 'تحذير',
    badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    rowClass: 'border-l-4 border-l-amber-500/80 hover:bg-amber-950/10',
  },
  INFO: {
    labelAr: 'معلومات',
    badgeClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/25',
    rowClass: 'hover:bg-cyan-950/5',
  },
  DEBUG: {
    labelAr: 'تصحيح',
    badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/25',
    rowClass: 'hover:bg-purple-950/5 opacity-90',
  },
  TRACE: {
    labelAr: 'تتبع دقيق',
    badgeClass: 'bg-slate-500/15 text-slate-300 border-slate-500/20',
    rowClass: 'hover:bg-slate-900/40 opacity-80',
  },
};

const COMPONENT_LABELS: Record<string, { nameAr: string; color: string }> = {
  backend: { nameAr: 'الخادم الموحد', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
  gateway: { nameAr: 'بوابة API', color: 'text-violet-400 bg-violet-500/10 border-violet-500/20' },
  flowscope: { nameAr: 'تدفق الشبكة', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  threatscope: { nameAr: 'تحليل التهديدات', color: 'text-rose-400 bg-rose-500/10 border-rose-500/20' },
  logscope: { nameAr: 'سجلات الأمان', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
};

function getArabicLogMessage(item: {
  message_ar?: string | null;
  message?: string | null;
  message_en?: string | null;
  event_code?: string | null;
}): string {
  const ar = (item.message_ar || '').trim();
  if (/[\u0600-\u06FF]/.test(ar)) {
    return ar;
  }

  const raw = (item.message || ar || item.message_en || '').trim();
  if (/[\u0600-\u06FF]/.test(raw)) {
    return raw;
  }

  // Pattern matching for known platform messages
  const levelMatch = raw.match(/Platform log level changed from (\w+) to (\w+)/i);
  if (levelMatch) {
    const fromLevel =
      LEVEL_CONFIG[levelMatch[1].toUpperCase() as PlatformLogLevel]?.labelAr || levelMatch[1];
    const toLevel =
      LEVEL_CONFIG[levelMatch[2].toUpperCase() as PlatformLogLevel]?.labelAr || levelMatch[2];
    return `تم تغيير مستوى تسجيل المنصة من ${levelMatch[1].toUpperCase()} (${fromLevel}) إلى ${levelMatch[2].toUpperCase()} (${toLevel})`;
  }

  if (/^Unified backend server starting/i.test(raw)) {
    return 'بدء تشغيل خادم المنصة الموحد';
  }
  if (/^Unified backend server shutting down/i.test(raw)) {
    return 'تم إيقاف خادم المنصة الموحد بنجاح';
  }
  if (/^Unhandled backend exception/i.test(raw)) {
    return 'حدث استثناء غير معالج في الخادم الموحد';
  }
  if (/^Server initialized/i.test(raw)) {
    return 'تمت تهيئة الخادم بنجاح';
  }
  if (/^test message/i.test(raw)) {
    return 'رسالة اختبار تشغيلية';
  }

  return ar || raw || item.event_code || 'حدث تشغيلي';
}

export default function PlatformLogsPage() {
  const [logs, setLogs] = useState<PlatformLogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [kpis, setKpis] = useState<PlatformLogsKPIs | null>(null);
  const [metrics, setMetrics] = useState<PlatformLoggingMetrics | null>(null);
  const [currentLevel, setCurrentLevel] = useState<PlatformLogLevel>('INFO');
  const [autoRefresh, setAutoRefresh] = useState<boolean>(false);
  const [changingLevel, setChangingLevel] = useState<boolean>(false);
  const [levelChangeNotice, setLevelChangeNotice] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [filterLevel, setFilterLevel] = useState<string>('ALL');
  const [filterComponent, setFilterComponent] = useState<string>('ALL');
  const [filterEventType, setFilterEventType] = useState<string>('ALL');
  const [filterDateFrom, setFilterDateFrom] = useState<string>('');
  const [filterDateTo, setFilterDateTo] = useState<string>('');

  // 3-Level Drawer State
  const [selectedLog, setSelectedLog] = useState<PlatformLogItem | null>(null);
  const [drawerTab, setDrawerTab] = useState<'quick' | 'correlation' | 'technical'>('quick');
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineItems, setTimelineItems] = useState<CorrelationTimelineItem[]>([]);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Correlation Modal State
  const [modalCorrelationId, setModalCorrelationId] = useState<string | null>(null);
  const [modalTimeline, setModalTimeline] = useState<CorrelationTimelineItem[]>([]);
  const [modalLoading, setModalLoading] = useState(false);

  // Debounce search
  useEffect(() => {
    const timer = setTimeout(() => {
      setPage(1);
      setDebouncedSearch(search.trim());
    }, 350);
    return () => clearTimeout(timer);
  }, [search]);

  // Load platform logs
  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getPlatformLogs({
        page,
        limit: 50,
        search: debouncedSearch,
        level: filterLevel !== 'ALL' ? filterLevel : undefined,
        component: filterComponent !== 'ALL' ? filterComponent : undefined,
        event_type: filterEventType !== 'ALL' ? filterEventType : undefined,
        from: filterDateFrom || undefined,
        to: filterDateTo || undefined,
      });
      setLogs(res.logs || []);
      setTotal(res.total || 0);
      setTotalPages(res.total_pages || 1);
      setKpis(res.kpis || null);
      setMetrics(res.metrics || null);
      setCurrentLevel(res.current_level || 'INFO');
    } catch (err) {
      console.error('Failed to load platform logs:', err);
    } finally {
      setLoading(false);
    }
  }, [
    page,
    debouncedSearch,
    filterLevel,
    filterComponent,
    filterEventType,
    filterDateFrom,
    filterDateTo,
  ]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  // Auto-refresh interval (every 6 seconds)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      fetchLogs();
    }, 6000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchLogs]);

  // Handle Log Level Change
  const handleChangeLogLevel = async (newLevel: PlatformLogLevel) => {
    if (newLevel === currentLevel) return;
    setChangingLevel(true);
    try {
      const res = await setPlatformLogLevel(newLevel);
      setCurrentLevel(res.level);
      setLevelChangeNotice(`تم تعديل مستوى التسجيل للمنصة إلى ${res.level} بنجاح.`);
      setTimeout(() => setLevelChangeNotice(null), 4000);
      fetchLogs();
    } catch (err) {
      console.error('Failed to update log level:', err);
    } finally {
      setChangingLevel(false);
    }
  };

  // Open drawer and load correlation if needed
  const openDrawer = async (log: PlatformLogItem, tab: 'quick' | 'correlation' | 'technical' = 'quick') => {
    setSelectedLog(log);
    setDrawerTab(tab);
    if (log.correlation_id) {
      setTimelineLoading(true);
      try {
        const res = await getCorrelationTimeline(log.correlation_id);
        setTimelineItems(res.timeline || []);
      } catch (err) {
        console.error('Failed to fetch correlation timeline:', err);
      } finally {
        setTimelineLoading(false);
      }
    } else {
      setTimelineItems([]);
    }
  };

  // Open standalone correlation modal
  const openCorrelationModal = async (corrId: string) => {
    setModalCorrelationId(corrId);
    setModalLoading(true);
    try {
      const res = await getCorrelationTimeline(corrId);
      setModalTimeline(res.timeline || []);
    } catch (err) {
      console.error('Failed to fetch modal correlation timeline:', err);
    } finally {
      setModalLoading(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500/30">
      <Navbar />

      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Header Bar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
          <div>
            <div className="inline-flex items-center gap-2 text-amber-400 text-xs font-bold tracking-wider mb-2">
              <Terminal className="w-4 h-4" /> PLATFORM OBSERVABILITY & LOGGING
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white flex items-center gap-3">
              سجلات المنصة والمراقبة التشغيلية
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-amber-500/10 text-amber-300 border border-amber-500/30">
                مستوى التسجيل: {currentLevel}
              </span>
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              مراقبة الأحداث الداخلية، استكشاف الأعطال، وتتبع تدفق الطلبات عبر معرّف الترابط الموحد (Correlation ID).
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Dynamic Level Selector */}
            <div className="flex items-center bg-slate-900 border border-slate-800 rounded-xl p-1 text-xs">
              <span className="px-2.5 text-slate-400 font-medium">المستوى:</span>
              {(['TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] as PlatformLogLevel[]).map(
                (lvl) => (
                  <button
                    key={lvl}
                    onClick={() => handleChangeLogLevel(lvl)}
                    disabled={changingLevel}
                    className={`px-2.5 py-1 rounded-lg font-bold transition-all text-[11px] ${
                      currentLevel === lvl
                        ? 'bg-amber-500 text-slate-950 shadow-sm'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    {lvl}
                  </button>
                )
              )}
            </div>

            {/* Auto-Refresh Toggle */}
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-bold border transition-colors ${
                autoRefresh
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              <Activity className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-pulse' : ''}`} />
              {autoRefresh ? 'تحديث تلقائي: نشط (6 ثوانٍ)' : 'تحديث يدوي'}
            </button>

            {/* Manual Refresh */}
            <button
              onClick={() => fetchLogs()}
              disabled={loading}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-200 text-xs font-bold transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              تحديث
            </button>
          </div>
        </div>

        {/* Level Change Notice */}
        {levelChangeNotice && (
          <div className="mb-6 p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center justify-between animate-fadeIn">
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              {levelChangeNotice}
            </span>
            <button onClick={() => setLevelChangeNotice(null)}>
              <X className="w-4 h-4 text-emerald-400 hover:text-white" />
            </button>
          </div>
        )}

        {/* KPIs Cards */}
        <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
            <div className="text-xs text-slate-400">إجمالي الأحداث</div>
            <div className="text-2xl font-black mt-1 text-white tabular-nums">
              {(kpis?.total_events || 0).toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">سجلات مخزنة</div>
          </div>

          <div className="rounded-2xl border border-rose-500/30 bg-rose-950/20 p-4">
            <div className="text-xs text-rose-300 flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5" /> أحداث حرجة
            </div>
            <div className="text-2xl font-black mt-1 text-rose-300 tabular-nums">
              {(kpis?.critical || 0).toLocaleString()}
            </div>
            <div className="text-[11px] text-rose-400/70 mt-1">تتطلب تدخلاً فورياً</div>
          </div>

          <div className="rounded-2xl border border-red-500/25 bg-red-950/15 p-4">
            <div className="text-xs text-red-300 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5" /> أخطاء تشغيلية
            </div>
            <div className="text-2xl font-black mt-1 text-red-300 tabular-nums">
              {(kpis?.errors || 0).toLocaleString()}
            </div>
            <div className="text-[11px] text-red-400/70 mt-1">فشل استدعاء أو استثناء</div>
          </div>

          <div className="rounded-2xl border border-amber-500/25 bg-amber-950/15 p-4">
            <div className="text-xs text-amber-300 flex items-center gap-1.5">
              <AlertOctagon className="w-3.5 h-3.5" /> تحذيرات
            </div>
            <div className="text-2xl font-black mt-1 text-amber-300 tabular-nums">
              {(kpis?.warnings || 0).toLocaleString()}
            </div>
            <div className="text-[11px] text-amber-400/70 mt-1">مخاطر محتملة</div>
          </div>

          <div className="rounded-2xl border border-cyan-500/25 bg-cyan-950/15 p-4">
            <div className="text-xs text-cyan-300">سجلات معلوماتية</div>
            <div className="text-2xl font-black mt-1 text-cyan-300 tabular-nums">
              {(kpis?.info || 0).toLocaleString()}
            </div>
            <div className="text-[11px] text-cyan-400/70 mt-1">عمليات نظام عادية</div>
          </div>

          <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
            <div className="text-xs text-slate-400">عمق الطابور والإسقاط</div>
            <div className="text-2xl font-black mt-1 text-slate-200 tabular-nums flex items-baseline gap-1.5">
              <span>{metrics?.queue_depth || 0}</span>
              <span className="text-xs text-slate-500 font-normal">/ {metrics?.dropped_total || 0} مسقط</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">ضغط المعالجة العكسي</div>
          </div>
        </section>

        {/* Filter Bar */}
        <section className="bg-slate-900/90 border border-slate-800/80 rounded-2xl p-4 mb-6 backdrop-blur-sm">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {/* Free Search */}
            <div className="lg:col-span-2 relative">
              <label className="text-[11px] font-bold text-slate-400 mb-1 block">البحث الحر</label>
              <div className="relative">
                <Search className="w-4 h-4 text-slate-500 absolute right-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  placeholder="ابحث بالرسالة، معرّف التتبع، الخطأ..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pr-9 pl-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500/50"
                />
              </div>
            </div>

            {/* Level Filter */}
            <div>
              <label className="text-[11px] font-bold text-slate-400 mb-1 block">المستوى</label>
              <select
                value={filterLevel}
                onChange={(e) => {
                  setPage(1);
                  setFilterLevel(e.target.value);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500/50"
              >
                <option value="ALL">جميع المستويات</option>
                <option value="CRITICAL">CRITICAL (حرج)</option>
                <option value="ERROR">ERROR (خطأ)</option>
                <option value="WARNING">WARNING (تحذير)</option>
                <option value="INFO">INFO (معلومات)</option>
                <option value="DEBUG">DEBUG (تصحيح)</option>
                <option value="TRACE">TRACE (تتبع)</option>
              </select>
            </div>

            {/* Component Filter */}
            <div>
              <label className="text-[11px] font-bold text-slate-400 mb-1 block">المكون</label>
              <select
                value={filterComponent}
                onChange={(e) => {
                  setPage(1);
                  setFilterComponent(e.target.value);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500/50"
              >
                <option value="ALL">جميع المكونات</option>
                <option value="backend">الخادم الموحد (Backend)</option>
                <option value="gateway">بوابة API (Gateway)</option>
                <option value="flowscope">FlowScope</option>
                <option value="threatscope">ThreatScope</option>
                <option value="logscope">LogScope</option>
              </select>
            </div>

            {/* Event Type Filter */}
            <div>
              <label className="text-[11px] font-bold text-slate-400 mb-1 block">نوع الحدث</label>
              <select
                value={filterEventType}
                onChange={(e) => {
                  setPage(1);
                  setFilterEventType(e.target.value);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-amber-500/50"
              >
                <option value="ALL">جميع الأنواع</option>
                <option value="request">طلب HTTP (Request)</option>
                <option value="error">خطأ واستثناء (Error)</option>
                <option value="system">أحداث النظام (System)</option>
                <option value="auth">المصادقة والصلاحيات (Auth)</option>
                <option value="job">معالجة مهمة (Job)</option>
              </select>
            </div>

            {/* Reset Filters */}
            <div className="flex items-end">
              <button
                onClick={() => {
                  setSearch('');
                  setFilterLevel('ALL');
                  setFilterComponent('ALL');
                  setFilterEventType('ALL');
                  setFilterDateFrom('');
                  setFilterDateTo('');
                  setPage(1);
                }}
                className="w-full py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-bold transition-colors"
              >
                إعادة ضبط الفلاتر
              </button>
            </div>
          </div>
        </section>

        {/* Logs Table */}
        <section className="bg-slate-900/80 border border-slate-800/90 rounded-2xl overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-bold">
                <tr>
                  <th className="px-4 py-3.5">المستوى</th>
                  <th className="px-4 py-3.5">الوقت</th>
                  <th className="px-4 py-3.5">المكون</th>
                  <th className="px-4 py-3.5">الرسالة والتفاصيل التشغيلية</th>
                  <th className="px-4 py-3.5">معرّف الترابط (Correlation)</th>
                  <th className="px-4 py-3.5 text-center">الإجراءات</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {loading && logs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-16 text-center text-slate-400">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-amber-400" />
                      جاري تحميل سجلات المنصة...
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-16 text-center text-slate-500">
                      لا توجد سجلات تطابق معايير التصفية الحالية.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => {
                    const cfg = LEVEL_CONFIG[log.level] || LEVEL_CONFIG.INFO;
                    const comp = COMPONENT_LABELS[log.component] || {
                      nameAr: log.component,
                      color: 'text-slate-400 bg-slate-800 border-slate-700',
                    };
                    return (
                      <tr
                        key={log.id}
                        className={`transition-colors cursor-pointer ${cfg.rowClass}`}
                        onClick={() => openDrawer(log, 'quick')}
                      >
                        {/* Level Badge */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-black ${cfg.badgeClass}`}
                          >
                            <span>{log.level}</span>
                            <span className="opacity-70 text-[9px]">({cfg.labelAr})</span>
                          </span>
                        </td>

                        {/* Timestamp */}
                        <td className="px-4 py-3 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                          {log.timestamp ? (
                            <div>
                              <div>{log.timestamp.slice(11, 19)}</div>
                              <div className="text-[9px] text-slate-500">{log.timestamp.slice(0, 10)}</div>
                            </div>
                          ) : (
                            '—'
                          )}
                        </td>

                        {/* Component */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`inline-block px-2 py-0.5 rounded-md border text-[10px] font-bold ${comp.color}`}
                          >
                            {comp.nameAr}
                          </span>
                        </td>

                        {/* Message & Technical Code */}
                        <td className="px-4 py-3 max-w-md">
                          <div className="font-semibold text-slate-100 line-clamp-1">
                            {getArabicLogMessage(log)}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5 text-[10px] text-slate-400 font-mono">
                            <span className="text-amber-400/90 font-bold">{log.event_code}</span>
                            {log.duration_ms !== null && (
                              <span className="text-emerald-400">
                                ⏱️ {log.duration_ms.toFixed(1)} ms
                              </span>
                            )}
                            {log.error_code && (
                              <span className="text-red-400 bg-red-950/40 px-1 rounded">
                                {log.error_code}
                              </span>
                            )}
                          </div>
                        </td>

                        {/* Correlation ID Chip */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          {log.correlation_id ? (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                openCorrelationModal(log.correlation_id!);
                              }}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-cyan-300 font-mono text-[10px] border border-cyan-500/20 hover:border-cyan-500/40 transition-colors"
                              title="عرض شجرة الترابط والخط الزمني للطلب"
                            >
                              <Network className="w-3 h-3 text-cyan-400" />
                              <span>{log.correlation_id.slice(0, 15)}...</span>
                            </button>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="px-4 py-3 whitespace-nowrap text-center">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              openDrawer(log, 'quick');
                            }}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                            title="عرض تفاصيل السجل"
                          >
                            <ChevronLeft className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Bar */}
          <div className="p-4 border-t border-slate-800 bg-slate-950/50 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
            <div>
              عرض {(logs.length).toLocaleString()} من إجمالي {total.toLocaleString()} سجل
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
              >
                الصفحة السابقة
              </button>
              <span className="font-mono text-slate-200">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || loading}
                className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
              >
                الصفحة التالية
              </button>
            </div>
          </div>
        </section>

        {/* 3-Level Interactive Drawer */}
        {selectedLog && (
          <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fadeIn">
            <div className="w-full max-w-2xl bg-slate-900 border-r border-slate-800 h-full flex flex-col shadow-2xl">
              {/* Drawer Header */}
              <div className="p-5 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={`px-2 py-0.5 rounded-full border text-[10px] font-black ${
                        LEVEL_CONFIG[selectedLog.level]?.badgeClass
                      }`}
                    >
                      {selectedLog.level}
                    </span>
                    <span className="text-xs font-mono text-amber-400">{selectedLog.event_code}</span>
                  </div>
                  <h2 className="text-base font-black text-white">تفاصيل سجل المنصة #{selectedLog.id}</h2>
                </div>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Tabs (3 Levels) */}
              <div className="flex border-b border-slate-800 bg-slate-950/40 text-xs font-bold">
                <button
                  onClick={() => setDrawerTab('quick')}
                  className={`flex-1 py-3 border-b-2 transition-colors flex items-center justify-center gap-2 ${
                    drawerTab === 'quick'
                      ? 'border-amber-400 text-amber-300 bg-amber-500/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Layers className="w-4 h-4" /> المستوى 1: نظرة سريعة
                </button>
                <button
                  onClick={() => setDrawerTab('correlation')}
                  className={`flex-1 py-3 border-b-2 transition-colors flex items-center justify-center gap-2 ${
                    drawerTab === 'correlation'
                      ? 'border-cyan-400 text-cyan-300 bg-cyan-500/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Network className="w-4 h-4" /> المستوى 2: الترابط ({timelineItems.length})
                </button>
                <button
                  onClick={() => setDrawerTab('technical')}
                  className={`flex-1 py-3 border-b-2 transition-colors flex items-center justify-center gap-2 ${
                    drawerTab === 'technical'
                      ? 'border-purple-400 text-purple-300 bg-purple-500/5'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Code className="w-4 h-4" /> المستوى 3: التفاصيل التقنية
                </button>
              </div>

              {/* Drawer Content */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6">
                {/* Level 1: Quick View */}
                {drawerTab === 'quick' && (
                  <div className="space-y-4 text-xs">
                    {/* Arabic Message */}
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
                      <div className="text-slate-400 text-[11px] mb-1">الرسالة التوضيحية بالعربية:</div>
                      <div className="text-sm font-semibold text-slate-100">
                        {getArabicLogMessage(selectedLog)}
                      </div>
                    </div>

                    {/* English Technical Message */}
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800">
                      <div className="text-slate-400 text-[11px] mb-1">Technical Log (English):</div>
                      <div className="text-xs font-mono text-slate-300">
                        {selectedLog.message_en || selectedLog.message}
                      </div>
                    </div>

                    {/* Metadata Grid */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">المكون (Component)</div>
                        <div className="font-bold text-slate-200 mt-0.5">{selectedLog.component}</div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">المسجل (Logger)</div>
                        <div className="font-mono text-slate-200 mt-0.5">{selectedLog.logger}</div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">الوقت الدقيق (UTC)</div>
                        <div className="font-mono text-slate-200 mt-0.5">{selectedLog.timestamp}</div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">زمن التنفيذ (Duration)</div>
                        <div className="font-bold text-emerald-400 mt-0.5">
                          {selectedLog.duration_ms !== null
                            ? `${selectedLog.duration_ms.toFixed(2)} ms`
                            : '—'}
                        </div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">معرّف الطلب (Request ID)</div>
                        <div className="font-mono text-slate-200 mt-0.5">
                          {selectedLog.request_id || '—'}
                        </div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">المستخدم (User ID)</div>
                        <div className="font-bold text-slate-200 mt-0.5">{selectedLog.user_id || '—'}</div>
                      </div>
                    </div>

                    {/* Correlation ID Section */}
                    {selectedLog.correlation_id && (
                      <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 flex items-center justify-between">
                        <div>
                          <div className="text-cyan-400 text-[11px] font-bold">
                            معرّف الترابط المشترك (Correlation ID)
                          </div>
                          <div className="font-mono text-slate-200 mt-1">{selectedLog.correlation_id}</div>
                        </div>
                        <button
                          onClick={() => setDrawerTab('correlation')}
                          className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 font-bold text-xs flex items-center gap-1.5"
                        >
                          عرض الخط الزمني
                          <ChevronLeft className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </div>
                )}

                {/* Level 2: Correlation Timeline */}
                {drawerTab === 'correlation' && (
                  <div className="space-y-4">
                    <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-300 flex items-center justify-between">
                      <span>سلسلة الأحداث المرتبطة بـ: </span>
                      <span className="font-mono text-cyan-300 font-bold">
                        {selectedLog.correlation_id || 'لا يوجد معرّف ترابط'}
                      </span>
                    </div>

                    {timelineLoading ? (
                      <div className="py-12 text-center text-slate-400">
                        <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
                        جاري جمع الخط الزمني للترابط...
                      </div>
                    ) : timelineItems.length === 0 ? (
                      <div className="py-12 text-center text-slate-500 text-xs">
                        لم يتم العثور على أحداث مترابطة أخرى لهذا المعرّف.
                      </div>
                    ) : (
                      <div className="relative border-r-2 border-slate-800 mr-3 space-y-6">
                        {timelineItems.map((item, idx) => {
                          const isCurrent = item.id === selectedLog.id;
                          return (
                            <div key={item.id} className="relative pr-6">
                              {/* Circle node */}
                              <div
                                className={`absolute -right-[7px] top-1 w-3 h-3 rounded-full border-2 ${
                                  isCurrent
                                    ? 'bg-amber-400 border-amber-300 ring-4 ring-amber-400/20'
                                    : 'bg-slate-900 border-cyan-400'
                                }`}
                              />
                              <div
                                className={`p-4 rounded-xl border text-xs ${
                                  isCurrent
                                    ? 'bg-slate-900 border-amber-500/40 shadow-lg'
                                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                                }`}
                              >
                                <div className="flex items-center justify-between gap-2 mb-1">
                                  <div className="flex items-center gap-2">
                                    <span
                                      className={`px-2 py-0.5 rounded text-[9px] font-black ${
                                        LEVEL_CONFIG[item.level]?.badgeClass
                                      }`}
                                    >
                                      {item.level}
                                    </span>
                                    <span className="font-bold text-slate-200">{item.component}</span>
                                    <span className="font-mono text-slate-500 text-[10px]">
                                      {item.event_code}
                                    </span>
                                  </div>
                                  <span className="font-mono text-[10px] text-slate-400">
                                    {item.timestamp ? item.timestamp.slice(11, 23) : ''}
                                  </span>
                                </div>
                                <div className="text-slate-100 font-semibold mt-1">
                                  {getArabicLogMessage(item)}
                                </div>
                                {item.duration_ms !== null && (
                                  <div className="text-[10px] text-emerald-400 mt-1">
                                    ⏱️ زمن التنفيذ: {item.duration_ms.toFixed(1)} ms
                                  </div>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* Level 3: Deep Technical Details */}
                {drawerTab === 'technical' && (
                  <div className="space-y-4 text-xs">
                    {/* Error & Stack Trace (if present) */}
                    {(selectedLog.exception_type || selectedLog.stack_trace) && (
                      <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/30">
                        <div className="text-red-300 font-bold mb-2 flex items-center justify-between">
                          <span>الاستثناء: {selectedLog.exception_type || 'Unknown Exception'}</span>
                          <button
                            onClick={() =>
                              copyToClipboard(selectedLog.stack_trace || '', 'stack')
                            }
                            className="px-2 py-1 rounded bg-red-900/40 hover:bg-red-900/60 text-red-200 text-[10px] flex items-center gap-1"
                          >
                            <Copy className="w-3 h-3" />
                            {copiedKey === 'stack' ? 'تم النسخ!' : 'نسخ Trace'}
                          </button>
                        </div>
                        {selectedLog.stack_trace && (
                          <pre className="font-mono text-[11px] text-red-200/90 bg-slate-950 p-3 rounded-lg overflow-x-auto whitespace-pre leading-relaxed dir-ltr text-left">
                            {selectedLog.stack_trace}
                          </pre>
                        )}
                      </div>
                    )}

                    {/* Technical Details JSON */}
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-slate-400 font-bold">بيانات تقنية (Technical Details):</span>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              JSON.stringify(selectedLog.technical_details || {}, null, 2),
                              'details'
                            )
                          }
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" />
                          {copiedKey === 'details' ? 'تم النسخ!' : 'نسخ'}
                        </button>
                      </div>
                      <pre className="font-mono text-[11px] text-slate-300 bg-slate-900/60 p-3 rounded-lg overflow-x-auto dir-ltr text-left">
                        {selectedLog.technical_details
                          ? JSON.stringify(selectedLog.technical_details, null, 2)
                          : '{}'}
                      </pre>
                    </div>

                    {/* Raw Event JSON */}
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-slate-400 font-bold">سجل JSON الخام الكامل:</span>
                        <button
                          onClick={() => copyToClipboard(selectedLog.raw_json, 'raw')}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" />
                          {copiedKey === 'raw' ? 'تم النسخ!' : 'نسخ JSON'}
                        </button>
                      </div>
                      <pre className="font-mono text-[10px] text-cyan-300 bg-slate-900/90 p-3 rounded-lg overflow-x-auto max-h-60 dir-ltr text-left">
                        {(() => {
                          try {
                            return JSON.stringify(JSON.parse(selectedLog.raw_json), null, 2);
                          } catch {
                            return selectedLog.raw_json;
                          }
                        })()}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Standalone Correlation Modal */}
        {modalCorrelationId && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-fadeIn">
            <div className="w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
              <div className="p-5 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-300">
                    <Network className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">الخط الزمني للترابط المشترك</h3>
                    <div className="text-xs font-mono text-cyan-400 mt-0.5">{modalCorrelationId}</div>
                  </div>
                </div>
                <button
                  onClick={() => setModalCorrelationId(null)}
                  className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6">
                {modalLoading ? (
                  <div className="py-16 text-center text-slate-400">
                    <RefreshCw className="w-7 h-7 animate-spin mx-auto mb-2 text-cyan-400" />
                    جاري تتبع مسار العمليات المترابطة...
                  </div>
                ) : modalTimeline.length === 0 ? (
                  <div className="py-16 text-center text-slate-500 text-sm">
                    لا توجد سجلات مرتبطة بهذا المعرّف.
                  </div>
                ) : (
                  <div className="relative border-r-2 border-slate-800 mr-4 space-y-6">
                    {modalTimeline.map((step, idx) => (
                      <div key={step.id} className="relative pr-6">
                        <div className="absolute -right-[7px] top-1.5 w-3 h-3 rounded-full border-2 border-cyan-400 bg-slate-950" />
                        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 text-xs">
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[9px] font-black ${
                                  LEVEL_CONFIG[step.level]?.badgeClass
                                }`}
                              >
                                {step.level}
                              </span>
                              <span className="font-bold text-slate-200">{step.component}</span>
                              <span className="font-mono text-amber-400/90 text-[10px]">
                                {step.event_code}
                              </span>
                            </div>
                            <span className="font-mono text-[10px] text-slate-400">
                              {step.timestamp ? step.timestamp.slice(11, 23) : ''}
                            </span>
                          </div>
                          <div className="text-slate-100 font-semibold text-sm mt-1">
                            {getArabicLogMessage(step)}
                          </div>
                          {step.duration_ms !== null && (
                            <div className="text-[10px] text-emerald-400 mt-1">
                              ⏱️ زمن التنفيذ: {step.duration_ms.toFixed(1)} ms
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
                <button
                  onClick={() => setModalCorrelationId(null)}
                  className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold"
                >
                  إغلاق النافذة
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

