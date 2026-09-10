'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight,
  Clock3, Filter, RefreshCw, Search, ShieldCheck, UserRound, XCircle,
} from 'lucide-react';
import { Navbar } from '../../components/Navbar';
import { getAuditLogs, getAuditSummary } from '../../lib/api';
import { AuditEvent, AuditSummary } from '../../lib/types';

const categoryLabels: Record<string, string> = {
  authentication: 'الدخول والجلسات', account: 'الحسابات', administration: 'الإدارة',
  analysis: 'التحليل', enrichment: 'المصادر الخارجية', report: 'التقارير', learning: 'التعلّم',
  jobs: 'المهام', history: 'سجل العمليات', audit: 'سجل التدقيق', system: 'النظام', api: 'واجهة API',
};

const outcomeLabels: Record<string, string> = { success: 'ناجحة', failure: 'فاشلة', denied: 'مرفوضة' };

function EventBadge({ event }: { event: AuditEvent }) {
  const style = event.level === 'error'
    ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
    : event.level === 'warning'
      ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
      : 'bg-cyan-500/10 text-cyan-200 border-cyan-500/25';
  return <span className={`px-2.5 py-1 rounded-full border text-[11px] font-bold ${style}`}>
    {event.level === 'error' ? 'خطأ' : event.level === 'warning' ? 'تحذير' : 'معلومة'}
  </span>;
}

function SummaryCard({ title, value, hint, tone = 'cyan' }: { title: string; value: number; hint: string; tone?: 'cyan' | 'rose' | 'emerald' | 'violet' }) {
  const tones = {
    cyan: 'from-cyan-500/15 border-cyan-500/20 text-cyan-300',
    rose: 'from-rose-500/15 border-rose-500/20 text-rose-300',
    emerald: 'from-emerald-500/15 border-emerald-500/20 text-emerald-300',
    violet: 'from-violet-500/15 border-violet-500/20 text-violet-300',
  };
  return <div className={`rounded-2xl border bg-gradient-to-bl ${tones[tone]} to-transparent p-5`}>
    <div className="text-xs text-slate-400">{title}</div>
    <div className="text-3xl font-black mt-2 tabular-nums">{value.toLocaleString('en-US')}</div>
    <div className="text-[11px] text-slate-500 mt-1">{hint}</div>
  </div>;
}

export default function LogsPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filters, setFilters] = useState({ search: '', application: '', level: '', category: '', outcome: '' });
  const [appliedSearch, setAppliedSearch] = useState('');
  const limit = 50;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [logs, totals] = await Promise.all([
        getAuditLogs({ ...filters, search: appliedSearch, page, limit }),
        getAuditSummary(),
      ]);
      setEvents(logs.events || []);
      setTotal(logs.total || 0);
      setSummary(totals);
    } finally {
      setLoading(false);
    }
  }, [filters.application, filters.level, filters.category, filters.outcome, appliedSearch, page]);

  useEffect(() => { load().catch(() => setLoading(false)); }, [load]);
  useEffect(() => {
    const timer = setTimeout(() => { setPage(1); setAppliedSearch(filters.search.trim()); }, 350);
    return () => clearTimeout(timer);
  }, [filters.search]);

  const totalPages = Math.max(1, Math.ceil(total / limit));
  const activeFilters = useMemo(() => Object.values(filters).filter(Boolean).length, [filters]);

  return <div className="min-h-screen">
    <Navbar />
    <main className="max-w-[1500px] mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4 mb-7">
        <div>
          <div className="inline-flex items-center gap-2 text-cyan-300 text-xs font-bold tracking-wider mb-2">
            <ShieldCheck className="w-4 h-4" /> AUDIT & OBSERVABILITY
          </div>
          <h1 className="text-3xl font-black text-white">سجل التدقيق التفصيلي</h1>
          <p className="text-sm text-slate-400 mt-2">تتبّع موحّد لكل عمليات المستخدمين والتحليل والتصدير وحالة الخدمات، مع زمن التنفيذ والنتيجة.</p>
        </div>
        <button onClick={() => load()} disabled={loading} className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/25 text-cyan-200 text-sm font-bold disabled:opacity-50">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> تحديث السجل
        </button>
      </div>

      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <SummaryCard title="إجمالي الأحداث المحفوظة" value={summary?.retained_events || 0} hint="ضمن ملفات السجل الحالية" />
        <SummaryCard title="أحداث آخر 24 ساعة" value={summary?.last_24_hours || 0} hint="كل التطبيقات والخدمات" tone="violet" />
        <SummaryCard title="فشل أو رفض خلال 24 ساعة" value={summary?.failures_24h || 0} hint="للمراجعة والتحقق" tone="rose" />
        <SummaryCard title="المستخدمون النشطون" value={summary?.users_24h || 0} hint="خلال آخر 24 ساعة" tone="emerald" />
      </section>

      <section className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-white/10 bg-white/[0.025]">
          <div className="flex flex-col xl:flex-row gap-3">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input value={filters.search} onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                placeholder="ابحث بالمستخدم، العملية، المهمة، المسار أو التفاصيل..."
                className="w-full bg-dark-950/70 border border-white/10 rounded-xl py-2.5 pr-10 pl-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/40 outline-none" />
            </div>
            {[
              ['application', 'كل التطبيقات', [['platform', 'المنصة'], ['flowscope', 'FlowScope'], ['threatscope', 'ThreatScope'], ['logscope', 'LogScope']]],
              ['level', 'كل المستويات', [['info', 'معلومة'], ['warning', 'تحذير'], ['error', 'خطأ']]],
              ['outcome', 'كل النتائج', [['success', 'ناجحة'], ['failure', 'فاشلة'], ['denied', 'مرفوضة']]],
              ['category', 'كل الفئات', Object.entries(categoryLabels)],
            ].map(([key, label, options]) => <select key={String(key)} value={filters[key as keyof typeof filters]}
              onChange={(e) => { setPage(1); setFilters({ ...filters, [String(key)]: e.target.value }); }}
              className="bg-dark-950/70 border border-white/10 rounded-xl px-3 py-2.5 text-xs text-slate-200 outline-none focus:border-cyan-500/40">
              <option value="">{String(label)}</option>
              {(options as string[][]).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
            </select>)}
            {activeFilters > 0 && <button onClick={() => { setFilters({ search: '', application: '', level: '', category: '', outcome: '' }); setAppliedSearch(''); setPage(1); }}
              className="px-3 py-2 rounded-xl text-xs text-slate-400 hover:text-white hover:bg-white/5 flex items-center gap-1"><Filter className="w-3.5 h-3.5" /> مسح ({activeFilters})</button>}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1050px] text-right">
            <thead className="text-[11px] text-slate-500 uppercase bg-dark-950/40 border-b border-white/10">
              <tr><th className="p-4">الوقت</th><th className="p-4">المستوى</th><th className="p-4">العملية</th><th className="p-4">التطبيق</th><th className="p-4">المستخدم</th><th className="p-4">النتيجة</th><th className="p-4">المدة</th><th className="p-4 w-10"></th></tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {!loading && events.length === 0 && <tr><td colSpan={8} className="p-16 text-center text-slate-500">لا توجد أحداث تطابق عوامل البحث الحالية.</td></tr>}
              {events.map((event) => <React.Fragment key={event.id}>
                <tr onClick={() => setExpanded(expanded === event.id ? null : event.id)} className="hover:bg-white/[0.035] cursor-pointer transition-colors">
                  <td className="p-4 whitespace-nowrap"><div className="text-xs text-slate-200 tabular-nums">{new Date(event.timestamp).toLocaleDateString('en-US')}</div><div className="text-[11px] text-slate-500 mt-1" dir="ltr">{new Date(event.timestamp).toLocaleTimeString('en-US')}</div></td>
                  <td className="p-4"><EventBadge event={event} /></td>
                  <td className="p-4"><div className="text-sm font-bold text-slate-100">{event.message}</div><div className="text-[11px] text-slate-500 mt-1">{categoryLabels[event.category] || event.category} · {event.action}</div></td>
                  <td className="p-4"><span className={`px-2 py-1 rounded-lg text-[11px] font-bold ${event.application === 'flowscope' ? 'bg-cyan-500/10 text-cyan-300' : event.application === 'threatscope' ? 'bg-rose-500/10 text-rose-300' : event.application === 'logscope' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-violet-500/10 text-violet-300'}`}>{event.application === 'platform' ? 'المنصة' : event.application}</span></td>
                  <td className="p-4"><div className="text-xs text-slate-200 flex items-center gap-1.5"><UserRound className="w-3.5 h-3.5 text-slate-500" />{event.display_name || event.username || 'غير مسجّل'}</div><div className="text-[10px] text-slate-600 mt-1" dir="ltr">{event.client_ip || '—'}</div></td>
                  <td className="p-4"><span className={`inline-flex items-center gap-1 text-xs font-bold ${event.outcome === 'success' ? 'text-emerald-300' : event.outcome === 'denied' ? 'text-amber-300' : 'text-rose-300'}`}>{event.outcome === 'success' ? <CheckCircle2 className="w-4 h-4" /> : event.outcome === 'denied' ? <AlertTriangle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}{outcomeLabels[event.outcome]}</span><div className="text-[10px] text-slate-600 mt-1" dir="ltr">HTTP {event.status_code || '—'}</div></td>
                  <td className="p-4"><span className="text-xs text-slate-300 inline-flex items-center gap-1"><Clock3 className="w-3.5 h-3.5 text-slate-500" />{event.duration_ms === undefined ? '-' : `${event.duration_ms.toLocaleString('en-US')} ms`}</span></td>
                  <td className="p-4"><ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${expanded === event.id ? 'rotate-180' : ''}`} /></td>
                </tr>
                {expanded === event.id && <tr className="bg-dark-950/45"><td colSpan={8} className="p-5">
                  <div className="grid md:grid-cols-3 gap-4 mb-4 text-xs">
                    <div><span className="text-slate-500">معرّف الطلب</span><div className="font-mono text-cyan-200 mt-1 break-all" dir="ltr">{event.request_id || event.id}</div></div>
                    <div><span className="text-slate-500">معرّف المهمة</span><div className="font-mono text-slate-200 mt-1" dir="ltr">{event.job_id || '—'}</div></div>
                    <div><span className="text-slate-500">الطلب</span><div className="font-mono text-slate-200 mt-1 break-all" dir="ltr">{event.method} {event.path}</div></div>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-black/25 p-4"><div className="text-xs font-bold text-slate-300 mb-2">التفاصيل الفنية المنقّحة</div><pre className="text-[11px] leading-6 text-slate-400 whitespace-pre-wrap break-all text-left" dir="ltr">{JSON.stringify(event.details || {}, null, 2)}</pre></div>
                </td></tr>}
              </React.Fragment>)}
            </tbody>
          </table>
        </div>

        <div className="p-4 border-t border-white/10 flex items-center justify-between text-xs text-slate-400">
          <span>عرض {events.length.toLocaleString('en-US')} من أصل {total.toLocaleString('en-US')} سجل</span>
          <div className="flex items-center gap-2"><button disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)} className="p-2 rounded-lg border border-white/10 disabled:opacity-30 hover:bg-white/5"><ChevronRight className="w-4 h-4" /></button><span className="px-3">صفحة {page.toLocaleString('en-US')} من {totalPages.toLocaleString('en-US')}</span><button disabled={page >= totalPages || loading} onClick={() => setPage((p) => p + 1)} className="p-2 rounded-lg border border-white/10 disabled:opacity-30 hover:bg-white/5"><ChevronLeft className="w-4 h-4" /></button></div>
        </div>
      </section>
    </main>
  </div>;
}
