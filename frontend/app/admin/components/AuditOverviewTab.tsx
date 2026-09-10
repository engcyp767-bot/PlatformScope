'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ScrollText,
  ArrowUpRight,
  ShieldCheck,
  Download,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Search,
} from 'lucide-react';
import { getAuditLogs, getAuditSummary, verifyAuditIntegrity } from '../../../lib/api';
import { AuditEvent, AuditSummary } from '../../../lib/types';

export function AuditOverviewTab() {
  const [summary, setSummary] = useState<AuditSummary | null>(null);
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [appFilter, setAppFilter] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ verified: boolean; message: string } | null>(
    null
  );

  const loadAuditData = async () => {
    setLoading(true);
    try {
      const [sumRes, logsRes] = await Promise.all([
        getAuditSummary().catch(() => null),
        getAuditLogs({ limit: 25, search, application: appFilter }).catch(() => ({
          events: [],
          total: 0,
        })),
      ]);
      setSummary(sumRes);
      setLogs(logsRes.events || []);
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAuditData();
  }, [search, appFilter]);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditIntegrity();
      setVerifyResult(res);
    } catch (err: unknown) {
      setVerifyResult({
        verified: false,
        message: err instanceof Error ? err.message : 'فشل الاتصال بمحرك التحقق التشفيري.',
      });
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 bg-gradient-to-r from-sky-900/10 via-dark-900 to-dark-900">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 shrink-0">
              <ScrollText className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>سجلات التدقيق الأمني ونشاط المنظومة (Platform Audit & Activity)</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  سلسلة تجزئة SHA-256
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                يسجل النظام كافة العمليات الحساسة (تسجيل الدخول، إنشاء وتعديل المستخدمين، تعديل الصلاحيات، تصدير الحزم الجنائية، وتغيير الإعدادات) مع سلسلة تشفير مانعة للتلاعب.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleVerify}
              disabled={verifying}
              className="px-3.5 py-2 rounded-xl bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 font-bold text-xs flex items-center gap-2 transition-all disabled:opacity-50"
              title="فحص السلسلة التشفيرية"
            >
              <ShieldCheck className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
              <span>{verifying ? 'جارٍ فحص السلسلة...' : 'فحص نزاهة السلسلة'}</span>
            </button>
            <a
              href="/api/audit/export?format=csv"
              download
              className="px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs font-bold flex items-center gap-1.5 transition-all"
              title="تصدير السجلات بصيغة CSV"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              <span>CSV</span>
            </a>
            <a
              href="/api/audit/export?format=json"
              download
              className="px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-xs font-bold flex items-center gap-1.5 transition-all"
              title="تصدير السجلات بصيغة JSON"
            >
              <Download className="w-3.5 h-3.5 text-purple-400" />
              <span>JSON</span>
            </a>
            <Link
              href="/logs"
              className="px-3.5 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs flex items-center gap-1.5 shadow-lg shadow-sky-600/20 transition-all"
            >
              <span>مستكشف السجلات</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>

        {/* Verify Banner */}
        {verifyResult && (
          <div
            className={`mt-4 p-3 rounded-xl border text-xs flex items-center justify-between gap-3 ${
              verifyResult.verified
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            }`}
          >
            <div className="flex items-center gap-2">
              {verifyResult.verified ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{verifyResult.message}</span>
            </div>
            <button
              onClick={() => setVerifyResult(null)}
              className="text-[10px] text-slate-400 hover:text-white underline"
            >
              إغلاق
            </button>
          </div>
        )}
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div className="glass-panel p-4 rounded-2xl border border-white/10">
          <span className="text-slate-400 text-[11px] block">السجلات المحفوظة</span>
          <span className="text-xl font-bold text-white font-mono mt-1 block">
            {summary?.retained_events ?? 0}
          </span>
        </div>
        <div className="glass-panel p-4 rounded-2xl border border-white/10">
          <span className="text-slate-400 text-[11px] block">أحداث آخر 24 ساعة</span>
          <span className="text-xl font-bold text-sky-400 font-mono mt-1 block">
            {summary?.last_24_hours ?? 0}
          </span>
        </div>
        <div className="glass-panel p-4 rounded-2xl border border-white/10">
          <span className="text-slate-400 text-[11px] block">عمليات غير ناجحة (24h)</span>
          <span className="text-xl font-bold text-rose-400 font-mono mt-1 block">
            {summary?.failures_24h ?? 0}
          </span>
        </div>
        <div className="glass-panel p-4 rounded-2xl border border-white/10">
          <span className="text-slate-400 text-[11px] block">مستخدمون نشطون (24h)</span>
          <span className="text-xl font-bold text-emerald-400 font-mono mt-1 block">
            {summary?.users_24h ?? 0}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <select
            value={appFilter}
            onChange={(e) => setAppFilter(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-white/5 border border-white/10 text-xs text-white focus:border-sky-500 focus:outline-none"
          >
            <option value="">جميع التطبيقات والمحركات</option>
            <option value="platform">Platform Core</option>
            <option value="flowscope">FlowScope</option>
            <option value="threatscope">ThreatScope</option>
            <option value="logscope">LogScope</option>
          </select>
          <button
            onClick={loadAuditData}
            disabled={loading}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
            title="تحديث"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-sky-400' : ''}`} />
          </button>
        </div>

        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="بحث في سجلات التدقيق..."
            className="w-full pr-8 pl-3 py-1.5 rounded-xl bg-white/5 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="glass-panel overflow-hidden border border-white/10 rounded-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-right">
            <thead className="bg-white/5 text-slate-400 border-b border-white/5 font-semibold">
              <tr>
                <th className="p-3.5">الوقت</th>
                <th className="p-3.5">التطبيق</th>
                <th className="p-3.5">التصنيف</th>
                <th className="p-3.5">الإجراء</th>
                <th className="p-3.5">النتيجة</th>
                <th className="p-3.5">المستخدم</th>
                <th className="p-3.5">الرسالة والتفاصيل</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {logs.map((e) => (
                <tr key={e.id} className="hover:bg-white/5 transition-colors">
                  <td className="p-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleTimeString('ar-SA')} -{' '}
                    {new Date(e.timestamp).toLocaleDateString('ar-SA')}
                  </td>
                  <td className="p-3.5 font-bold text-white">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-sky-500/10 text-sky-300 border border-sky-500/20">
                      {e.application}
                    </span>
                  </td>
                  <td className="p-3.5 text-slate-400 text-[11px]">{e.category}</td>
                  <td className="p-3.5 font-mono text-[11px] text-purple-300">{e.action}</td>
                  <td className="p-3.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        e.outcome === 'success'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : e.outcome === 'denied'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}
                    >
                      {e.outcome === 'success' ? 'ناجح' : e.outcome === 'denied' ? 'مرفوض' : 'فشل'}
                    </span>
                  </td>
                  <td className="p-3.5 font-mono text-slate-300 text-[11px]">
                    {e.username || '—'}
                  </td>
                  <td className="p-3.5 text-slate-300 text-[11px] max-w-xs truncate">
                    {e.message}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 text-xs">
                    {loading ? 'جارٍ تحميل سجلات التدقيق...' : 'لا توجد سجلات تدقيق مطابقة للبحث.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
