'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  History,
  RotateCcw,
  Calendar,
  Clock,
  Cpu,
  Database,
  Archive,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Sliders,
} from 'lucide-react';
import { PlatformConfig, ConfigRevision } from '../../../lib/types';
import { getPlatformConfigHistory, rollbackPlatformConfig } from '../../../lib/api';

interface TabGovernanceProps {
  config: PlatformConfig;
  onChange: (updated: PlatformConfig) => void;
  onReload: () => void;
}

export function TabGovernance({ config, onChange, onReload }: TabGovernanceProps) {
  const [history, setHistory] = useState<ConfigRevision[]>([]);
  const [loadingHistory, setLoadingHistory] = useState<boolean>(true);
  const [rollingBack, setRollingBack] = useState<number | null>(null);
  const [actionMessage, setActionMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const gov = config.governance || {
    audit_retention_days: 90,
    job_retention_days: 30,
    max_workers: 4,
    session_timeout_minutes: 60,
    auto_vacuum_enabled: true,
    backup_retention_copies: 7,
  };

  const updateGov = (partial: Partial<typeof gov>) => {
    onChange({
      ...config,
      governance: { ...gov, ...partial },
    });
  };

  const fetchHistory = async () => {
    try {
      setLoadingHistory(true);
      const res = await getPlatformConfigHistory(30);
      setHistory(res.history || []);
    } catch (err) {
      console.error('Failed to fetch config history', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [config.version]);

  const handleRollback = async (rev: ConfigRevision) => {
    if (!window.confirm(`هل أنت متأكد من استرجاع إعدادات المنصة إلى الإصدار رقم ${rev.version} (تاريخ ${new Date(rev.timestamp).toLocaleString('ar-SA')})؟`)) {
      return;
    }

    try {
      setRollingBack(rev.id);
      setActionMessage(null);
      await rollbackPlatformConfig(rev.id);
      setActionMessage({ ok: true, text: `تم استرجاع إعدادات المنصة بنجاح إلى الإصدار رقم ${rev.version}.` });
      onReload();
      await fetchHistory();
    } catch (err: any) {
      setActionMessage({ ok: false, text: err.message || 'فشل استرجاع الإعدادات.' });
    } finally {
      setRollingBack(null);
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Action Message Banner */}
      {actionMessage && (
        <div
          className={`p-4 rounded-2xl border text-xs flex items-center gap-3 ${
            actionMessage.ok
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/20 text-rose-300'
          }`}
        >
          {actionMessage.ok ? (
            <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400" />
          ) : (
            <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400" />
          )}
          <span>{actionMessage.text}</span>
        </div>
      )}

      {/* Section 1: Enterprise Governance & Retention Controls */}
      <div className="p-6 rounded-2xl bg-dark-900/60 border border-white/10 space-y-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">سياسات الحوكمة ودورة حياة البيانات</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              تحديد مدد الاحتفاظ بالسجلات، وضوابط جلسات العمل، ومسارات المعالجة المركزية
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2">
          {/* Audit Retention */}
          <div className="p-4 rounded-xl bg-dark-950/60 border border-white/5 space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Calendar className="w-4 h-4 text-cyan-400" />
                <span>الاحتفاظ بسجلات التدقيق الأمني (أيام)</span>
              </label>
              <span className="text-xs font-bold font-mono text-cyan-400">{gov.audit_retention_days} يوم</span>
            </div>
            <p className="text-[11px] text-slate-400">المدة الزمنية للاحتفاظ بسجلات النشاط وتتبع العمليات قبل الأرشفة</p>
            <input
              type="number"
              min={1}
              max={3650}
              value={gov.audit_retention_days}
              onChange={(e) => updateGov({ audit_retention_days: parseInt(e.target.value) || 90 })}
              className="w-full px-3 py-2 rounded-xl bg-dark-900 border border-white/10 text-white text-xs font-mono focus:border-purple-500 outline-none"
            />
          </div>

          {/* Job Retention */}
          <div className="p-4 rounded-xl bg-dark-950/60 border border-white/5 space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Archive className="w-4 h-4 text-amber-400" />
                <span>الاحتفاظ بالمهام المكتملة (أيام)</span>
              </label>
              <span className="text-xs font-bold font-mono text-amber-400">{gov.job_retention_days} يوم</span>
            </div>
            <p className="text-[11px] text-slate-400">المدة الزمنية لحفظ مخرجات وتحليلات المهام القديمة في قائمة الانتظار</p>
            <input
              type="number"
              min={1}
              max={3650}
              value={gov.job_retention_days}
              onChange={(e) => updateGov({ job_retention_days: parseInt(e.target.value) || 30 })}
              className="w-full px-3 py-2 rounded-xl bg-dark-900 border border-white/10 text-white text-xs font-mono focus:border-purple-500 outline-none"
            />
          </div>

          {/* Max Workers */}
          <div className="p-4 rounded-xl bg-dark-950/60 border border-white/5 space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-purple-400" />
                <span>أقصى مسارات معالجة المهام (Workers)</span>
              </label>
              <span className="text-xs font-bold font-mono text-purple-400">{gov.max_workers} مسارات</span>
            </div>
            <p className="text-[11px] text-slate-400">الحد الأقصى لعدد الخيوط المخصصة لتنفيذ المهام والتحليلات المتوازية</p>
            <input
              type="number"
              min={1}
              max={64}
              value={gov.max_workers}
              onChange={(e) => updateGov({ max_workers: parseInt(e.target.value) || 4 })}
              className="w-full px-3 py-2 rounded-xl bg-dark-900 border border-white/10 text-white text-xs font-mono focus:border-purple-500 outline-none"
            />
          </div>

          {/* Session Timeout */}
          <div className="p-4 rounded-xl bg-dark-950/60 border border-white/5 space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Clock className="w-4 h-4 text-emerald-400" />
                <span>مهلة الخمول للجلسات (دقائق)</span>
              </label>
              <span className="text-xs font-bold font-mono text-emerald-400">{gov.session_timeout_minutes} دقيقة</span>
            </div>
            <p className="text-[11px] text-slate-400">إغلاق جلسة المستخدم تلقائياً بعد انقضاء هذه المدة دون تفاعل</p>
            <input
              type="number"
              min={5}
              max={1440}
              value={gov.session_timeout_minutes}
              onChange={(e) => updateGov({ session_timeout_minutes: parseInt(e.target.value) || 60 })}
              className="w-full px-3 py-2 rounded-xl bg-dark-900 border border-white/10 text-white text-xs font-mono focus:border-purple-500 outline-none"
            />
          </div>
        </div>

        {/* Database Vacuum & Backups */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2 border-t border-white/5">
          <div className="flex items-center justify-between p-4 rounded-xl bg-dark-950/60 border border-white/5">
            <div>
              <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-400" />
                <span>التنظيف والتحسين التلقائي (VACUUM)</span>
              </span>
              <p className="text-[11px] text-slate-400 mt-1">
                استرداد المساحات غير المستخدمة في قواعد بيانات SQLite دورياً
              </p>
            </div>
            <input
              type="checkbox"
              checked={gov.auto_vacuum_enabled}
              onChange={(e) => updateGov({ auto_vacuum_enabled: e.target.checked })}
              className="w-4 h-4 accent-purple-600 rounded cursor-pointer"
            />
          </div>

          <div className="p-4 rounded-xl bg-dark-950/60 border border-white/5 space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Archive className="w-4 h-4 text-indigo-400" />
                <span>عدد النسخ الاحتياطية المحفوظة</span>
              </label>
              <span className="text-xs font-bold font-mono text-indigo-400">{gov.backup_retention_copies} نسخ</span>
            </div>
            <input
              type="number"
              min={1}
              max={100}
              value={gov.backup_retention_copies}
              onChange={(e) => updateGov({ backup_retention_copies: parseInt(e.target.value) || 7 })}
              className="w-full px-3 py-2 rounded-xl bg-dark-900 border border-white/10 text-white text-xs font-mono focus:border-purple-500 outline-none"
            />
          </div>
        </div>
      </div>

      {/* Section 2: Configuration Version History & Rollback */}
      <div className="p-6 rounded-2xl bg-dark-900/60 border border-white/10 space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <History className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">سجل تعديلات الإعدادات والإصدارات</h3>
                <span className="px-2 py-0.5 rounded-full text-xs font-bold font-mono bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  الإصدار الحالي: v{config.version || 1}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                تتبع كامل لكافة التغييرات مع إمكانية الرجوع الفوري لأي إصدار سابق
              </p>
            </div>
          </div>

          <button
            onClick={fetchHistory}
            disabled={loadingHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingHistory ? 'animate-spin' : ''}`} />
            <span>تحديث السجل</span>
          </button>
        </div>

        {/* History Table */}
        <div className="overflow-x-auto rounded-xl border border-white/5">
          <table className="w-full text-right text-xs">
            <thead className="bg-dark-950/80 text-slate-400 border-b border-white/10">
              <tr>
                <th className="p-3 font-semibold">الإصدار</th>
                <th className="p-3 font-semibold">المستخدم</th>
                <th className="p-3 font-semibold">التاريخ والوقت</th>
                <th className="p-3 font-semibold">وصف التغيير</th>
                <th className="p-3 font-semibold text-center">الإجراء</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {history.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-500">
                    لا يوجد سجل تعديلات سابق حتى الآن (سيتم تسجيل أي حفظ جديد تلقائياً)
                  </td>
                </tr>
              ) : (
                history.map((rev) => {
                  const isCurrent = rev.version === config.version;
                  return (
                    <tr
                      key={rev.id}
                      className={`transition-colors ${
                        isCurrent ? 'bg-purple-500/5' : 'hover:bg-white/5'
                      }`}
                    >
                      <td className="p-3 font-mono font-bold text-purple-300">
                        v{rev.version}
                        {isCurrent && (
                          <span className="mr-2 px-1.5 py-0.5 rounded text-[10px] font-sans font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            الحالي
                          </span>
                        )}
                      </td>
                      <td className="p-3 font-medium text-slate-300">{rev.actor}</td>
                      <td className="p-3 text-slate-400 font-mono">
                        {new Date(rev.timestamp).toLocaleString('ar-SA')}
                      </td>
                      <td className="p-3 text-slate-300 max-w-xs truncate">{rev.summary || 'تعديل الإعدادات'}</td>
                      <td className="p-3 text-center">
                        {!isCurrent && (
                          <button
                            onClick={() => handleRollback(rev)}
                            disabled={rollingBack === rev.id}
                            className="flex items-center gap-1 mx-auto px-2.5 py-1 rounded-lg bg-white/5 hover:bg-rose-500/20 hover:text-rose-300 border border-white/10 hover:border-rose-500/30 text-slate-300 transition-all text-xs"
                            title="استرجاع هذا الإصدار"
                          >
                            <RotateCcw className={`w-3 h-3 ${rollingBack === rev.id ? 'animate-spin' : ''}`} />
                            <span>استرجاع</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
