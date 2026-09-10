import React, { useEffect, useState } from 'react';
import { HardDrive, Trash2, Clock, ShieldAlert, AlertTriangle, RefreshCw, Database, CheckCircle2 } from 'lucide-react';
import { PlatformConfig, StorageStats } from '../../../lib/types';
import { Field, SectionCard, inputClass } from './FormControls';
import { getStorageStats, vacuumStorageDatabases, cleanupEnterpriseStorage } from '../../../lib/api';

export function TabStorage({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['storage']>) => void;
}) {
  const s = config.storage;
  const [stats, setStats] = useState<StorageStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionRunning, setActionRunning] = useState<'vacuum' | 'cleanup' | null>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);

  const loadStats = async () => {
    setLoading(true);
    try {
      const res = await getStorageStats();
      setStats(res);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadStats();
  }, []);

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Real Storage Breakdown Card */}
      <SectionCard
        title="استهلاك القرص والملفات الفعلي"
        subtitle="قراءة فورية ومباشرة لمجلدات التخزين وسعة القرص الصلب لنظام التشغيل"
        action={
          <button
            type="button"
            onClick={loadStats}
            disabled={loading}
            className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-300 flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            تحديث المقاييس
          </button>
        }
      >
        {stats?.disk ? (
          <div className="space-y-5">
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-bold">المساحة الإجمالية للقرص الصلب</span>
                <span className="font-bold text-white">
                  {stats.disk.used_percent}% مستخدم ({formatBytes(stats.disk.used_bytes)} / {formatBytes(stats.disk.total_bytes)})
                </span>
              </div>
              <div className="w-full h-3 rounded-full bg-slate-800 overflow-hidden border border-white/10">
                <div
                  className={`h-full transition-all duration-500 ${
                    stats.disk.used_percent > 85 ? 'bg-rose-500' : 'bg-cyan-500'
                  }`}
                  style={{ width: `${Math.min(100, stats.disk.used_percent)}%` }}
                />
              </div>
              <div className="text-[11px] text-slate-400 flex justify-between">
                <span>المساحة الشاغرة: {formatBytes(stats.disk.free_bytes)}</span>
                <span>الموقع: جذر تخزين المنصة (storage/)</span>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                <div className="text-[11px] text-slate-400">مهام FlowScope</div>
                <div className="text-base font-black text-white mt-1">{stats.jobs.flowscope.count}</div>
                <div className="text-[10px] text-slate-500">{formatBytes(stats.jobs.flowscope.bytes)}</div>
              </div>
              <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                <div className="text-[11px] text-slate-400">مهام ThreatScope</div>
                <div className="text-base font-black text-white mt-1">{stats.jobs.threatscope.count}</div>
                <div className="text-[10px] text-slate-500">{formatBytes(stats.jobs.threatscope.bytes)}</div>
              </div>
              <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                <div className="text-[11px] text-slate-400">مهام LogScope</div>
                <div className="text-base font-black text-white mt-1">{stats.jobs.logscope.count}</div>
                <div className="text-[10px] text-slate-500">{formatBytes(stats.jobs.logscope.bytes)}</div>
              </div>
              <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                <div className="text-[11px] text-slate-400">سجلات التدقيق (Audit)</div>
                <div className="text-base font-black text-white mt-1">{stats.audit.file_count} ملفات</div>
                <div className="text-[10px] text-slate-500">{formatBytes(stats.audit.bytes)}</div>
              </div>
            </div>
          </div>
        ) : (
          <div className="py-6 text-center text-xs text-slate-500">جارٍ قراءة مقاييس التخزين...</div>
        )}
      </SectionCard>

      {/* Retention Policies */}
      <SectionCard
        title="سياسات الاحتفاظ والتنظيف التلقائي (Data Retention Policies)"
        subtitle="تحديد مدة بقاء مهام التحليل القديمة وملفات التدقيق والمعاينة المؤقتة (0 = احتفاظ دائم دون حذف)"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="الاحتفاظ بمهام التحليل بالأيام (Job Retention Days)"
            hint="حذف مجلدات المهام الأقدم من هذه المدة تلقائيًا عند تشغيل المنصة (0 = لا تحذف أبدًا)"
          >
            <input
              type="number"
              min={0}
              max={3650}
              className={inputClass}
              value={s.job_retention_days}
              onChange={(e) => onChange({ job_retention_days: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="الاحتفاظ بسجلات التدقيق بالأيام (Audit Retention Days)"
            hint="مدة بقاء ملفات التدقيق الأمنية JSONL قبل الأرشفة أو الحذف (0 = دائم)"
          >
            <input
              type="number"
              min={0}
              max={3650}
              className={inputClass}
              value={s.audit_retention_days}
              onChange={(e) => onChange({ audit_retention_days: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="الاحتفاظ بملفات المعاينة بالساعات (Preview Retention Hours)"
            hint="تنظيف ملفات PDF المؤقتة في مجلد tmp/report-previews (0 = دائم)"
          >
            <input
              type="number"
              min={0}
              max={8760}
              className={inputClass}
              value={s.preview_retention_hours}
              onChange={(e) => onChange({ preview_retention_hours: Number(e.target.value) })}
            />
          </Field>

          <Field
            label="عدد سجلات العمليات في الصفحة (History Page Size)"
            hint="سقف استرجاع السجلات في شاشة سجل العمليات (10 - 500)"
          >
            <input
              type="number"
              min={10}
              max={500}
              className={inputClass}
              value={s.history_page_size}
              onChange={(e) => onChange({ history_page_size: Number(e.target.value) })}
            />
          </Field>
        </div>

        <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4 text-xs text-rose-200 leading-relaxed">
          <strong>تنبيه أمني:</strong> عند ضبط مدة أكبر من صفر، تُحذف المهام والمجلدات المعرّفة بنمط 32 رمزًا سداسيًا الأقدم من المدة المحددة عند إقلاع المنصة. لا يمكن استرجاع المهام المحذوفة برمجيًا بعد تطبيق التنظيف.
        </div>
      </SectionCard>

      {/* Interactive Maintenance & VACUUM */}
      <SectionCard
        title="تفريغ قواعد البيانات وحوكمة المساحة (Defragmentation & Maintenance)"
        subtitle="تشغيل أوامر VACUUM المباشرة لاستعادة المساحات غير المستغلة وتنفيذ دورة الأرشفة الفورية"
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={actionRunning !== null}
              onClick={async () => {
                try {
                  setActionRunning('vacuum');
                  setActionResult(null);
                  const res = await vacuumStorageDatabases();
                  setActionResult(`تم تنفيذ تفريغ قواعد البيانات بنجاح: تم استرداد ${res.reclaimed_total_mb} ميغابايت ومعالجة ${res.databases_processed} قاعدة بيانات.`);
                  loadStats();
                } catch (e: any) {
                  setActionResult(`فشل تنفيذ VACUUM: ${e.message}`);
                } finally {
                  setActionRunning(null);
                }
              }}
              className="px-4 py-2 rounded-xl bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-xs font-bold text-purple-300 flex items-center gap-2 transition-all shadow-sm shadow-purple-600/10"
            >
              <Database className={`w-4 h-4 ${actionRunning === 'vacuum' ? 'animate-spin' : ''}`} />
              <span>تنفيذ تفريغ قواعد البيانات (VACUUM Now)</span>
            </button>

            <button
              type="button"
              disabled={actionRunning !== null}
              onClick={async () => {
                try {
                  setActionRunning('cleanup');
                  setActionResult(null);
                  const res = await cleanupEnterpriseStorage({
                    jobs_days: s.job_retention_days || 30,
                    audit_days: s.audit_retention_days || 90,
                    dry_run: false,
                  });
                  setActionResult(`اكتملت دورة الأرشفة والتنظيف: تم أرشفة المهام القديمة وتفريغ مساحات التخزين بنجاح.`);
                  loadStats();
                } catch (e: any) {
                  setActionResult(`فشل دورة التنظيف: ${e.message}`);
                } finally {
                  setActionRunning(null);
                }
              }}
              className="px-4 py-2 rounded-xl bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/30 text-xs font-bold text-cyan-300 flex items-center gap-2 transition-all shadow-sm shadow-cyan-600/10"
            >
              <Trash2 className={`w-4 h-4 ${actionRunning === 'cleanup' ? 'animate-spin' : ''}`} />
              <span>تطبيق دورة الأرشفة والتنظيف الآن</span>
            </button>
          </div>

          {actionResult && (
            <div className="p-3 rounded-xl bg-dark-950 border border-white/10 text-xs text-slate-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{actionResult}</span>
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
}
