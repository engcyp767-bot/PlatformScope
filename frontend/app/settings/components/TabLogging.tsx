import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { Activity, ShieldAlert, FileText, ExternalLink, RefreshCw } from 'lucide-react';
import { PlatformConfig } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass, selectClass } from './FormControls';
import { getAuditLogs, getAuditSummary } from '../../../lib/api';

export function TabLogging({
  config,
  onChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['logging']>) => void;
}) {
  const l = config.logging;
  const [logs, setLogs] = useState<any[]>([]);
  const [summary, setSummary] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);

  const loadAuditData = async () => {
    setLoading(true);
    try {
      const [logRes, sumRes] = await Promise.all([
        getAuditLogs({ limit: 5 }),
        getAuditSummary(),
      ]);
      setLogs(logRes.events || []);
      setSummary(sumRes || null);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadAuditData();
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      <SectionCard
        title="سياسة تسجيل الأحداث والتدقيق (Logging Policies)"
        subtitle="التحكم في دقة وعمق تسجيل العمليات التشغيلية والأمنية في ملفات التدقيق"
      >
        <div className="grid sm:grid-cols-2 gap-4 pb-2">
          <Toggle
            checked={l.enabled}
            onChange={(enabled) => onChange({ enabled })}
            label="تفعيل التسجيل التفصيلي (Engine Logging)"
            description="تسجيل كافة العمليات والتحليلات الجنائية في storage/logs/"
          />
          <Toggle
            checked={l.include_details}
            onChange={(include_details) => onChange({ include_details })}
            label="تضمين التفاصيل والبيانات الفنية"
            description="إدراج الحقول الموسعة ومعاملات الطلب في سجلات JSONL"
          />
        </div>

        <div className="grid md:grid-cols-2 gap-5 pt-3 border-t border-white/5">
          <Field
            label="الحد الأدنى لمستوى التسجيل (Logging Level)"
            hint="تحديد عتبة تسجيل الرسائل (الافتراضي: Info للمنظومات المستقرة)"
          >
            <select
              className={selectClass}
              value={l.level}
              onChange={(e) => onChange({ level: e.target.value })}
            >
              <option value="debug">Debug (تفصيلي شامل لتصحيح الأخطاء)</option>
              <option value="info">Info (معلوماتي قياسي - موصى به)</option>
              <option value="warning">Warning (تحذيرات فقط)</option>
              <option value="error">Error (أخطاء تشغيلية فقط)</option>
            </select>
          </Field>

          <Field
            label="أقصى طول لنص التفاصيل (Max Detail Length)"
            hint="الحد الأقصى لعدد محارف حقل التفاصيل لتجنب تضخم السجلات (100 - 5000)"
          >
            <input
              type="number"
              min={100}
              max={5000}
              className={inputClass}
              value={l.max_detail_length}
              onChange={(e) => onChange({ max_detail_length: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>

      {/* Recent Audit Events Preview */}
      <SectionCard
        title="آخر أحداث التدقيق المسجلة (Audit Logs Preview)"
        subtitle="موجز مباشر من سجل العمليات الأمني الموحد"
        action={
          <Link
            href="/logs"
            className="px-3 py-1.5 rounded-xl border border-white/10 text-xs font-semibold text-cyan-400 hover:bg-cyan-500/10 flex items-center gap-1.5 transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            سجل التدقيق الكامل
          </Link>
        }
      >
        {loading ? (
          <div className="py-6 text-center text-xs text-slate-500">جارٍ قراءة أحداث التدقيق...</div>
        ) : logs.length === 0 ? (
          <div className="p-4 rounded-xl border border-white/5 bg-white/[0.01] text-xs text-slate-500 text-center">
            لا توجد أحداث مسجلة حتى الآن.
          </div>
        ) : (
          <div className="space-y-2">
            {logs.map((evt, idx) => (
              <div
                key={evt.id || idx}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-xl border border-white/5 bg-white/[0.015] text-xs"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white">{evt.action || 'حدث'}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-white/10 text-slate-300">
                      {evt.application || 'platform'}
                    </span>
                    <span className="text-[11px] text-slate-400">بواسطة: {evt.username || 'System'}</span>
                  </div>
                  <p className="text-slate-400 text-[11px]">{evt.message}</p>
                </div>
                <div className="text-[10px] text-slate-500 shrink-0">
                  {new Date(evt.timestamp).toLocaleString('ar-EG')}
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
