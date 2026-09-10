'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock, Globe, Server, Radio, RefreshCw, CheckCircle2,
  AlertTriangle, Play, Calendar, Zap, ShieldCheck, Check,
  ArrowRight, Info
} from 'lucide-react';
import { PlatformConfig, PlatformTimeConfig, PlatformTimeStatus } from '../../../lib/types';
import { Field, Toggle, SectionCard, inputClass, selectClass } from './FormControls';
import { getPlatformTime, syncPlatformTime, testPlatformConnection } from '../../../lib/api';

const DEFAULT_NTP_PRESETS = [
  { label: 'حوض التوقيت العالمي (pool.ntp.org)', value: 'pool.ntp.org' },
  { label: 'خادم جوجل (time.google.com)', value: 'time.google.com' },
  { label: 'خادم كلاود فلير (time.cloudflare.com)', value: 'time.cloudflare.com' },
  { label: 'خادم مايكروسوفت (time.windows.com)', value: 'time.windows.com' },
];

export function TabGeneral({
  config,
  onChange,
  onTimeChange,
}: {
  config: PlatformConfig;
  onChange: (values: Partial<PlatformConfig['general']>) => void;
  onTimeChange?: (values: Partial<PlatformTimeConfig>) => void;
}) {
  const g = config.general;
  const timeCfg: PlatformTimeConfig = {
    source: 'host',
    manual_time: '',
    ntp_server: 'pool.ntp.org',
    ntp_port: 123,
    ntp_sync_interval_seconds: 3600,
    auto_sync: true,
    ...(config.time || {}),
  };

  // Live status telemetry state
  const [timeStatus, setTimeStatus] = useState<PlatformTimeStatus | null>(null);
  const [liveSeconds, setLiveSeconds] = useState<number>(Date.now());
  const [isSyncing, setIsSyncing] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<{ ok: boolean; message: string } | null>(null);

  // Fetch live time status from API
  const refreshTimeStatus = useCallback(async () => {
    try {
      const res = await getPlatformTime();
      setTimeStatus(res);
    } catch {
      // Degraded fallback
    }
  }, []);

  useEffect(() => {
    refreshTimeStatus();
    const interval = setInterval(() => {
      setLiveSeconds(Date.now());
    }, 1000);
    return () => clearInterval(interval);
  }, [refreshTimeStatus]);

  // Handle immediate NTP sync
  const handleImmediateSync = async () => {
    setIsSyncing(true);
    setActionFeedback(null);
    try {
      const res = await syncPlatformTime({
        server: timeCfg.ntp_server,
        port: timeCfg.ntp_port,
      });
      setTimeStatus(res.status);
      setActionFeedback({
        ok: res.ok,
        message: res.message || (res.ok ? 'تمت المزامنة بنجاح' : 'فشلت المزامنة'),
      });
    } catch (err: any) {
      setActionFeedback({
        ok: false,
        message: err.message || 'حدث خطأ أثناء الاتصال بالخادم لمزامنة الوقت',
      });
    } finally {
      setIsSyncing(false);
    }
  };

  // Handle testing NTP connection
  const handleTestNtp = async () => {
    setIsTesting(true);
    setActionFeedback(null);
    try {
      const res = await testPlatformConnection({
        kind: 'ntp',
        ntp_server: timeCfg.ntp_server,
        ntp_port: timeCfg.ntp_port,
      });
      setActionFeedback({
        ok: res.ok,
        message: res.ok ? `${res.message} ${res.sample ? `(${res.sample})` : ''}` : res.message,
      });
    } catch (err: any) {
      setActionFeedback({
        ok: false,
        message: err.message || 'تعذر فحص الاتصال بخادم NTP',
      });
    } finally {
      setIsTesting(false);
    }
  };

  // Calculate formatted live times
  const formatIsoReadable = (isoStr: string | null | undefined, offsetSec = 0) => {
    if (!isoStr) return '---';
    try {
      const date = new Date(isoStr);
      if (isNaN(date.getTime())) return isoStr;
      return date.toLocaleString('ar-SA', {
        dateStyle: 'medium',
        timeStyle: 'medium',
        hour12: false,
      });
    } catch {
      return isoStr;
    }
  };

  // Compute live clock based on status offset
  const currentOffset = timeStatus ? timeStatus.offset_seconds : 0;
  const platformNowDate = new Date(Date.now() + currentOffset * 1000);
  const hostNowDate = new Date();

  return (
    <div className="space-y-6 animate-fade-in">
      {/* 1. Platform Time & Synchronization Architecture */}
      <SectionCard
        title="توقيت ومزامنة المنصة (Platform Time & Synchronization)"
        subtitle="إدارة مصدر التوقيت المعتمد لسجلات التحليل، الحوادث الأمنية، وتقارير التدقيق"
        badge={
          <span
            className={`text-xs px-2.5 py-1 rounded-lg border font-semibold flex items-center gap-1.5 ${
              timeCfg.source === 'ntp'
                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                : timeCfg.source === 'manual'
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
            }`}
          >
            {timeCfg.source === 'ntp' && <Radio className="w-3.5 h-3.5 animate-pulse" />}
            {timeCfg.source === 'manual' && <Calendar className="w-3.5 h-3.5" />}
            {timeCfg.source === 'host' && <Server className="w-3.5 h-3.5" />}
            المصدر النشط: {timeCfg.source === 'ntp' ? 'NTP شبكي' : timeCfg.source === 'manual' ? 'يدوي مخصص' : 'توقيت المضيف'}
          </span>
        }
      >
        {/* Live Clock Visual Header */}
        <div className="grid sm:grid-cols-3 gap-3 mb-6 p-4 rounded-2xl bg-white/[0.02] border border-white/5">
          <div className="space-y-1">
            <span className="text-[11px] font-bold text-slate-400 block flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              ساعة المنصة الحالية (Platform Time)
            </span>
            <div className="text-base sm:text-lg font-mono font-bold text-white tracking-wider">
              {platformNowDate.toLocaleTimeString('en-GB', { hour12: false })}
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              {platformNowDate.toISOString().split('T')[0]} (UTC)
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-[11px] font-bold text-slate-400 block flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              ساعة نظام المضيف (Host Clock)
            </span>
            <div className="text-base sm:text-lg font-mono font-bold text-slate-300 tracking-wider">
              {hostNowDate.toLocaleTimeString('en-GB', { hour12: false })}
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              {hostNowDate.toISOString().split('T')[0]} (UTC)
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-[11px] font-bold text-slate-400 block flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              فارق الانحراف (Offset)
            </span>
            <div
              className={`text-base sm:text-lg font-mono font-bold ${
                Math.abs(currentOffset) < 1
                  ? 'text-emerald-400'
                  : Math.abs(currentOffset) < 60
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {timeStatus?.offset_formatted || '+0.000s'}
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              {timeStatus?.source === 'host' ? 'مطابق لساعة النظام المضيف' : 'إزاحة محسوبة عن وقت المضيف'}
            </div>
          </div>
        </div>

        {/* Source Mode Selector (3 Cards) */}
        <div className="space-y-3">
          <label className="block text-xs font-bold text-slate-300">
            حدد مصدر توقيت المنصة المعتمد:
          </label>
          <div className="grid sm:grid-cols-3 gap-3">
            {/* Host Option */}
            <button
              type="button"
              onClick={() => onTimeChange?.({ source: 'host' })}
              className={`p-4 rounded-xl border text-right transition-all flex flex-col justify-between gap-3 ${
                timeCfg.source === 'host'
                  ? 'bg-emerald-500/10 border-emerald-500/40 shadow-sm shadow-emerald-500/10'
                  : 'bg-white/[0.02] border-white/10 hover:border-white/20'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-300">
                  <Server className="w-5 h-5" />
                </div>
                {timeCfg.source === 'host' && (
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 ring-4 ring-emerald-400/20" />
                )}
              </div>
              <div>
                <h4 className="text-xs font-bold text-white mb-1">ساعة نظام المضيف (Host)</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  الاعتماد مباشرة على ساعة نظام التشغيل المحلي للمنصة دون أي انحراف.
                </p>
              </div>
            </button>

            {/* Manual Option */}
            <button
              type="button"
              onClick={() => onTimeChange?.({ source: 'manual' })}
              className={`p-4 rounded-xl border text-right transition-all flex flex-col justify-between gap-3 ${
                timeCfg.source === 'manual'
                  ? 'bg-amber-500/10 border-amber-500/40 shadow-sm shadow-amber-500/10'
                  : 'bg-white/[0.02] border-white/10 hover:border-white/20'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <div className="p-2 rounded-lg bg-amber-500/20 text-amber-300">
                  <Calendar className="w-5 h-5" />
                </div>
                {timeCfg.source === 'manual' && (
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 ring-4 ring-amber-400/20" />
                )}
              </div>
              <div>
                <h4 className="text-xs font-bold text-white mb-1">الضبط اليدوي (Manual)</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  تحديد وقت وتاريخ مخصص مع استمرار تدفق الثواني طبيعياً (للتحقيقات الجنائية).
                </p>
              </div>
            </button>

            {/* NTP Option */}
            <button
              type="button"
              onClick={() => onTimeChange?.({ source: 'ntp' })}
              className={`p-4 rounded-xl border text-right transition-all flex flex-col justify-between gap-3 ${
                timeCfg.source === 'ntp'
                  ? 'bg-cyan-500/10 border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                  : 'bg-white/[0.02] border-white/10 hover:border-white/20'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-300">
                  <Radio className="w-5 h-5" />
                </div>
                {timeCfg.source === 'ntp' && (
                  <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-cyan-400/20" />
                )}
              </div>
              <div>
                <h4 className="text-xs font-bold text-white mb-1">مزامنة NTP شبكية (Network)</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  مزامنة آلية دورية عبر بروتوكول RFC 5905 مع خوادم التوقيت الموثوقة.
                </p>
              </div>
            </button>
          </div>
        </div>

        {/* Dynamic Controls based on chosen source */}
        {timeCfg.source === 'manual' && (
          <div className="mt-6 p-4 rounded-2xl bg-amber-500/5 border border-amber-500/20 space-y-4">
            <div className="flex items-start gap-3">
              <Info className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
              <div className="text-xs text-amber-200/90 leading-relaxed">
                <strong>ملاحظة هامة:</strong> الضبط اليدوي لا يجمد عقارب الساعة؛ بل يتم اعتماد هذا التاريخ كوقت مرجعي تستمر المنصة بالتقدم منه ثانية بثانية، مما يسمح بمحاكاة التحقيقات الجنائية بدقة تامة.
              </div>
            </div>

            <div className="grid sm:grid-cols-2 gap-4 items-end">
              <Field
                label="التاريخ والوقت اليدوي المطلوب تعيينه"
                hint="أدخل التاريخ والوقت بصيغة YYYY-MM-DDTHH:MM:SS"
              >
                <input
                  type="datetime-local"
                  step="1"
                  dir="ltr"
                  className={inputClass}
                  value={
                    timeCfg.manual_time
                      ? timeCfg.manual_time.replace('Z', '').slice(0, 19)
                      : ''
                  }
                  onChange={(e) => {
                    const val = e.target.value;
                    onTimeChange?.({
                      manual_time: val ? `${val}:00Z`.slice(0, 20) : '',
                    });
                  }}
                />
              </Field>

              <button
                type="button"
                onClick={() => {
                  const nowIso = new Date().toISOString().slice(0, 19);
                  onTimeChange?.({ manual_time: `${nowIso}Z` });
                }}
                className="px-4 py-2.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 text-xs font-semibold inline-flex items-center justify-center gap-2 transition-colors"
              >
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                تعبئة التوقيت الحالي لنظام المضيف
              </button>
            </div>
          </div>
        )}

        {timeCfg.source === 'ntp' && (
          <div className="mt-6 p-4 rounded-2xl bg-cyan-500/5 border border-cyan-500/20 space-y-5">
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-300 block">
                خوادم NTP الموصى بها مسبقاً:
              </label>
              <div className="flex flex-wrap gap-2">
                {DEFAULT_NTP_PRESETS.map((preset) => (
                  <button
                    key={preset.value}
                    type="button"
                    onClick={() => onTimeChange?.({ ntp_server: preset.value })}
                    className={`text-[11px] font-mono px-3 py-1.5 rounded-lg border transition-all ${
                      timeCfg.ntp_server === preset.value
                        ? 'bg-cyan-500/20 border-cyan-400 text-cyan-200 font-bold'
                        : 'bg-white/5 border-white/10 text-slate-300 hover:border-white/20'
                    }`}
                  >
                    {preset.value}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid sm:grid-cols-3 gap-4">
              <div className="sm:col-span-2">
                <Field
                  label="عنوان خادم NTP (Domain أو IP)"
                  hint="يمكنك استخدام خادم NTP داخلي للشبكة أو خادم عام (مثل pool.ntp.org)"
                >
                  <input
                    type="text"
                    dir="ltr"
                    className={inputClass}
                    value={timeCfg.ntp_server}
                    onChange={(e) => onTimeChange?.({ ntp_server: e.target.value })}
                    placeholder="pool.ntp.org"
                  />
                </Field>
              </div>

              <div>
                <Field label="منفذ UDP" hint="الافتراضي 123">
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    className={inputClass}
                    value={timeCfg.ntp_port}
                    onChange={(e) => onTimeChange?.({ ntp_port: Number(e.target.value) })}
                  />
                </Field>
              </div>
            </div>

            <div className="grid sm:grid-cols-2 gap-4 items-center">
              <Field
                label="فاصل المزامنة التلقائية (Sync Interval)"
                hint="المدة الزمنية بين كل محاولة مزامنة دورية في الخلفية"
              >
                <select
                  className={selectClass}
                  value={timeCfg.ntp_sync_interval_seconds}
                  onChange={(e) =>
                    onTimeChange?.({ ntp_sync_interval_seconds: Number(e.target.value) })
                  }
                >
                  <option value={300}>كل 5 دقائق (300 ثانية)</option>
                  <option value={900}>كل 15 دقيقة (900 ثانية)</option>
                  <option value={1800}>كل 30 دقيقة (1800 ثانية)</option>
                  <option value={3600}>كل ساعة (3600 ثانية) - القياسي</option>
                  <option value={21600}>كل 6 ساعات (21600 ثانية)</option>
                  <option value={86400}>كل 24 ساعة (86400 ثانية)</option>
                </select>
              </Field>

              <div className="pt-2">
                <Toggle
                  checked={timeCfg.auto_sync}
                  onChange={(auto_sync) => onTimeChange?.({ auto_sync })}
                  label="المزامنة الدورية في الخلفية"
                  description="تشغيل خيط مستقل يحدث انحراف التوقيت دورياً"
                />
              </div>
            </div>

            {/* Actions: Test Connection & Immediate Sync */}
            <div className="pt-3 border-t border-white/5 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  disabled={isTesting}
                  onClick={handleTestNtp}
                  className="px-4 py-2 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 text-xs font-semibold inline-flex items-center gap-2 transition-colors disabled:opacity-50"
                >
                  <Zap className={`w-3.5 h-3.5 text-amber-400 ${isTesting ? 'animate-spin' : ''}`} />
                  {isTesting ? 'جارٍ فحص الاتصال...' : 'اختبار الاتصال بالخادم'}
                </button>

                <button
                  type="button"
                  disabled={isSyncing}
                  onClick={handleImmediateSync}
                  className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold inline-flex items-center gap-2 transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                  {isSyncing ? 'جارٍ المزامنة الآن...' : 'مزامنة الوقت فوراً'}
                </button>
              </div>

              {timeStatus?.ntp?.last_sync_iso && (
                <span className="text-[11px] text-slate-400">
                  آخر مزامنة ناجحة:{' '}
                  <span className="text-slate-200 font-mono">
                    {formatIsoReadable(timeStatus.ntp.last_sync_iso)}
                  </span>
                  {timeStatus.ntp.delay_ms > 0 && ` (${timeStatus.ntp.delay_ms}ms)`}
                </span>
              )}
            </div>

            {/* Live Feedback banner */}
            {actionFeedback && (
              <div
                className={`p-3 rounded-xl border text-xs leading-relaxed flex items-start gap-2.5 ${
                  actionFeedback.ok
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-200'
                }`}
              >
                {actionFeedback.ok ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                )}
                <span>{actionFeedback.message}</span>
              </div>
            )}
          </div>
        )}
      </SectionCard>

      {/* 2. Language & Timezone */}
      <SectionCard
        title="اللغة والمنطقة الزمنية"
        subtitle="تحديد لغة واجهة المستخدم وتوقيت عرض السجلات والأحداث الجنائية"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="لغة واجهة المنصة"
            hint="اللغة العربية مدعومة بالكامل مع اتجاه RTL والمصطلحات التقنية"
          >
            <select
              className={selectClass}
              value={g.language}
              onChange={(e) => onChange({ language: e.target.value })}
            >
              <option value="ar">العربية (Arabic) - الافتراضية</option>
              <option value="en">English (الإنجليزية)</option>
            </select>
          </Field>

          <Field
            label="المنطقة الزمنية (Timezone)"
            hint="المعيار المعتمد في طوابع الوقت لتقارير SOC وسجلات التدقيق"
          >
            <input
              type="text"
              dir="ltr"
              className={inputClass}
              value={g.timezone}
              onChange={(e) => onChange({ timezone: e.target.value })}
              placeholder="Asia/Riyadh"
            />
          </Field>
        </div>
      </SectionCard>

      {/* 3. Navigation & Density */}
      <SectionCard
        title="سلوك العرض والتنقل الافتراضي"
        subtitle="تهيئة الصفحة الافتراضية وكثافة عرض الجداول عند تسجيل الدخول"
      >
        <div className="grid md:grid-cols-2 gap-5">
          <Field
            label="الصفحة الافتراضية بعد تسجيل الدخول"
            hint="الصفحة التي يتم توجيه المحلل إليها تلقائيًا بعد المصادقة الناجحة"
          >
            <select
              className={selectClass}
              value={g.default_app}
              onChange={(e) => onChange({ default_app: e.target.value })}
            >
              <option value="dashboard">لوحة التحكم الرئيسية (Dashboard)</option>
              <option value="flowscope">FlowScope (تحليل تدفقات الشبكة)</option>
              <option value="threatscope">ThreatScope (فحص سجلات XDR)</option>
              <option value="logscope">LogScope (تحقيق السجلات الجنائية)</option>
            </select>
          </Field>

          <Field
            label="عدد العناصر في كل صفحة (Pagination Limit)"
            hint="عدد السجلات الافتراضي في جداول الحوادث ومؤشرات الاختراق (10 - 200)"
          >
            <input
              type="number"
              min={10}
              max={200}
              className={inputClass}
              value={g.items_per_page}
              onChange={(e) => onChange({ items_per_page: Number(e.target.value) })}
            />
          </Field>
        </div>
      </SectionCard>

      {/* 4. Visual Toggles */}
      <SectionCard
        title="عناصر الواجهة التفاعلية"
        subtitle="التحكم في ظهور بطاقات الترحيب ومؤشرات الحالة العامة"
      >
        <div className="grid sm:grid-cols-2 gap-4">
          <Toggle
            checked={g.show_welcome}
            onChange={(show_welcome) => onChange({ show_welcome })}
            label="عرض شريط الترحيب والملخص التنفيذي"
            description="إظهار رسالة الترحيب والملخص السريع في الصفحة الرئيسية"
          />
          <Toggle
            checked={g.show_system_status}
            onChange={(show_system_status) => onChange({ show_system_status })}
            label="عرض شارة حالة المحركات في شريط التنقل"
            description="إظهار مؤشر اتصال المحركات التحليلية في شريط Navbar"
          />
        </div>
      </SectionCard>
    </div>
  );
}
