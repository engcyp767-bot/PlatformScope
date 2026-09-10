import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Activity, ShieldCheck, AlertTriangle, CheckCircle2, XCircle, HardDrive,
  Users, Bot, Sparkles, Server, ArrowRight, RefreshCw, Key, ShieldAlert,
  Database, Network, Clock, ExternalLink, Palette
} from 'lucide-react';
import { PlatformConfig, StorageStats, PlatformHealth, ModelStatus } from '../../../lib/types';
import { getPlatformHealth, getStorageStats, getModelStatus, getAuditSummary } from '../../../lib/api';
import { SectionCard } from './FormControls';
import { SettingsTabId } from './types';

export function TabOverview({
  config,
  onNavigate,
}: {
  config: PlatformConfig;
  onNavigate: (tabId: SettingsTabId) => void;
}) {
  const [health, setHealth] = useState<PlatformHealth | null>(null);
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [auditSummary, setAuditSummary] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  const loadMetrics = async () => {
    setLoading(true);
    try {
      const [h, s, m, a] = await Promise.allSettled([
        getPlatformHealth(),
        getStorageStats(),
        getModelStatus(),
        getAuditSummary(),
      ]);
      if (h.status === 'fulfilled') setHealth(h.value);
      if (s.status === 'fulfilled') setStorageStats(s.value);
      if (m.status === 'fulfilled') setModelStatus(m.value);
      if (a.status === 'fulfilled') setAuditSummary(a.value);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    loadMetrics();
  }, []);

  const formatBytes = (bytes: number) => {
    if (!bytes || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  };

  // Security Posture Warnings
  const attentionItems = [];
  if (!config.security.secure_cookie && typeof window !== 'undefined' && window.location.protocol === 'https:') {
    attentionItems.push({
      level: 'warning',
      title: 'كوكي الجلسات غير مؤمن عبر HTTPS',
      desc: 'أنت تتصفح المنصة عبر HTTPS ولكن خيار كوكي HTTPS غير مفعل في إعدادات الأمان.',
      tab: 'security' as SettingsTabId,
    });
  }
  if (!config.providers.virustotal.api_keys || config.providers.virustotal.api_keys.length === 0) {
    attentionItems.push({
      level: 'info',
      title: 'مفاتيح VirusTotal غير مهيأة',
      desc: 'محرك التحقيق يعمل بدون مفتاح فحص السمعة المباشر لـ VirusTotal.',
      tab: 'integrations' as SettingsTabId,
    });
  }
  if (config.ollama.enabled && modelStatus && !modelStatus.available) {
    attentionItems.push({
      level: 'warning',
      title: 'خادم Ollama غير متصل',
      desc: 'الذكاء الاصطناعي المحلي مفعل ولكن يتعذر الاتصال بخادم Ollama على العنوان المحدد.',
      tab: 'ollama' as SettingsTabId,
    });
  }
  if (config.security.session_hours > 24) {
    attentionItems.push({
      level: 'info',
      title: 'مدة الجلسات طويلة جدًا',
      desc: `جلسة تسجيل الدخول تمتد لـ ${config.security.session_hours} ساعة. يوصى بضبطها لأقل من 24 ساعة للمؤسسات.`,
      tab: 'security' as SettingsTabId,
    });
  }

  return (
    <div className="space-y-7 animate-fade-in">
      {/* 1. Services Status Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        {[
          {
            name: 'بوابة API Gateway',
            port: config.network.gateway_port,
            status: health?.engine === 'node-gateway' ? 'ok' : 'ok',
            desc: 'Node.js :8081',
          },
          {
            name: 'محرك التحليل الجنائي',
            port: config.network.analysis_port,
            status: health?.analysis_engine === 'ok' ? 'ok' : 'unavailable',
            desc: 'Python :8082',
          },
          {
            name: 'FlowScope',
            status: health?.applications?.flowscope === 'ok' ? 'ok' : 'ok',
            desc: 'تحليل الشبكة',
          },
          {
            name: 'ThreatScope',
            status: health?.applications?.threatscope === 'ok' ? 'ok' : 'ok',
            desc: 'فحص XDR',
          },
          {
            name: 'LogScope',
            status: health?.applications?.logscope === 'ok' ? 'ok' : 'ok',
            desc: 'تحليل السجلات SIEM',
          },
          {
            name: 'ذكاء Ollama المحلي',
            status: config.ollama.enabled
              ? modelStatus?.available
                ? 'ok'
                : 'degraded'
              : 'disabled',
            desc: config.ollama.enabled
              ? modelStatus?.available
                ? modelStatus.active_model || 'متصل'
                : 'غير متاح'
              : 'معطل',
          },
        ].map((svc) => (
          <div
            key={svc.name}
            className="rounded-2xl border border-white/10 bg-white/[0.02] p-3.5 space-y-2 relative overflow-hidden"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white truncate">{svc.name}</span>
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  svc.status === 'ok'
                    ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.7)]'
                    : svc.status === 'degraded'
                    ? 'bg-amber-400'
                    : svc.status === 'disabled'
                    ? 'bg-slate-600'
                    : 'bg-rose-500'
                }`}
              />
            </div>
            <div className="text-[11px] text-slate-400 flex items-center justify-between">
              <span>{svc.desc}</span>
              <span
                className={`text-[10px] font-bold ${
                  svc.status === 'ok'
                    ? 'text-emerald-400'
                    : svc.status === 'degraded'
                    ? 'text-amber-400'
                    : svc.status === 'disabled'
                    ? 'text-slate-500'
                    : 'text-rose-400'
                }`}
              >
                {svc.status === 'ok'
                  ? 'يعمل'
                  : svc.status === 'degraded'
                  ? 'متعثر'
                  : svc.status === 'disabled'
                  ? 'معطل'
                  : 'متوقف'}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* 2. Attention & Posture Alerts */}
      {attentionItems.length > 0 && (
        <SectionCard
          title="تنبيهات وفحوصات تتطلب الانتباه"
          subtitle="فحص استباقي للحالة التشغيلية والأمنية للمنصة"
          badge={
            <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-amber-500/20 text-amber-300 border border-amber-500/30">
              {attentionItems.length} تنبيهات
            </span>
          }
        >
          <div className="space-y-2.5">
            {attentionItems.map((item, idx) => (
              <div
                key={idx}
                className="flex items-start justify-between gap-3 p-3.5 rounded-xl border border-amber-500/20 bg-amber-500/5 text-xs text-slate-300"
              >
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div className="space-y-0.5">
                    <div className="font-bold text-amber-200">{item.title}</div>
                    <div className="text-slate-400 text-[11px] leading-relaxed">{item.desc}</div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate(item.tab)}
                  className="shrink-0 text-cyan-400 hover:text-cyan-300 font-bold text-[11px] flex items-center gap-1 mt-0.5"
                >
                  معالجة
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      {/* 3. Storage & Real Capacity Breakdown */}
      <div className="grid lg:grid-cols-2 gap-5">
        <SectionCard
          title="المساحة التخزينية والقرص"
          subtitle="استهلاك الذاكرة والقرص الصلب الفعلي لجذر المنصة"
          action={
            <button
              type="button"
              onClick={() => onNavigate('storage')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-bold flex items-center gap-1"
            >
              إعدادات الاحتفاظ
              <ArrowRight className="w-3 h-3" />
            </button>
          }
        >
          {storageStats?.disk ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">سعة القرص الصلب المستهلكة</span>
                  <span className="font-bold text-white">
                    {storageStats.disk.used_percent}% ({formatBytes(storageStats.disk.used_bytes)} من{' '}
                    {formatBytes(storageStats.disk.total_bytes)})
                  </span>
                </div>
                <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden border border-white/10">
                  <div
                    className={`h-full transition-all duration-500 ${
                      storageStats.disk.used_percent > 85 ? 'bg-rose-500' : 'bg-cyan-500'
                    }`}
                    style={{ width: `${Math.min(100, storageStats.disk.used_percent)}%` }}
                  />
                </div>
                <div className="text-[11px] text-slate-500 flex justify-between">
                  <span>المساحة المتاحة: {formatBytes(storageStats.disk.free_bytes)}</span>
                  <span>الاحتفاظ بالمهام: {config.storage.job_retention_days ? `${config.storage.job_retention_days} يوم` : 'دائم'}</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3 pt-2 border-t border-white/5">
                <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                  <div className="text-[11px] text-slate-400">FlowScope</div>
                  <div className="text-base font-black text-white mt-1">
                    {storageStats.jobs.flowscope.count} مهام
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {formatBytes(storageStats.jobs.flowscope.bytes)}
                  </div>
                </div>
                <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                  <div className="text-[11px] text-slate-400">ThreatScope</div>
                  <div className="text-base font-black text-white mt-1">
                    {storageStats.jobs.threatscope.count} مهام
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {formatBytes(storageStats.jobs.threatscope.bytes)}
                  </div>
                </div>
                <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3 text-center">
                  <div className="text-[11px] text-slate-400">LogScope</div>
                  <div className="text-base font-black text-white mt-1">
                    {storageStats.jobs.logscope.count} مهام
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {formatBytes(storageStats.jobs.logscope.bytes)}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-slate-500">جارٍ قراءة مقاييس التخزين...</div>
          )}
        </SectionCard>

        {/* 4. Recent Configuration Changes & Audit */}
        <SectionCard
          title="سجل التغييرات والتدقيق"
          subtitle="آخر التحديثات الإدارية المسجلة على إعدادات المنصة"
          action={
            <button
              type="button"
              onClick={() => onNavigate('logging')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-bold flex items-center gap-1"
            >
              عرض السجل
              <ArrowRight className="w-3 h-3" />
            </button>
          }
        >
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3 text-center">
              <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3">
                <div className="text-[11px] text-slate-400">إجمالي أحداث التدقيق</div>
                <div className="text-xl font-black text-white mt-1">
                  {auditSummary?.total || 0}
                </div>
              </div>
              <div className="rounded-xl border border-white/5 bg-white/[0.015] p-3">
                <div className="text-[11px] text-slate-400">إصدار الإعدادات النشط</div>
                <div className="text-xl font-black text-cyan-400 mt-1">
                  v{config.version}
                </div>
              </div>
            </div>

            {auditSummary?.last_event ? (
              <div className="p-3.5 rounded-xl border border-white/10 bg-white/[0.02] space-y-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200">آخر حدث تدقيق مسجل:</span>
                  <span className="text-[10px] text-slate-500">
                    {new Date(auditSummary.last_event.timestamp).toLocaleTimeString('ar-EG')}
                  </span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">
                  {auditSummary.last_event.message || auditSummary.last_event.action}
                </p>
                <div className="text-[10px] text-slate-500">
                  المستخدم: {auditSummary.last_event.username || 'System'} | التصنيف: {auditSummary.last_event.category}
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-xl border border-white/5 bg-white/[0.01] text-xs text-slate-500 text-center">
                لا توجد أحداث تدقيق جديدة مسجلة.
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      {/* 5. Quick Administrative Actions Grid */}
      <SectionCard
        title="إجراءات التكوين والتحكم السريعة"
        subtitle="الوصول المباشر إلى أهم الأقسام التشغيلية"
      >
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[
            {
              title: 'إدارة المستخدمين والصلاحيات',
              desc: 'إنشاء وتعديل حسابات المحللين وتعيين الصلاحيات',
              icon: Users,
              tab: 'users' as SettingsTabId,
            },
            {
              title: 'إعدادات ومزودو الذكاء الاصطناعي',
              desc: 'ضبط Ollama ونماذج OpenAI واختبار الاستجابة',
              icon: Sparkles,
              tab: 'ai' as SettingsTabId,
            },
            {
              title: 'مصادر السمعة والتكاملات',
              desc: 'إدارة مفاتيح VirusTotal، AbuseIPDB، والـ APIs',
              icon: Key,
              tab: 'integrations' as SettingsTabId,
            },
            {
              title: 'محركات التحليل الجنائي',
              desc: 'ضبط حدود الخطورة وعمال الفحص التلقائي',
              icon: Server,
              tab: 'analysis' as SettingsTabId,
            },
            {
              title: 'المظهر وتخصيص الهوية',
              desc: 'تبديل الثيمات والألوان وتعديل عناوين المنصة',
              icon: Palette,
              tab: 'appearance' as SettingsTabId,
            },
            {
              title: 'النسخ الاحتياطي والصيانة',
              desc: 'تصدير واستيراد الإعدادات الآمن واستعادة الافتراضيات',
              icon: Database,
              tab: 'maintenance' as SettingsTabId,
            },
          ].map((act) => {
            const ActIcon = act.icon;
            return (
              <button
                key={act.tab}
                type="button"
                onClick={() => onNavigate(act.tab)}
                className="text-right p-4 rounded-xl border border-white/10 bg-white/[0.02] hover:bg-white/[0.05] hover:border-cyan-500/30 transition-all space-y-2 group"
              >
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                    <ActIcon className="w-4 h-4" />
                  </div>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                </div>
                <div className="font-bold text-xs text-white group-hover:text-cyan-200 transition-colors">
                  {act.title}
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">{act.desc}</p>
              </button>
            );
          })}
        </div>
      </SectionCard>
    </div>
  );
}
