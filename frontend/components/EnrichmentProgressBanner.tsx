import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Database,
  Search,
  Globe,
  Radio,
  Layers,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { useTranslation } from '../lib/i18n';

interface ProviderStats {
  enabled?: boolean;
  queries?: number;
  cache_hits?: number;
  errors?: number;
  source_status?: string;
  verdict?: string;
}

interface EnrichmentData {
  status?: 'not_started' | 'running' | 'completed' | 'interrupted' | string;
  checked?: number;
  total?: number;
  cached?: number;
  new?: number;
  providers?: Record<string, ProviderStats>;
  results?: Record<string, any>;
}

interface Props {
  enrichment?: EnrichmentData;
  colorScheme?: 'emerald' | 'cyan' | 'rose';
  onRetry?: () => void;
}

export function EnrichmentProgressBanner({ enrichment, colorScheme = 'emerald', onRetry }: Props) {
  const { t } = useTranslation();

  if (!enrichment || enrichment.status === 'not_started') {
    return null;
  }

  // If completed with literally no indicators at all, don't show empty banner
  if (enrichment.status !== 'running' && !enrichment.total && !enrichment.checked) {
    return null;
  }

  const isRunning = enrichment.status === 'running';
  const isCompleted = enrichment.status === 'completed';
  const isInterrupted = enrichment.status === 'interrupted';

  const total = Number(enrichment.total) || 0;
  const checked = Number(enrichment.checked) || 0;
  const cachedCount = Number(enrichment.cached) || 0;
  const newCount = Number(enrichment.new) || (checked - cachedCount > 0 ? checked - cachedCount : 0);
  const percent = total > 0 ? Math.min(100, Math.round((checked / total) * 100)) : isCompleted ? 100 : 0;

  // Providers configuration & query counters
  const providers = enrichment.providers || {};
  const providerKeys = Object.keys(providers);

  // Styling color classes
  const colorMap = {
    emerald: {
      border: 'border-emerald-500/30',
      bg: 'from-emerald-950/30 via-dark-850 to-dark-850',
      badgeBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      bar: 'from-emerald-500 to-teal-400',
      icon: 'text-emerald-400',
    },
    cyan: {
      border: 'border-cyan-500/30',
      bg: 'from-cyan-950/30 via-dark-850 to-dark-850',
      badgeBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      bar: 'from-cyan-500 to-blue-400',
      icon: 'text-cyan-400',
    },
    rose: {
      border: 'border-rose-500/30',
      bg: 'from-rose-950/30 via-dark-850 to-dark-850',
      badgeBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      bar: 'from-rose-500 to-amber-400',
      icon: 'text-rose-400',
    },
  };
  const theme = colorMap[colorScheme] || colorMap.emerald;

  return (
    <div className={`glass-panel p-5 border ${theme.border} bg-gradient-to-r ${theme.bg} rounded-2xl shadow-xl transition-all`}>
      {/* Header row with status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-white/5 border border-white/10">
            {isRunning ? (
              <RefreshCw className={`w-5 h-5 ${theme.icon} animate-spin`} />
            ) : isCompleted ? (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white font-heading">
                {t('logscope.enrichment_panel_title') || 'لوحة استخبارات التهديدات وتقدم الفحص'}
              </h3>
              <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full border ${
                isRunning
                  ? 'bg-amber-500/15 text-amber-400 border-amber-500/30 animate-pulse'
                  : isCompleted
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                  : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
              }`}>
                {isRunning
                  ? (t('logscope.enrichment_running') || 'جارٍ الفحص...')
                  : isCompleted
                  ? (t('logscope.enrichment_completed') || 'مكتمل بنجاح')
                  : (t('logscope.enrichment_interrupted') || 'متوقف مؤقتًا')}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {total > 0
                ? `تم التحقق من ${checked} مؤشر أمني من إجمالي ${total} عبر منصات التهديدات العالمية`
                : 'يتم فحص وتحليل العناوين والمؤشرات الأمنية المكتشفة'}
            </p>
          </div>
        </div>

        {isInterrupted && onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 font-bold text-xs flex items-center gap-1.5 transition-all self-start sm:self-auto"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>إعادة المتابعة</span>
          </button>
        )}
      </div>

      {/* Progress Bar */}
      <div className="space-y-1.5 mb-4">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-300 flex items-center gap-1.5">
            <Zap className={`w-3.5 h-3.5 ${theme.icon}`} />
            <span>نسبة إنجاز الفحص:</span>
          </span>
          <span className="font-bold text-white text-sm">{percent}%</span>
        </div>
        <div className="h-2.5 rounded-full bg-dark-950/70 border border-white/5 overflow-hidden" dir="ltr">
          <div
            className={`h-full rounded-full bg-gradient-to-r ${theme.bar} transition-all duration-500 ease-out`}
            style={{ width: `${percent}%` }}
          />
        </div>
      </div>

      {/* Metrics Badges Breakdown (New vs Cached vs Total) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 pt-3 border-t border-white/10">
        {/* 1. New Scanned */}
        <div className="rounded-xl bg-black/20 border border-white/10 p-3 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Search className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-bold text-slate-400">
              {t('logscope.new_scanned_label') || 'مفحوص جديد (مباشر)'}
            </div>
            <div className="text-lg font-extrabold text-emerald-400 font-mono">
              {newCount}
            </div>
          </div>
        </div>

        {/* 2. Cached Scanned */}
        <div className="rounded-xl bg-black/20 border border-white/10 p-3 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-bold text-slate-400">
              {t('logscope.cached_scanned_label') || 'مفحوص سابقاً (Snapshot)'}
            </div>
            <div className="text-lg font-extrabold text-blue-400 font-mono">
              {cachedCount}
            </div>
          </div>
        </div>

        {/* 3. Total Targets */}
        <div className="rounded-xl bg-black/20 border border-white/10 p-3 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-bold text-slate-400">إجمالي المؤشرات</div>
            <div className="text-lg font-extrabold text-purple-400 font-mono">
              {total || checked}
            </div>
          </div>
        </div>

        {/* 4. Providers summary / active platforms */}
        <div className="rounded-xl bg-black/20 border border-white/10 p-3 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <Globe className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[11px] font-bold text-slate-400">منصات الاستخبارات</div>
            <div className="text-sm font-bold text-white font-mono">
              {providerKeys.length ? `${providerKeys.length} منصات نشطة` : 'VirusTotal / AbuseIPDB'}
            </div>
          </div>
        </div>
      </div>

      {/* Providers Status Pill List */}
      {providerKeys.length > 0 && (
        <div className="mt-3 pt-3 border-t border-white/5 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-bold text-slate-400 flex items-center gap-1">
            <Radio className="w-3.5 h-3.5 text-slate-400" />
            <span>حالة المنصات:</span>
          </span>
          {providerKeys.map((pKey) => {
            const p = providers[pKey] || {};
            const pName = pKey === 'virustotal' ? 'VirusTotal' : pKey === 'abuseipdb' ? 'AbuseIPDB' : pKey === 'shodan' ? 'Shodan InternetDB' : pKey === 'malwarebazaar' ? 'MalwareBazaar' : pKey.toUpperCase();
            const queries = p.queries || 0;
            const hits = p.cache_hits || 0;
            const isEnabled = p.enabled !== false;
            const isQuota = isEnabled && (p.source_status === 'quota_exceeded' || p.source_status === 'provider_deferred');
            
            return (
              <span
                key={pKey}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono border ${
                  !isEnabled
                    ? 'bg-slate-900/60 text-slate-400 border-slate-700/40 opacity-75'
                    : isQuota
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    : 'bg-white/5 text-slate-300 border-white/10'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${!isEnabled ? 'bg-slate-500' : isQuota ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
                <span className="font-bold text-white">{pName}</span>
                {isEnabled ? (
                  <span className="text-[10px] text-slate-400">
                    (استعلام: {queries} · ذاكرة: {hits})
                  </span>
                ) : (
                  <span className="text-[10px] text-slate-400 font-sans">
                    (غير مفعل — يحتاج مفتاح)
                  </span>
                )}
                {isQuota && <span className="text-[10px] text-amber-400 font-sans">تجاوز الحصة</span>}
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}
