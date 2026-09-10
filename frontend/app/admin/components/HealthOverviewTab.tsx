'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { Activity, ArrowUpRight, CheckCircle2, Server, Database, ShieldCheck, RefreshCw, Cpu, HardDrive, AlertTriangle } from 'lucide-react';
import { getPlatformDetailedHealth } from '../../../lib/api';
import { PlatformHealthResponse } from '../../../lib/types';

export function HealthOverviewTab() {
  const [health, setHealth] = useState<PlatformHealthResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchHealth = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getPlatformDetailedHealth();
      setHealth(data);
    } catch (err) {
      console.error('Failed to load health:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  const metrics = health?.system_metrics;
  const components = health?.components || [];
  const healthyCount = components.filter((c) => c.status === 'healthy').length;
  const degradedCount = components.filter((c) => c.status === 'degraded').length;
  const failedCount = components.filter((c) => c.status === 'unhealthy').length;

  return (
    <div className="space-y-6">
      {/* Header Panel */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 bg-gradient-to-r from-emerald-900/10 via-dark-900 to-dark-900">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
              <Activity className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>صحة المنصة والمراقبة الحيوية (Platform Health & Telemetry)</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  10 مكونات نشطة
                  {components.length ? `${healthyCount}/${components.length} مكونات سليمة` : 'جاري الفحص...'}
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                متابعة لحظية لحالة الخوادم، زمن الاستجابة (Latency)، مسارات الاتصال، استهلاك الذاكرة، وسلامة قاعدة البيانات وسلسلة التدقيق.
                متابعة لحظية لحالة الخوادم، زمن الاستجابة (Latency)، مقاييس الموارد الحية (CPU/RAM/Disk)، وسلامة قواعد البيانات وسلسلة التدقيق.
              </p>
            </div>
          </div>

          <Link
            href="/operations/health"
            className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all self-start sm:self-auto"
          >
            <span>فتح لوحة صحة المنصة التفصيلية</span>
            <ArrowUpRight className="w-4 h-4" />
          </Link>
          <div className="flex items-center gap-3 self-start sm:self-auto">
            <button
              onClick={fetchHealth}
              disabled={loading}
              className="p-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-colors"
              title="تحديث فوري"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <Link
              href="/operations/health"
              className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
            >
              <span>فتح لوحة المراقبة التفصيلية</span>
              <ArrowUpRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </div>

      {/* Real-time Hardware Telemetry Meters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
        {/* CPU Gauge */}
        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-200">
              <Cpu className="w-4 h-4 text-emerald-400" />
              استهلاك المعالج (CPU)
            </span>
            <span className="font-mono text-emerald-400 font-bold">
              {metrics ? `${metrics.cpu_percent}%` : '—'}
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-white/5 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                (metrics?.cpu_percent || 0) > 80
                  ? 'bg-rose-500'
                  : (metrics?.cpu_percent || 0) > 50
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, metrics?.cpu_percent || 0)}%` }}
            />
          </div>
          <div className="text-[11px] text-slate-500">
            نشط عبر {metrics?.active_threads || 1} خيوط معالجة (Threads)
          </div>
        </div>

        {/* RAM Gauge */}
        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-200">
              <Activity className="w-4 h-4 text-blue-400" />
              ذاكرة النظام (RAM)
            </span>
            <span className="font-mono text-blue-400 font-bold">
              {metrics ? `${metrics.ram_percent}%` : '—'}
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-white/5 overflow-hidden">
            <div
              className="h-full bg-blue-500 transition-all duration-500"
              style={{ width: `${Math.min(100, metrics?.ram_percent || 0)}%` }}
            />
          </div>
          <div className="text-[11px] text-slate-500">
            {metrics?.ram_used_gb || 0} GB من {metrics?.ram_total_gb || 0} GB
          </div>
        </div>

        {/* Disk Gauge */}
        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-200">
              <HardDrive className="w-4 h-4 text-purple-400" />
              سعة التخزين والقرص
            </span>
            <span className="font-mono text-purple-400 font-bold">
              {metrics ? `${metrics.disk_percent}%` : '—'}
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-white/5 overflow-hidden">
            <div
              className="h-full bg-purple-500 transition-all duration-500"
              style={{ width: `${Math.min(100, metrics?.disk_percent || 0)}%` }}
            />
          </div>
          <div className="text-[11px] text-slate-500">
            المتاح: {metrics?.disk_free_gb || 0} GB من أصل {metrics?.disk_total_gb || 0} GB
          </div>
        </div>

        {/* Process & Uptime */}
        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-3">
          <div className="flex items-center justify-between text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-200">
              <Server className="w-4 h-4 text-amber-400" />
              ذاكرة الخادم والتشغيل
            </span>
            <span className="font-mono text-amber-400 font-bold">
              {metrics?.process_memory_mb || 0} MB
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-2">
            وقت التشغيل المستمر (Uptime):{' '}
            <span className="font-bold text-white font-mono">
              {metrics ? `${Math.floor(metrics.uptime_seconds / 60)} دقيقة` : '—'}
            </span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {metrics?.timestamp ? new Date(metrics.timestamp).toLocaleTimeString() : ''}
          </div>
        </div>
      </div>

      {/* Component Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-400 font-bold">
              <Server className="w-4 h-4" />
              <span>الخوادم والبوابات (Gateway & Backend)</span>
            </div>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            الـ API Gateway يعمل على المنفذ 8081 ومحرك بايثون يعمل على المنفذ 8082 في حلقة محلية آمنة (Loopback Only).
          </p>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-blue-400 font-bold">
              <Database className="w-4 h-4" />
              <span>قواعد البيانات ومستودع السجلات</span>
            </div>
            <span className="w-2 h-2 rounded-full bg-blue-400" />
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            قواعد SQLite تعمل بوضع WAL فائق السرعة مع إدارة مستقلة للاتصالات والفهارس المتقدمة.
            قواعد SQLite تعمل بوضع WAL فائق السرعة مع إدارة مستقلة للاتصالات والفهارس المتقدمة وسلسلة تدقيق تشفيرية.
          </p>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-white/10 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-purple-400 font-bold">
              <ShieldCheck className="w-4 h-4" />
              <span>المحركات الأمنية الثلاثة</span>
            </div>
            <span className="w-2 h-2 rounded-full bg-purple-400" />
          </div>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            جاهزية كاملة لوحدات FlowScope و ThreatScope و LogScope مع تفعيل كواشف Sigma واستخبارات التهديدات.
            جاهزية كاملة لوحدات FlowScope و ThreatScope و LogScope مع كواشف التهديدات وتحليلات الرسوم البيانية.
          </p>
        </div>
      </div>
    </div>
  );
}

