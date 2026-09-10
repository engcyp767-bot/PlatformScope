'use client';

import React from 'react';
import { Network, ArrowRight, ShieldCheck, ShieldAlert, Activity, Target } from 'lucide-react';

interface NetworkFlowViewProps {
  ips?: Array<{
    ip: string;
    count: number;
    critical: number;
    high: number;
    destinations?: string[];
    ports?: string[];
  }>;
  onFilterEntity: (type: 'user' | 'ip' | 'device', value: string) => void;
}

export function NetworkFlowView({ ips = [], onFilterEntity }: NetworkFlowViewProps) {
  if (!ips.length) {
    return (
      <div className="rounded-2xl border border-white/10 bg-dark-900/40 p-12 text-center space-y-3">
        <Network className="w-8 h-8 text-slate-500 mx-auto" />
        <h3 className="text-base font-bold text-white">لا توجد تدفقات شبكية مسجلة</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          السجلات لا تتضمن بيانات عناوين IP صريحة أو أن الحقول مصدرية فقط.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-dark-900/50 p-4 rounded-2xl border border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/25 text-cyan-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-white">
              مسارات واتصالات الشبكة (Network Flows)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              رسم تخطيطي للمسارات بين عناوين المصدر والوجهات والمنافذ المرصودة
            </p>
          </div>
        </div>
      </div>

      {/* Flow Cards */}
      <div className="grid gap-3">
        {ips.map((item, idx) => (
          <div
            key={idx}
            className="p-4 rounded-2xl border border-white/10 bg-dark-900/60 space-y-3 hover:border-cyan-500/30 transition-all"
          >
            <div className="flex flex-wrap items-center justify-between gap-4">
              {/* Source IP */}
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400">
                  <Target className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[10px] text-slate-400 font-bold">عنوان المصدر (Source IP)</div>
                  <button
                    type="button"
                    onClick={() => onFilterEntity('ip', item.ip)}
                    className="text-sm font-bold font-mono text-white hover:text-cyan-300 transition-colors"
                  >
                    {item.ip}
                  </button>
                </div>
              </div>

              {/* Arrow */}
              <div className="hidden sm:flex items-center gap-2 text-slate-500 font-mono text-xs">
                <span>{item.count.toLocaleString('en-US')} حدث</span>
                <ArrowRight className="w-4 h-4 text-emerald-500" />
              </div>

              {/* Destinations */}
              <div className="space-y-1">
                <div className="text-[10px] text-slate-400 font-bold">الوجهات المتصل بها:</div>
                <div className="flex flex-wrap gap-1.5">
                  {item.destinations && item.destinations.length > 0 ? (
                    item.destinations.map((d, dIdx) => (
                      <button
                        key={dIdx}
                        type="button"
                        onClick={() => onFilterEntity('ip', d)}
                        className="px-2 py-0.5 rounded bg-black/40 border border-white/10 text-[11px] font-mono text-amber-300 hover:border-amber-500/30"
                      >
                        {d}
                      </button>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500">غير محددة صراحة</span>
                  )}
                </div>
              </div>

              {/* Ports */}
              {item.ports && item.ports.length > 0 && (
                <div className="space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">المنافذ:</div>
                  <div className="flex flex-wrap gap-1">
                    {item.ports.map((p, pIdx) => (
                      <span
                        key={pIdx}
                        className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] font-mono text-slate-300"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Badges */}
              <div className="flex items-center gap-2">
                {item.critical > 0 && (
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-bold font-mono">
                    {item.critical} حرج
                  </span>
                )}
                {item.high > 0 && (
                  <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-bold font-mono">
                    {item.high} مرتفع
                  </span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
