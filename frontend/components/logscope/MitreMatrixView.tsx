'use client';

import React, { useState } from 'react';
import { Crosshair, ShieldAlert, ListFilter, Search, Layers } from 'lucide-react';

interface MitreMatrixViewProps {
  mitreMatrix: Array<{
    technique: string;
    tactic: string;
    count: number;
    threat_family?: string;
  }>;
  onFilterTechnique: (technique: string) => void;
}

export function MitreMatrixView({ mitreMatrix, onFilterTechnique }: MitreMatrixViewProps) {
  const [search, setSearch] = useState('');

  const filtered = mitreMatrix.filter((item) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      item.technique.toLowerCase().includes(q) ||
      item.tactic.toLowerCase().includes(q) ||
      (item.threat_family && item.threat_family.toLowerCase().includes(q))
    );
  });

  // Group by tactic
  const groupedByTactic: Record<string, typeof mitreMatrix> = {};
  for (const item of filtered) {
    const tac = item.tactic || 'General Attack Activity';
    if (!groupedByTactic[tac]) {
      groupedByTactic[tac] = [];
    }
    groupedByTactic[tac].push(item);
  }

  if (mitreMatrix.length === 0) {
    return (
      <div className="rounded-2xl border border-white/10 bg-dark-900/40 p-12 text-center space-y-3">
        <Crosshair className="w-8 h-8 text-slate-500 mx-auto" />
        <h3 className="text-base font-bold text-white">لم يتم رصد تقنيات MITRE مطابقة مباشرة</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          السجلات لا تحتوي على أنماط هجومية معروفة ضمن مصفوفة MITRE ATT&CK أو أنها أحداث نظام تشغيل روتينية.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-dark-900/50 p-4 rounded-2xl border border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400">
            <Crosshair className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-white">
              مصفوفة تقنيات وتكتيكات MITRE ATT&CK ({mitreMatrix.length} تقنية)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              تصنيف الأنشطة والهجمات المرصودة طبقاً للمعايير العالمية لمراحل الهجوم السيبراني
            </p>
          </div>
        </div>

        <div className="relative">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="بحث في التقنيات والتكتيكات..."
            className="bg-black/30 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 focus:outline-none w-64 pr-8"
          />
          <Search className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-2.5" />
        </div>
      </div>

      {/* Grid of Tactics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {Object.entries(groupedByTactic).map(([tactic, techniques]) => (
          <div
            key={tactic}
            className="rounded-2xl border border-white/10 bg-dark-900/60 p-5 space-y-4 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-3">
                <span className="text-xs font-bold text-emerald-400 tracking-wide">
                  تكتيك: {tactic}
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-white/10 text-slate-300">
                  {techniques.length}
                </span>
              </div>

              <div className="mt-3 space-y-2.5">
                {techniques.map((tech, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-black/30 border border-white/5 hover:border-emerald-500/30 transition-all space-y-2"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-mono text-[11px] font-bold">
                        {tech.technique}
                      </span>
                      <span className="text-xs font-bold text-slate-300 font-mono">
                        {tech.count.toLocaleString('en-US')}{' '}
                        <span className="text-[10px] text-slate-500 font-normal">حدث</span>
                      </span>
                    </div>

                    {tech.threat_family && (
                      <div className="text-[11px] text-purple-300 font-medium truncate">
                        {tech.threat_family}
                      </div>
                    )}

                    <div className="pt-1 flex justify-end">
                      <button
                        type="button"
                        onClick={() => onFilterTechnique(tech.technique)}
                        className="flex items-center gap-1 text-[11px] font-bold text-emerald-400 hover:text-emerald-300 transition-colors"
                      >
                        <ListFilter className="w-3 h-3" />
                        <span>تصفية الأحداث المرتبطة</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
