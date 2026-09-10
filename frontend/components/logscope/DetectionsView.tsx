'use client';

import React, { useState } from 'react';
import { Radio, ShieldAlert, ListFilter, Search, Layers, Activity } from 'lucide-react';

interface DetectionsViewProps {
  detections: Array<{
    detection_id: string;
    title_ar: string;
    severity: string;
    count: number;
    threat_family?: string;
    mitre_tactics?: string[];
    mitre_techniques?: string[];
  }>;
  patterns: Array<{
    pattern_name: string;
    events_count: number;
    critical_count?: number;
    high_count?: number;
    severity?: string;
  }>;
  onFilterDetection: (detectionId: string) => void;
  onFilterThreatFamily: (threatFamily: string) => void;
}

export function DetectionsView({
  detections,
  patterns,
  onFilterDetection,
  onFilterThreatFamily,
}: DetectionsViewProps) {
  const [search, setSearch] = useState('');

  const filteredDetections = detections.filter((d) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      d.detection_id.toLowerCase().includes(q) ||
      d.title_ar.toLowerCase().includes(q) ||
      (d.threat_family && d.threat_family.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Patterns Overview Cards */}
      {patterns && patterns.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-slate-300 font-bold text-xs">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span>الأنماط السلوكية المكتشفة في حركة السجلات:</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {patterns.map((pat, idx) => (
              <div
                key={idx}
                className="rounded-2xl border border-white/10 bg-dark-900/60 p-4 space-y-3 hover:border-emerald-500/30 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <h4 className="text-sm font-bold text-white leading-snug" dir="auto">
                      {pat.pattern_name}
                    </h4>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-white/10 text-slate-300">
                      {pat.events_count.toLocaleString('en-US')} حدث
                    </span>
                  </div>

                  <div className="flex items-center gap-3 mt-3 text-xs">
                    {pat.critical_count ? (
                      <span className="text-rose-400 font-bold">
                        {pat.critical_count} حرج
                      </span>
                    ) : null}
                    {pat.high_count ? (
                      <span className="text-amber-400 font-bold">
                        {pat.high_count} مرتفع
                      </span>
                    ) : null}
                  </div>
                </div>

                <div className="pt-2 border-t border-white/5 flex justify-end">
                  <button
                    type="button"
                    onClick={() => onFilterThreatFamily(pat.pattern_name)}
                    className="flex items-center gap-1 text-[11px] font-bold text-emerald-400 hover:text-emerald-300"
                  >
                    <ListFilter className="w-3 h-3" />
                    <span>تصفية أحداث هذا النمط</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detections Rules Matching Table */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 bg-dark-900/50 p-4 rounded-2xl border border-white/10">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/25 text-purple-400">
              <Radio className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-extrabold text-white">
                قواعد الكشف المطابقة ({detections.length})
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                تنبيهات أمنية محددة تم توليدها بواسطة كواشف النطاقات وقواعد الارتباط
              </p>
            </div>
          </div>

          <div className="relative">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="بحث في قواعد الكشف..."
              className="bg-black/30 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 focus:outline-none w-64 pr-8"
            />
            <Search className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-2.5" />
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-dark-900/40 overflow-hidden">
          <table className="w-full text-right text-xs">
            <thead>
              <tr className="border-b border-white/10 bg-white/5 text-slate-400 font-bold">
                <th className="p-3.5">معرف الكشف (Detection ID)</th>
                <th className="p-3.5">التوصيف الأمني المكتشف</th>
                <th className="p-3.5">المستوى</th>
                <th className="p-3.5">التكرار</th>
                <th className="p-3.5">التقنية المرتبطة</th>
                <th className="p-3.5 text-left">إجراء</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredDetections.map((det) => (
                <tr key={det.detection_id} className="hover:bg-white/5 transition-colors">
                  <td className="p-3.5 font-mono text-emerald-400 font-bold">
                    {det.detection_id}
                  </td>
                  <td className="p-3.5 font-medium text-white max-w-sm" dir="auto">
                    {det.title_ar}
                  </td>
                  <td className="p-3.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        det.severity === 'حرج'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : det.severity === 'مرتفع'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-slate-500/20 text-slate-300'
                      }`}
                    >
                      {det.severity}
                    </span>
                  </td>
                  <td className="p-3.5 font-mono font-bold text-slate-200">
                    {det.count.toLocaleString('en-US')}
                  </td>
                  <td className="p-3.5 font-mono text-slate-300">
                    {det.mitre_techniques?.[0] || '—'}
                  </td>
                  <td className="p-3.5 text-left">
                    <button
                      type="button"
                      onClick={() => onFilterDetection(det.detection_id)}
                      className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-emerald-400 text-xs font-bold transition-colors inline-flex items-center gap-1"
                    >
                      <ListFilter className="w-3 h-3" />
                      <span>تصفية</span>
                    </button>
                  </td>
                </tr>
              ))}

              {filteredDetections.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-400 text-xs">
                    لا توجد كشفات تطابق معايير البحث.
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
