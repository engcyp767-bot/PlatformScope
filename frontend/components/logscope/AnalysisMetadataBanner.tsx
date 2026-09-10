'use client';

import React, { useState } from 'react';
import { ShieldCheck, Layers, FileCode2, ChevronDown, ChevronUp, Sparkles, CheckCircle2 } from 'lucide-react';

interface AnalysisMetadataBannerProps {
  metadata?: {
    detected_source?: string;
    detected_source_label?: string;
    source_confidence?: number;
    source_evidence?: string[];
    analysis_mode?: 'full' | 'partial' | string;
    recognized_fields?: string[];
    source_headers?: string[];
    filename?: string;
    row_count?: number;
    analyzed_at?: string;
  };
}

export function AnalysisMetadataBanner({ metadata }: AnalysisMetadataBannerProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  if (!metadata || !metadata.detected_source) {
    return null;
  }

  const confidencePercent = metadata.source_confidence
    ? Math.round(metadata.source_confidence * 100)
    : 100;

  const isFullMode = metadata.analysis_mode === 'full';
  const recognizedCount = metadata.recognized_fields?.length || 0;
  const totalHeadersCount = metadata.source_headers?.length || recognizedCount;

  return (
    <div className="rounded-2xl border border-emerald-500/20 bg-gradient-to-r from-emerald-950/30 via-dark-900/60 to-dark-900/40 p-4 transition-all shadow-lg backdrop-blur-sm">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Source Identification & Confidence */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-slate-400 font-medium">المصدر المكتشف:</span>
              <span className="text-sm font-bold text-white">
                {metadata.detected_source_label || metadata.detected_source}
              </span>
              <span className="px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono">
                {metadata.detected_source}
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
              <span>نسبة ثقة التعرف:</span>
              <span className="font-bold text-emerald-400 font-mono">{confidencePercent}%</span>
              <span className="text-slate-600">·</span>
              <span>نمط التحليل:</span>
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                isFullMode 
                  ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20' 
                  : 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
              }`}>
                {isFullMode ? 'تحليل كامل (Full Mode)' : 'تحليل متدرج (Partial Mode)'}
              </span>
            </div>
          </div>
        </div>

        {/* Quick Stats & Expand Button */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-black/30 border border-white/5 text-xs text-slate-300">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            <span>الحقول المطبعة:</span>
            <span className="font-bold text-white font-mono">{recognizedCount} / {totalHeadersCount}</span>
          </div>

          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-slate-200 transition-colors"
          >
            <span>{isExpanded ? 'إخفاء أدلة المصدر' : 'عرض أدلة وتفاصيل المصدر'}</span>
            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="mt-4 pt-4 border-t border-white/10 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs animate-in fade-in duration-200">
          {/* Audit Evidence */}
          <div className="space-y-2 bg-black/25 p-3.5 rounded-xl border border-white/5">
            <div className="flex items-center gap-1.5 text-emerald-300 font-bold">
              <Sparkles className="w-3.5 h-3.5" />
              <span>أدلة الكشف الجنائي للمصدر (Audit Evidence):</span>
            </div>
            {metadata.source_evidence && metadata.source_evidence.length > 0 ? (
              <ul className="space-y-1 text-slate-300">
                {metadata.source_evidence.map((ev, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{ev}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-slate-400">تم التعرف عبر مطابقة بصمات الحقول الموحدة وقيم السجلات.</p>
            )}
          </div>

          {/* Recognized Fields */}
          <div className="space-y-2 bg-black/25 p-3.5 rounded-xl border border-white/5">
            <div className="flex items-center gap-1.5 text-cyan-300 font-bold">
              <FileCode2 className="w-3.5 h-3.5" />
              <span>الحقول القياسية المعترف بها ({recognizedCount}):</span>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto pr-1">
              {metadata.recognized_fields?.map((field, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded-md bg-white/5 border border-white/10 text-[11px] font-mono text-slate-200"
                >
                  {field}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
