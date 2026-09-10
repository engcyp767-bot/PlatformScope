'use client';

import React, { useState } from 'react';
import { X, Search, CheckCircle2, AlertOctagon, ShieldAlert, Copy, ExternalLink, Loader2 } from 'lucide-react';
import { lookupIOCs } from '../../lib/api';
import { IOCItem, IOCLookupResult } from '../../lib/types';

interface QuickLookupModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectIOC?: (ioc: IOCItem) => void;
}

export function QuickLookupModal({ isOpen, onClose, onSelectIOC }: QuickLookupModalProps) {
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<IOCLookupResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const raw = inputText.trim();
    if (!raw) return;

    // Split by newlines, commas, or spaces
    const values = raw
      .split(/[\r\n,;\s]+/)
      .map((v) => v.trim())
      .filter((v) => v.length > 0);

    if (values.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const res = await lookupIOCs(values);
      setResults(res.results || []);
    } catch (err: any) {
      setError(err.message || 'فشل في استعلام قاعدة المؤشرات.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const totalHits = results ? results.reduce((acc, r) => acc + (r.matched ? 1 : 0), 0) : 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div
        className="relative w-full max-w-3xl max-h-[90vh] flex flex-col rounded-2xl bg-dark-900/95 border border-white/10 shadow-2xl overflow-hidden"
        dir="rtl"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Search className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide">الفحص السريع الفوري لمؤشرات التهديد</h2>
              <p className="text-xs text-slate-400">مطابقة لحظية O(1) في الذاكرة لعناوين IP، النطاقات، الروابط والتجزئات</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 flex-1 overflow-y-auto space-y-5">
          <form onSubmit={handleLookup} className="space-y-3">
            <label className="block text-xs font-semibold text-slate-300">
              أدخل المؤشرات (مؤشر في كل سطر أو مفصولة بفواصل):
            </label>
            <div className="relative">
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="مثال:&#10;198.51.100.44&#10;cdn-update-auth-telemetry.com&#10;7b8f9e2d1c3a4b5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e"
                rows={4}
                dir="ltr"
                className="w-full px-4 py-3 rounded-xl bg-black/40 border border-white/15 text-sm text-white font-mono placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/20 transition-all resize-none"
              />
            </div>
            <div className="flex items-center justify-between pt-1">
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setInputText(
                      '198.51.100.44\ncdn-update-auth-telemetry.com\n8.8.8.8\n7b8f9e2d1c3a4b5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e'
                    )
                  }
                  className="text-[11px] text-emerald-400 hover:text-emerald-300 underline"
                >
                  تجربة عينة اختبار حية
                </button>
                <span className="text-slate-600">|</span>
                <button
                  type="button"
                  onClick={() => {
                    setInputText('');
                    setResults(null);
                  }}
                  className="text-[11px] text-slate-400 hover:text-slate-200"
                >
                  مسح الحقل
                </button>
              </div>
              <button
                type="submit"
                disabled={loading || !inputText.trim()}
                className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                <span>فحص المؤشرات الآن</span>
              </button>
            </div>
          </form>

          {error && (
            <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2">
              <AlertOctagon className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {results !== null && (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between text-xs text-slate-300">
                <span className="font-semibold">نتائج الفحص ({results.length} مدخل):</span>
                <span className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded-md bg-red-500/20 text-red-400 font-mono font-bold">
                    {totalHits} تطابق خبيث
                  </span>
                  <span className="px-2 py-0.5 rounded-md bg-emerald-500/20 text-emerald-400 font-mono">
                    {results.length - totalHits} سليم / غير مسجل
                  </span>
                </span>
              </div>

              <div className="space-y-2.5">
                {results.map((res, idx) => (
                  <div
                    key={idx}
                    className={`p-3.5 rounded-xl border transition-all ${
                      res.matched
                        ? 'bg-red-500/[0.07] border-red-500/30 hover:border-red-500/50'
                        : 'bg-white/[0.02] border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2.5 min-w-0">
                        {res.matched ? (
                          <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
                        ) : (
                          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                        )}
                        <span className="font-mono text-sm font-semibold text-white truncate" dir="ltr">
                          {res.query}
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(res.query)}
                          className="text-slate-400 hover:text-white p-1 rounded transition-colors"
                          title="نسخ القيمة"
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                        {copiedText === res.query && (
                          <span className="text-[10px] text-emerald-400 font-sans">تم النسخ!</span>
                        )}
                      </div>

                      <div>
                        {res.matched ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-red-500/20 text-red-400 text-xs font-semibold">
                            تهديد مسجل ({res.matches.length})
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 text-xs">
                            سليم / غير مرصود
                          </span>
                        )}
                      </div>
                    </div>

                    {res.matched && res.matches && res.matches.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-red-500/20 space-y-2">
                        {res.matches.map((m) => (
                          <div
                            key={m.id}
                            className="flex flex-wrap items-center justify-between gap-2 p-2 rounded-lg bg-black/40 text-xs"
                          >
                            <div className="flex items-center gap-2">
                              <span className="px-1.5 py-0.5 rounded bg-white/10 text-[10px] uppercase font-mono text-slate-300">
                                {m.type}
                              </span>
                              <span className="text-red-300 font-medium">{m.threat_type.toUpperCase()}</span>
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                                  m.severity === 'critical'
                                    ? 'bg-red-600 text-white'
                                    : m.severity === 'high'
                                    ? 'bg-orange-500 text-white'
                                    : 'bg-amber-500 text-black'
                                }`}
                              >
                                {m.severity}
                              </span>
                              <span className="text-slate-400 text-[11px]">موثوقية: {m.confidence}%</span>
                              {m.related_threat_actor && (
                                <span className="text-purple-400 text-[11px]">الفاعل: {m.related_threat_actor}</span>
                              )}
                            </div>

                            {onSelectIOC && (
                              <button
                                type="button"
                                onClick={() => {
                                  onSelectIOC(m);
                                  onClose();
                                }}
                                className="flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300 font-semibold"
                              >
                                <span>عرض السجل الجنائي</span>
                                <ExternalLink className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-white/10 bg-white/[0.01] flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-semibold text-slate-300 transition-colors"
          >
            إغلاق
          </button>
        </div>
      </div>
    </div>
  );
}
