'use client';

import React, { useState, useRef } from 'react';
import { ShieldCheck, ShieldAlert, UploadCloud, FileText, CheckCircle, AlertTriangle, X, Loader2, FileCode, Check, RefreshCw } from 'lucide-react';
import { verifyIncidentCase } from '../../lib/api';
import { CaseVerificationResult } from '../../lib/types';

interface VerifyCaseModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function VerifyCaseModal({ isOpen, onClose }: VerifyCaseModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CaseVerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = (selectedFile: File) => {
    if (!selectedFile.name.endsWith('.zip')) {
      setError('يرجى اختيار ملف أرشيف تحقيق بصيغة ZIP (.zip) فقط.');
      return;
    }
    setFile(selectedFile);
    setError(null);
    setResult(null);
    void runVerification(selectedFile);
  };

  const runVerification = async (targetFile: File) => {
    setLoading(true);
    setError(null);
    try {
      const res = await verifyIncidentCase(targetFile);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'فشل فحص سلامة وتجزئة ملف التحقيق.');
    } finally {
      setLoading(false);
    }
  };

  const resetAll = () => {
    setFile(null);
    setResult(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-3xl bg-dark-900 border border-white/10 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between bg-dark-800/60">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>فحص سلامة ملف التحقيق الجنائي الرقمي</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/30 text-purple-300 font-mono">
                  SHA-256 Manifest Verifier
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                تدقيق سلسلة الحيازة الجنائية للأدلة (Chain of Custody) ومطابقة بصمات التجزئة التشفيرية
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg hover:bg-white/10 flex items-center justify-center text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 custom-scrollbar">
          {/* Upload Drop Zone */}
          {!file && (
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const dropped = e.dataTransfer.files[0];
                if (dropped) handleFileChange(dropped);
              }}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-white/20 hover:border-purple-500/50 hover:bg-purple-500/5 rounded-2xl p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center gap-3"
            >
              <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-purple-400">
                <UploadCloud className="w-7 h-7 animate-bounce" />
              </div>
              <div>
                <p className="text-sm font-bold text-white">اسحب وأفلت حزمة التحقيق (INC-ID.zip) هنا أو انقر للاختيار</p>
                <p className="text-xs text-slate-400 mt-1">يدعم حزم الأرشيف الجنائية الصادرة من المنصة للتحقق من سلامة manifest.sha256</p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".zip"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFileChange(f);
                }}
              />
            </div>
          )}

          {/* Loading State */}
          {loading && (
            <div className="p-8 text-center flex flex-col items-center justify-center gap-3">
              <Loader2 className="w-8 h-8 text-purple-400 animate-spin" />
              <p className="text-sm font-medium text-slate-300">جاري قراءة الحزمة وحساب بصمات التجزئة SHA-256 لكافة الأدلة...</p>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{error}</span>
              </div>
              <button onClick={resetAll} className="px-2 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs">
                إعادة المحاولة
              </button>
            </div>
          )}

          {/* Verification Results Presentation */}
          {result && !loading && (
            <div className="space-y-5">
              {/* Verdict Header Banner */}
              <div
                className={`p-4 rounded-xl border flex items-center justify-between ${
                  result.valid
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                    : 'bg-red-950/40 border-red-500/40 text-red-200'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                      result.valid ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                    }`}
                  >
                    {result.valid ? <ShieldCheck className="w-6 h-6" /> : <ShieldAlert className="w-6 h-6" />}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold">{result.valid ? 'حزمة التحقيق سليمة وموثقة بنسبة 100%' : 'تحذير: تم رصد عدم تطابق في الأدلة الجنائية'}</h3>
                    <p className="text-xs opacity-90">{result.message}</p>
                  </div>
                </div>

                <button
                  onClick={resetAll}
                  className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white text-xs font-medium flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>فحص حزمة أخرى</span>
                </button>
              </div>

              {/* Case Metadata Details */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-white/[0.02] border border-white/5 p-4 rounded-xl text-xs">
                <div>
                  <span className="text-slate-400 block text-[11px]">معرّف الحادث:</span>
                  <span className="font-mono font-bold text-white text-sm">{result.case_id}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">ختم النزاهة التشفيري:</span>
                  <span className={`font-medium ${result.seal_valid ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {result.seal_valid ? 'مختوم ومطابق (Sealed)' : 'ختم غير متطابق'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">تاريخ التصدير:</span>
                  <span className="text-slate-200">{result.exported_at ? new Date(result.exported_at).toLocaleString('ar-SA') : 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">المحلل المصدّر:</span>
                  <span className="text-slate-200">{result.exported_by || 'N/A'}</span>
                </div>
              </div>

              {/* Statistics Breakdown */}
              <div className="grid grid-cols-4 gap-2 text-center text-xs">
                <div className="p-2.5 rounded-lg bg-white/5 border border-white/10">
                  <span className="text-[11px] text-slate-400 block">إجمالي الملفات</span>
                  <span className="text-base font-bold text-white font-mono">{result.total_files_in_manifest || 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                  <span className="text-[11px] text-emerald-400 block">ملفات مطابقة (سليمة)</span>
                  <span className="text-base font-bold text-emerald-300 font-mono">{result.verified_files_count || 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30">
                  <span className="text-[11px] text-red-400 block">ملفات متلاعب بها</span>
                  <span className="text-base font-bold text-red-400 font-mono">{result.mismatches_count || 0}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30">
                  <span className="text-[11px] text-amber-400 block">ملفات مفقودة</span>
                  <span className="text-base font-bold text-amber-400 font-mono">{result.missing_count || 0}</span>
                </div>
              </div>

              {/* Mismatches List if any */}
              {result.mismatches && result.mismatches.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>الملفات المعدلة أو المتلاعب بها (Hash Mismatch):</span>
                  </h4>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {result.mismatches.map((m, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-red-950/30 border border-red-500/30 text-xs font-mono">
                        <div className="text-red-300 font-bold">{m.path}</div>
                        <div className="text-[11px] text-slate-400">المتوقع: {m.expected_sha256}</div>
                        <div className="text-[11px] text-red-400">الفعلي: {m.actual_sha256}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Missing files if any */}
              {result.missing && result.missing.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>الملفات المفقودة من الحزمة (Missing Files):</span>
                  </h4>
                  <div className="space-y-1">
                    {result.missing.map((f, idx) => (
                      <div key={idx} className="p-2 rounded bg-amber-950/20 border border-amber-500/20 text-amber-300 text-xs font-mono">
                        {f}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Verified Files Manifest List */}
              {result.verified_files && result.verified_files.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                    <span>قائمة الأدلة والملفات المتحقق من سلامتها التشفيرية ({result.verified_files.length}):</span>
                  </h4>
                  <div className="border border-white/10 rounded-xl overflow-hidden max-h-56 overflow-y-auto custom-scrollbar">
                    <table className="w-full text-right text-xs">
                      <thead className="bg-white/5 text-slate-400 text-[11px]">
                        <tr>
                          <th className="py-2 px-3">الملف الجنائي</th>
                          <th className="py-2 px-3">الحجم</th>
                          <th className="py-2 px-3">بصمة SHA-256</th>
                          <th className="py-2 px-3 text-center">الحالة</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/5 text-slate-200">
                        {result.verified_files.map((vf, idx) => (
                          <tr key={idx} className="hover:bg-white/[0.02]">
                            <td className="py-2 px-3 font-mono text-cyan-300">{vf.path}</td>
                            <td className="py-2 px-3 text-slate-400">{vf.size}</td>
                            <td className="py-2 px-3 font-mono text-slate-400 text-[10px] truncate max-w-[200px]" title={vf.sha256}>
                              {vf.sha256}
                            </td>
                            <td className="py-2 px-3 text-center">
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 text-[10px] font-bold">
                                <Check className="w-2.5 h-2.5" />
                                <span>سليم</span>
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-white/10 bg-dark-800/60 flex items-center justify-between text-xs">
          <span className="text-slate-400">معيار التوثيق: FIPS 180-4 Secure Hash Standard (SHA-256)</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-white/10 hover:bg-white/20 text-white font-medium transition-colors"
          >
            إغلاق
          </button>
        </div>
      </div>
    </div>
  );
}
