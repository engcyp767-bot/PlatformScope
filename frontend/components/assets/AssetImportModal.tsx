'use client';

import React, { useState } from 'react';
import { X, UploadCloud, CheckCircle2, AlertCircle, FileText } from 'lucide-react';
import { importAssets } from '../../lib/api';

interface AssetImportModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

export function AssetImportModal({ onClose, onSuccess }: AssetImportModalProps) {
  const [content, setContent] = useState('');
  const [format, setFormat] = useState<'json' | 'csv'>('csv');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const sampleCsv = `Hostname,Primary IP,MAC Address,Type,Criticality,Department
DC-PRIMARY-01,10.0.0.1,00:50:56:A1:B2:C3,domain_controller,mission_critical,IT Operations
DB-PROD-SQL,10.0.5.20,00:50:56:D4:E5:F6,database,high,Database Admin
WS-FINANCE-04,192.168.10.45,00:50:56:11:22:33,workstation,medium,Finance`;

  const handleImport = async (dryRun: boolean = false) => {
    if (!content.trim()) {
      setError('يرجى لصق بيانات الأصول المراد استيرادها.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await importAssets(content, format, dryRun);
      if (res.success) {
        setResult(res);
        if (!dryRun) {
          onSuccess();
        }
      } else {
        setError(res.error || 'فشل الاستيراد');
      }
    } catch (err: any) {
      setError(err.message || 'تعذر إتمام الاستيراد');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in">
      <div className="bg-dark-900 border border-white/10 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden animate-scale-up">
        <div className="p-5 border-b border-white/10 bg-dark-800/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center text-primary">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">استيراد أصول CMDB</h2>
              <p className="text-xs text-slate-400 mt-0.5">استيراد جماعي مع الفحص التلقائي لمنع تكرار الأصول</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 space-y-1.5">
              <div className="flex items-center gap-2 font-bold">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>{result.dry_run ? 'نتيجة الفحص المسبق بنجاح:' : 'تم الاستيراد بنجاح:'}</span>
              </div>
              <div className="flex items-center gap-4 text-xs font-mono">
                <span>الإجمالي: {result.total_records}</span>
                <span>أصول جديدة: <strong className="text-emerald-400">{result.created_count}</strong></span>
                <span>تحديث أصول قائمة: <strong className="text-amber-400">{result.updated_count}</strong></span>
              </div>
              {result.errors && result.errors.length > 0 && (
                <div className="text-[11px] text-amber-300 mt-1">
                  تنبيهات ({result.errors.length}): {result.errors.slice(0, 3).join(' | ')}
                </div>
              )}
            </div>
          )}

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <label className="text-slate-400 font-medium">صيغة البيانات:</label>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setFormat('csv')}
                  className={`px-3 py-1 rounded-lg border text-xs font-medium ${format === 'csv' ? 'bg-primary/10 border-primary text-primary' : 'border-white/10 text-slate-400'}`}
                >
                  CSV
                </button>
                <button
                  type="button"
                  onClick={() => setFormat('json')}
                  className={`px-3 py-1 rounded-lg border text-xs font-medium ${format === 'json' ? 'bg-primary/10 border-primary text-primary' : 'border-white/10 text-slate-400'}`}
                >
                  JSON
                </button>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setContent(sampleCsv)}
              className="text-primary hover:underline text-[11px] flex items-center gap-1"
            >
              <FileText className="w-3 h-3" />
              <span>تحميل نموذج CSV تجريبي</span>
            </button>
          </div>

          <div>
            <textarea
              rows={8}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={format === 'csv' ? 'Hostname,Primary IP,MAC Address,Type,Criticality,Department...\n' : '[\n  { "hostname": "...", "primary_ip": "..." }\n]'}
              className="w-full bg-dark-800 border border-white/10 rounded-xl p-3 text-white font-mono text-xs focus:border-primary outline-none"
            />
          </div>

          <div className="pt-3 border-t border-white/10 flex items-center justify-end gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
            >
              إغلاق
            </button>
            <button
              type="button"
              onClick={() => handleImport(true)}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-slate-200 font-semibold transition-colors"
            >
              فحص مسبق (Dry Run)
            </button>
            <button
              type="button"
              onClick={() => handleImport(false)}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold transition-colors flex items-center gap-1.5"
            >
              <UploadCloud className="w-4 h-4" />
              <span>تأكيد الاستيراد</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
