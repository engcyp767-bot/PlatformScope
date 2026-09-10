'use client';

import React, { use, useState, useEffect } from 'react';
import Link from 'next/link';
import { ArrowRight, Download, RefreshCw, FileText, AlertTriangle, ExternalLink } from 'lucide-react';
import { Navbar } from '../../../../components/Navbar';

export default function FlowScopePreviewPage({ params }: { params: Promise<{ jobId: string }> }) {
  const { jobId } = use(params);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const downloadDocxUrl = `/api/flowscope/export/${jobId}.docx`;

  const fetchPdf = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/flowscope/preview/${jobId}?format=json`, {
        headers: {
          'Accept': 'application/json',
        },
      });

      if (!res.ok) {
        let msg = `تعذر تحميل ملف المعاينة (رمز: ${res.status})`;
        try {
          const data = await res.json();
          if (data?.error) msg = data.error;
        } catch {}
        throw new Error(msg);
      }

      const json = await res.json();
      if (!json?.pdf_base64) {
        throw new Error('لم يتم استلام بيانات التقرير بشكل صحيح');
      }

      const binaryString = window.atob(json.pdf_base64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      const pdfBlob = new Blob([bytes], { type: 'application/pdf' });
      const url = URL.createObjectURL(pdfBlob);
      setBlobUrl((prev) => {
        if (prev) URL.revokeObjectURL(prev);
        return url;
      });
    } catch (err: any) {
      setError(err?.message || 'تعذر تحميل المعاينة حالياً');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPdf();
    return () => {
      if (blobUrl) {
        URL.revokeObjectURL(blobUrl);
      }
    };
  }, [jobId]);

  return (
    <div className="min-h-screen flex flex-col bg-dark-950">
      <Navbar />
      <div className="flex-1 w-full p-4 h-[calc(100vh-64px)] flex flex-col gap-3 max-w-7xl mx-auto">
        <div className="flex flex-wrap justify-between items-center gap-3 bg-white/[0.02] border border-white/5 rounded-2xl px-5 py-3">
          <div className="flex items-center gap-3">
            <Link
              href={`/flowscope/${jobId}`}
              className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors"
            >
              <ArrowRight className="w-4 h-4 rtl:rotate-180" />
              <span>العودة لنتائج التحليل</span>
            </Link>
            <span className="text-white/20">|</span>
            <p className="text-xs text-slate-400 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              <span>تعرض المعاينة النسخة نفسها التي سيتم تنزيلها.</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            {blobUrl && (
              <a
                href={blobUrl}
                target="_blank"
                rel="noreferrer"
                className="px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                title="فتح المعاينة في تبويب جديد"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>فتح في تبويب مستقل</span>
              </a>
            )}
            <button
              onClick={fetchPdf}
              disabled={loading}
              className="px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              title="إعادة تحميل المعاينة"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>تحديث</span>
            </button>
            <a
              className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-dark-950 text-xs font-bold flex items-center gap-1.5 transition-colors shadow-lg shadow-cyan-500/20"
              href={downloadDocxUrl}
            >
              <Download className="w-3.5 h-3.5" />
              <span>تنزيل نسخة Word المعروضة</span>
            </a>
          </div>
        </div>

        <div className="flex-1 relative w-full rounded-2xl overflow-hidden border border-white/10 bg-dark-900/60 shadow-2xl flex flex-col">
          {loading && (
            <div className="absolute inset-0 z-10 flex flex-col items-center justify-center p-8 text-center bg-dark-950/80 backdrop-blur-sm">
              <div className="w-12 h-12 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin mb-4" />
              <h3 className="text-white font-bold text-base mb-1.5">جارِ إعداد وتنسيق تقرير Word الأمني...</h3>
              <p className="text-slate-400 text-xs max-w-md leading-relaxed">
                يتم تنسيق الجداول والملخص التنفيذي وتحميل صفحات المعاينة مباشرة.
              </p>
            </div>
          )}

          {error && !loading && (
            <div className="absolute inset-0 z-10 flex flex-col items-center justify-center p-8 text-center bg-dark-950/90">
              <AlertTriangle className="w-12 h-12 text-rose-400 mb-3" />
              <h3 className="text-white font-bold text-base mb-1.5">تعذر تحميل المعاينة حالياً</h3>
              <p className="text-slate-400 text-xs max-w-md mb-4">{error}</p>
              <button
                onClick={fetchPdf}
                className="px-4 py-2 rounded-xl bg-cyan-500 text-dark-950 text-xs font-bold flex items-center gap-2 hover:bg-cyan-400 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>إعادة المحاولة</span>
              </button>
            </div>
          )}

          {blobUrl && (
            <iframe
              src={`${blobUrl}#toolbar=1`}
              className="w-full flex-1 border-0 bg-white"
              title="Word Report Preview"
            />
          )}
        </div>
      </div>
    </div>
  );
}
