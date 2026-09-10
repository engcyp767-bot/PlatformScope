'use client';

import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Navbar } from '../../components/Navbar';
import { UploadCloud, ShieldAlert, AlertCircle, Play, CheckCircle2, BookOpen } from 'lucide-react';
import { useTranslation } from '../../lib/i18n';

export default function ThreatScopePage() {
  const { t } = useTranslation();
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const legacyJobId = new URLSearchParams(window.location.search).get('job');
    if (legacyJobId && /^[0-9a-f]{32}$/i.test(legacyJobId)) {
      router.replace(`/threatscope/${legacyJobId}`);
    }
  }, [router]);

  const [file, setFile] = useState<File | null>(null);
  const [sourceSystem, setSourceSystem] = useState('xdr_1');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [sourceSystems, setSourceSystems] = useState([
    { id: 'xdr_1', label: 'C-IN', description: 'تنبيهات بيئة العمل المركزية' },
    { id: 'xdr_2', label: 'DCS', description: 'خوادم مركز البيانات' },
    { id: 'xdr_3', label: 'C-OUT', description: 'الأجهزة الطرفية والخارجية' },
  ]);

  useEffect(() => {
    fetch('/api/settings/public', { cache: 'no-store' }).then((response) => response.json()).then((payload) => {
      const sources = payload?.source_systems?.threatscope;
      if (Array.isArray(sources) && sources.length) {
        setSourceSystems(sources);
        setSourceSystem((current) => sources.some((item: { id: string }) => item.id === current) ? current : sources[0].id);
      }
    }).catch(() => undefined);
  }, []);

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const f = e.dataTransfer.files[0];
      if (/\.(csv|xlsx)$/i.test(f.name)) {
        setFile(f);
        setError('');
      } else {
        setError(t('threatscope.upload_csv_xlsx'));
      }
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError('');
    }
  };

  const handleStartAnalysis = async () => {
    if (!file) return;
    setLoading(true);
    setError('');

    try {
      const arrayBuffer = await file.arrayBuffer();
      const res = await fetch('/api/threatscope/analyze', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Filename': encodeURIComponent(file.name),
          'X-Source-System': sourceSystem,
        },
        body: arrayBuffer,
      });

      if (!res.ok) {
        const payload = await res.json();
        throw new Error(payload.error || t('threatscope.upload_fail'));
      }

      const data = await res.json();
      router.push(`/threatscope/${data.job_id}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : t('threatscope.analysis_start_fail');
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 py-10">
        <div className="mb-8 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-3 py-1 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30 text-xs font-bold font-heading">
                THREATSCOPE
              </span>
              <span className="text-xs text-slate-400">{t('threatscope.subtitle')}</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white mt-2">
              {t('threatscope.page_title')}
            </h1>
          </div>
          <Link
            href="/help#threatscope"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-xs font-semibold text-rose-300 transition-colors shrink-0 self-start sm:self-auto"
            title="فتح دليل استخدام ThreatScope"
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>دليل استخدام ThreatScope</span>
          </Link>
        </div>

        {error && (
          <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-3 text-rose-300 text-sm">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="glass-panel p-8 space-y-6">
          <div>
            <label className="block text-xs font-bold text-slate-300 mb-2">{t('threatscope.source_sys_label')}</label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {sourceSystems.map((sys) => (
                <button
                  key={sys.id}
                  type="button"
                  onClick={() => setSourceSystem(sys.id)}
                  className={`p-4 rounded-xl text-right transition-all border ${
                    sourceSystem === sys.id
                      ? 'bg-rose-500/10 border-rose-500/50 text-white shadow-lg shadow-rose-500/10'
                      : 'bg-white/5 border-white/10 text-slate-400 hover:border-white/20'
                  }`}
                >
                  <div className="font-bold text-sm text-white font-heading">{sys.label}</div>
                  <div className="text-xs text-slate-400 mt-1">{sys.description}</div>
                </button>
              ))}
            </div>
          </div>

          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all ${
              file
                ? 'border-accent/50 bg-accent/5'
                : 'border-white/15 bg-white/5 hover:border-accent/40 hover:bg-white/10'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              accept=".csv,.xlsx"
              className="hidden"
            />

            <div className="w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-accent mx-auto flex items-center justify-center mb-4">
              <UploadCloud className="w-8 h-8" />
            </div>

            {file ? (
              <div>
                <div className="text-white font-bold text-base flex items-center justify-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span>{file.name}</span>
                </div>
                <div className="text-xs text-slate-400 mt-1 font-mono">
                  {(file.size / 1024 / 1024).toFixed(2)} MB
                </div>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setFile(null);
                  }}
                  className="mt-3 text-xs text-rose-400 hover:underline"
                >
                  {t('threatscope.cancel_file')}
                </button>
              </div>
            ) : (
              <div>
                <div className="text-white font-bold text-base">
                  {t('threatscope.drag_drop_main')}
                </div>
                <div className="text-xs text-slate-400 mt-2">
                  {t('threatscope.supported_desc')}
                </div>
              </div>
            )}
          </div>

          <div className="pt-4 flex items-center justify-end">
            <button
              onClick={handleStartAnalysis}
              disabled={!file || loading}
              className="px-8 py-3 rounded-xl bg-gradient-to-r from-accent to-rose-400 hover:from-rose-600 hover:to-rose-300 text-white font-bold text-sm shadow-lg shadow-accent/20 hover:shadow-accent/30 transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>{t('threatscope.btn_loading')}</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>{t('threatscope.btn_start')}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}
