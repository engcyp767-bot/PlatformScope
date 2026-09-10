'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  KeyRound,
  Download,
  Upload,
  RefreshCw,
  Copy,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Cpu,
  Layers,
  Users,
  HardDrive,
  FileCheck,
} from 'lucide-react';

interface LicenseData {
  state: string;
  license_type: string;
  product: string;
  edition: string;
  installation_id: string;
  instance_id: string;
  start_utc: string;
  expires_utc: string;
  days_remaining: number;
  grace_days: number;
  is_valid: boolean;
  status_message: string;
  customer_org: string;
  license_id: string;
  entitlements: {
    features: string[];
    max_users: number;
    max_assets: number;
    max_daily_events: number;
  };
}

export function LicensingTab() {
  const [license, setLicense] = useState<LicenseData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importText, setImportText] = useState('');
  const [alert, setAlert] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/licensing/status');
      if (res.ok) {
        const data = await res.json();
        setLicense(data);
      }
    } catch {
      // Backend status probe
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleCopyId = () => {
    if (license?.installation_id) {
      navigator.clipboard.writeText(license.installation_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleExportRequest = async () => {
    try {
      const res = await fetch('/api/licensing/request', { method: 'POST' });
      if (res.ok) {
        const reqData = await res.json();
        const blob = new Blob([JSON.stringify(reqData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `PlatformScope-ActivationRequest-${license?.installation_id || 'ID'}.req`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setAlert({ type: 'success', message: 'تم تصدير ملف طلب التفعيل بنجاح. أرسل هذا الملف لمزود الخدمة لإصدار ترخيصك.' });
      } else {
        setAlert({ type: 'error', message: 'تعذر إنشاء طلب التفعيل.' });
      }
    } catch (e: any) {
      setAlert({ type: 'error', message: e.message || 'حدث خطأ أثناء تصدير طلب التفعيل.' });
    }
  };

  const handleImportLicense = async () => {
    if (!importText.trim()) {
      setAlert({ type: 'error', message: 'يرجى لصق أو اختيار ملف الترخيص أولاً.' });
      return;
    }
    setImporting(true);
    setAlert(null);
    try {
      const res = await fetch('/api/licensing/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_text: importText.trim() }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setAlert({ type: 'success', message: data.message || 'تم تفعيل ترخيص Platform Scope بنجاح!' });
        setLicense(data.license);
        setImportText('');
      } else {
        setAlert({ type: 'error', message: data.error || 'فشل تفعيل ملف الترخيص.' });
      }
    } catch (e: any) {
      setAlert({ type: 'error', message: e.message || 'تعذر استيراد ملف الترخيص.' });
    } finally {
      setImporting(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setImportText(content);
    };
    reader.readAsText(file);
  };

  if (loading && !license) {
    return (
      <div className="flex items-center justify-center p-12 text-slate-400">
        <RefreshCw className="w-6 h-6 animate-spin text-purple-500 ml-3" />
        <span>جاري قراءة حالة الترخيص والهوية العتادية...</span>
      </div>
    );
  }

  const isExpired = license?.state === 'TRIAL_EXPIRED' || license?.state === 'LICENSE_EXPIRED';
  const isGrace = license?.state === 'LICENSE_GRACE_PERIOD';
  const isTrial = license?.license_type === 'TRIAL';

  return (
    <div className="space-y-6">
      {/* Alert Notification */}
      {alert && (
        <div
          className={`p-4 rounded-xl text-sm flex items-center gap-3 border ${
            alert.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
          }`}
        >
          {alert.type === 'success' ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <AlertTriangle className="w-5 h-5 shrink-0" />}
          <span>{alert.message}</span>
        </div>
      )}

      {/* Main Status Header Card */}
      <div className="bg-gradient-to-r from-purple-950/40 via-slate-900 to-indigo-950/40 border border-purple-500/20 rounded-2xl p-6 relative overflow-hidden">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-purple-600/20 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-bold text-white tracking-wide">Platform Scope</h2>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/20 border border-purple-500/30 text-purple-300">
                  {license?.edition || 'Enterprise'} Edition
                </span>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                    license?.is_valid
                      ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-300'
                      : 'bg-rose-500/20 border-rose-500/30 text-rose-300'
                  }`}
                >
                  {license?.state || 'ACTIVE'}
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                {license?.status_message || 'نظام إدارة وتفعيل تراخيص المنصة'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchStatus}
              className="p-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/10 transition-all"
              title="تحديث حالة الترخيص"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={handleExportRequest}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold shadow-lg shadow-purple-600/20 transition-all"
            >
              <Download className="w-4 h-4" />
              <span>تصدير طلب التفعيل (.req)</span>
            </button>
          </div>
        </div>

        {/* Trial Progress Bar if in Trial */}
        {isTrial && (
          <div className="mt-6 pt-6 border-t border-white/10">
            <div className="flex items-center justify-between text-xs text-slate-300 mb-2 font-medium">
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-purple-400" />
                <span>الفترة التجريبية (30 يوماً)</span>
              </span>
              <span className="font-bold text-white">
                {license?.days_remaining ?? 0} يوماً متبقية
              </span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden border border-white/5">
              <div
                className={`h-full transition-all duration-500 ${
                  (license?.days_remaining ?? 0) <= 3
                    ? 'bg-rose-500'
                    : (license?.days_remaining ?? 0) <= 7
                    ? 'bg-amber-500'
                    : 'bg-gradient-to-r from-purple-500 to-indigo-500'
                }`}
                style={{ width: `${Math.min(100, Math.max(0, ((license?.days_remaining ?? 0) / 30) * 100))}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Grid: Hardware Identity & License Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Hardware Identity Card */}
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-3 border-b border-white/5 pb-3">
            <Cpu className="w-5 h-5 text-indigo-400" />
            <h3 className="text-sm font-bold text-white">الهوية العتادية للجهاز (Hardware Identity)</h3>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <span className="text-slate-400 block mb-1">معرف التثبيت الفريد (Installation ID):</span>
              <div className="flex items-center justify-between bg-black/40 border border-white/10 rounded-xl p-2.5 font-mono text-indigo-300 select-all">
                <span>{license?.installation_id || 'PS-INST-UNKNOWN'}</span>
                <button
                  onClick={handleCopyId}
                  className="p-1 hover:text-white transition-colors"
                  title="نسخ المعرف"
                >
                  {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-[11px] text-slate-500 mt-1">
                هذا المعرف مرتبط بالعتاد الفعلي لجهازك ولا يتغير بتحديث البرامج أو عناوين الشبكة.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2">
              <div className="bg-white/5 rounded-xl p-3">
                <span className="text-slate-400 block text-[11px]">معرف النسخة (Instance):</span>
                <span className="font-mono text-slate-200 mt-0.5 block">{license?.instance_id || 'PS-INST'}</span>
              </div>
              <div className="bg-white/5 rounded-xl p-3">
                <span className="text-slate-400 block text-[11px]">طريقة الحماية:</span>
                <span className="text-emerald-400 font-semibold mt-0.5 block">Windows DPAPI + Ed25519</span>
              </div>
            </div>
          </div>
        </div>

        {/* License Specifications Card */}
        <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-5 space-y-4">
          <div className="flex items-center gap-3 border-b border-white/5 pb-3">
            <FileCheck className="w-5 h-5 text-purple-400" />
            <h3 className="text-sm font-bold text-white">تفاصيل وصلاحية الترخيص</h3>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-white/5 rounded-xl p-3">
              <span className="text-slate-400 block text-[11px]">نوع الترخيص:</span>
              <span className="text-white font-bold mt-0.5 block">{license?.license_type || 'TRIAL'}</span>
            </div>
            <div className="bg-white/5 rounded-xl p-3">
              <span className="text-slate-400 block text-[11px]">المؤسسة / العميل:</span>
              <span className="text-white font-medium mt-0.5 block truncate">{license?.customer_org || 'Customer'}</span>
            </div>
            <div className="bg-white/5 rounded-xl p-3">
              <span className="text-slate-400 block text-[11px]">تاريخ البدء:</span>
              <span className="text-slate-300 font-mono mt-0.5 block">{license?.start_utc?.slice(0, 10) || '-'}</span>
            </div>
            <div className="bg-white/5 rounded-xl p-3">
              <span className="text-slate-400 block text-[11px]">تاريخ الانتهاء:</span>
              <span className="text-slate-300 font-mono mt-0.5 block">{license?.expires_utc?.slice(0, 10) || '-'}</span>
            </div>
          </div>

          <div className="pt-2">
            <span className="text-slate-400 text-xs block mb-1">الحدود التشغيلية (Entitlements):</span>
            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div className="bg-purple-950/20 border border-purple-500/20 rounded-xl p-2">
                <span className="text-purple-300 block font-bold text-sm">{license?.entitlements?.max_users || 50}</span>
                <span className="text-[10px] text-slate-400">مستخدمين</span>
              </div>
              <div className="bg-purple-950/20 border border-purple-500/20 rounded-xl p-2">
                <span className="text-purple-300 block font-bold text-sm">{license?.entitlements?.max_assets?.toLocaleString() || '5,000'}</span>
                <span className="text-[10px] text-slate-400">أصول مراقبة</span>
              </div>
              <div className="bg-purple-950/20 border border-purple-500/20 rounded-xl p-2">
                <span className="text-purple-300 block font-bold text-sm">{((license?.entitlements?.max_daily_events || 10000000) / 1000000).toFixed(0)}M</span>
                <span className="text-[10px] text-slate-400">سجلات يومياً</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Offline License Import Card */}
      <div className="bg-slate-900/60 border border-white/10 rounded-2xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-white/5 pb-3">
          <div className="flex items-center gap-3">
            <KeyRound className="w-5 h-5 text-emerald-400" />
            <div>
              <h3 className="text-sm font-bold text-white">تفعيل واستيراد ملف الترخيص (Activate License)</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                استورد ملف الترخيص الموقع رقمياً (.lic) الصادر خصيصاً لجهازك للتفعيل دون اتصال بالإنترنت.
              </p>
            </div>
          </div>

          <label className="cursor-pointer flex items-center gap-2 px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium border border-white/10 transition-colors">
            <Upload className="w-3.5 h-3.5" />
            <span>اختيار ملف .lic</span>
            <input type="file" accept=".lic,.json,.txt" className="hidden" onChange={handleFileUpload} />
          </label>
        </div>

        <div className="space-y-3">
          <textarea
            rows={4}
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            placeholder="الصق محتوى ملف الترخيص (JSON Envelope) هنا أو اختر الملف من الزر أعلاه..."
            className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-purple-500/50 resize-none"
          />

          <div className="flex justify-end">
            <button
              onClick={handleImportLicense}
              disabled={importing || !importText.trim()}
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 disabled:text-slate-600 text-white text-xs font-bold shadow-lg shadow-emerald-600/20 transition-all"
            >
              {importing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
              <span>تفعيل الترخيص فورياً</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

