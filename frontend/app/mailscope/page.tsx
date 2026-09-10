'use client';

import React, { useEffect, useState } from 'react';
import {
  Mail,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  FileWarning,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  Filter,
  RefreshCw,
  Lock,
  Flame,
  ArrowRight,
  Radio,
  FileText,
  UserCheck,
  Server,
  Key,
  Copy,
  Check,
  Send,
  Download,
  Eye,
  Trash2,
  Layers,
  Sparkles,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { fetchApi } from '../../lib/api';

interface EmailHop {
  hop_number: number;
  from_host: string;
  by_host: string;
  with_protocol: string;
  timestamp: string;
  source_ip: string;
}

interface EmailAuthResults {
  spf_status: string;
  spf_sender: string;
  spf_ip: string;
  dkim_status: string;
  dkim_domain: string;
  dmarc_status: string;
  dmarc_policy: string;
  is_aligned: boolean;
}

interface EmailAttachment {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  is_dangerous_type: boolean;
  has_macros: boolean;
  is_double_extension: boolean;
  entropy: number;
  findings: string[];
}

interface EmailURL {
  url: string;
  display_text: string;
  domain: string;
  is_mismatched: boolean;
  is_shortened: boolean;
  is_punycode: boolean;
  is_ip_based: boolean;
  has_credential_keywords: boolean;
  reputation_score: number;
  category: string;
  threat_flags: string[];
}

interface EmailFinding {
  id: string;
  category: string;
  severity: string;
  title: string;
  title_ar: string;
  description: string;
  description_ar: string;
  mitre_technique: string;
  evidence: string;
}

interface ParsedEmail {
  message_id: string;
  subject: string;
  sender_name: string;
  sender_address: string;
  sender_domain: string;
  reply_to: string;
  return_path: string;
  to: string[];
  cc: string[];
  date: string;
  body_text: string;
  body_html: string;
  hops: EmailHop[];
  auth_results: EmailAuthResults;
  attachments: EmailAttachment[];
  urls: EmailURL[];
}

interface EmailReport {
  id: string;
  analyzed_at: string;
  verdict: 'clean' | 'suspicious' | 'phishing' | 'malicious' | 'bec_fraud' | 'spam';
  overall_score: number;
  risk_level: 'info' | 'low' | 'medium' | 'high' | 'critical';
  parsed_email: ParsedEmail;
  findings: EmailFinding[];
  auth_summary: Record<string, any>;
  url_summary: Record<string, any>;
  attachment_summary: Record<string, any>;
  bec_summary: Record<string, any>;
  recommended_actions: string[];
  remediation_playbook: Array<{
    step: number;
    action: string;
    title_ar: string;
    title_en: string;
    status: string;
    automated: boolean;
  }>;
  digital_signature: string;
  is_quarantined?: boolean;
  incident_id?: string;
}

interface MailStats {
  total_analyzed: number;
  phishing_count: number;
  bec_count: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  quarantined_count: number;
  clean_rate_percent: number;
  top_threat_domains: Array<{ sender_domain: string; count: number }>;
}

const SAMPLE_EMAILS = [
  {
    name: 'احتيال تحويل أموال تنفيذي (BEC CEO Fraud)',
    content: `From: "سعد القحطاني (الرئيس التنفيذي)" <saad.alqahtani.ceo@gmail.com>
To: accountant@company.com
Subject: طلب تحويل بنكي عاجل وسري للغاية
Date: Mon, 10 Sep 2026 09:30:00 +0300
Message-ID: <bec-sample-01@gmail.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=none

أهلاً بك،
أنا في اجتماع مغلق حالياً، أحتاج منك سداد فاتورة مستعجلة وتحديث بيانات الحساب البنكي إلى الآيبان المرفق فوراً بقيمة 120,000 ريال.
يرجى تنفيذ العملية بسريّة تامة وإرسال إشعار الدفع عبر هذا البريد.
الرئيس التنفيذي`,
  },
  {
    name: 'تصيد منتحل لمايكروسوفت 365 (M365 Credential Harvest)',
    content: `From: "Microsoft 365 Security" <admin@m365-verify-portal.net>
Reply-To: phish-collector@m365-verify-portal.net
To: user@company.com
Subject: تنبيه أمني: تم تعليق حسابك لتجاوز الحصة التخزينية
Date: Mon, 10 Sep 2026 11:15:00 +0300
Message-ID: <phish-sample-02@m365-verify-portal.net>
Authentication-Results: mx.company.com; spf=fail (client-ip=198.51.100.88); dmarc=fail action=reject
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>عزيزي المستخدم،</p>
<p>تم إيقاف استلام الرسائل في بريدك لتجاوز المساحة. يرجى تأكيد كلمة المرور لتفادي حذف البيانات:</p>
<a href="http://198.51.100.88/auth/portal-login.php">https://login.microsoftonline.com/verify-account</a>
<p>فريق دعم Microsoft 365</p>
</body></html>`,
  },
  {
    name: 'مرفق تنفيذي خبيث بامتداد مزدوج (Malware Double Extension)',
    content: `From: "إدارة الفواتير والتحصيل" <billing@contractor-services.com>
To: procurement@company.com
Subject: إشعار استحقاق دفعة وعقد التوريد لشهر سبتمبر
Date: Mon, 10 Sep 2026 13:45:00 +0300
Message-ID: <invoice-mal-03@contractor-services.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY_XYZ"

--BOUNDARY_XYZ
Content-Type: text/plain; charset=utf-8

مرفق لكم جدول الدفعات وتفاصيل الفاتورة المستحقة.

--BOUNDARY_XYZ
Content-Type: application/octet-stream; name="Invoice_Sep2026.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Sep2026.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

--BOUNDARY_XYZ--`,
  },
];

export default function MailScopePage() {
  const [stats, setStats] = useState<MailStats | null>(null);
  const [reports, setReports] = useState<any[]>([]);
  const [selectedReport, setSelectedReport] = useState<EmailReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [inputContent, setInputContent] = useState<string>('');
  const [filterVerdict, setFilterVerdict] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedSig, setCopiedSig] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'hops' | 'urls' | 'attachments' | 'findings' | 'playbook'>('overview');

  const loadData = async () => {
    try {
      setLoading(true);
      const [statsRes, reportsRes] = await Promise.all([
        fetchApi('/api/v1/mail/stats').catch(() => null),
        fetchApi(`/api/v1/mail/reports?verdict=${filterVerdict}&search=${encodeURIComponent(searchQuery)}`).catch(() => null),
      ]);

      if (statsRes && statsRes.data) {
        setStats(statsRes.data);
      } else if (statsRes && typeof statsRes.total_analyzed === 'number') {
        setStats(statsRes);
      }

      if (reportsRes && reportsRes.data) {
        setReports(reportsRes.data);
      } else if (Array.isArray(reportsRes)) {
        setReports(reportsRes);
      }
    } catch (err) {
      console.error('Failed to load MailScope data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [filterVerdict, searchQuery]);

  const handleAnalyze = async () => {
    if (!inputContent.trim()) return;
    try {
      setAnalyzing(true);
      const res = await fetchApi('/api/v1/mail/analyze', {
        method: 'POST',
        body: JSON.stringify({ raw_eml: inputContent }),
      });
      const reportData: EmailReport = res.data || res;
      setSelectedReport(reportData);
      loadData();
    } catch (err: any) {
      alert(`فشل التحليل: ${err.message || 'خطأ غير متوقع'}`);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleToggleQuarantine = async (reportId: string, currentQuarantined: boolean) => {
    try {
      await fetchApi(`/api/v1/mail/quarantine/${reportId}`, {
        method: 'POST',
        body: JSON.stringify({ quarantine: !currentQuarantined }),
      });
      if (selectedReport && selectedReport.id === reportId) {
        setSelectedReport({
          ...selectedReport,
          is_quarantined: !currentQuarantined,
        });
      }
      loadData();
    } catch (err: any) {
      alert(`فشل تعديل حالة الحجز: ${err.message}`);
    }
  };

  const handleOpenReportDetails = async (reportId: string) => {
    try {
      const res = await fetchApi(`/api/v1/mail/reports/${reportId}`);
      const data: EmailReport = res.data || res;
      setSelectedReport(data);
      setActiveTab('overview');
    } catch (err) {
      console.error('Failed to fetch report details:', err);
    }
  };

  const copySignature = (sig: string) => {
    navigator.clipboard.writeText(sig);
    setCopiedSig(true);
    setTimeout(() => setCopiedSig(false), 2000);
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'bec_fraud':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-purple-500/20 text-purple-400 border border-purple-500/40">
            <Flame className="w-3.5 h-3.5" />
            انتحال تنفيذي / BEC Fraud
          </span>
        );
      case 'malicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40">
            <ShieldAlert className="w-3.5 h-3.5" />
            بريد خبيث / Malicious
          </span>
        );
      case 'phishing':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3.5 h-3.5" />
            تصيد احتيالي / Phishing
          </span>
        );
      case 'suspicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/40">
            <Clock className="w-3.5 h-3.5" />
            مشبوه / Suspicious
          </span>
        );
      case 'clean':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
            <ShieldCheck className="w-3.5 h-3.5" />
            بريد آمن / Clean
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-slate-500/20 text-slate-400 border border-slate-500/40">
            {verdict}
          </span>
        );
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-500/15 border-red-500/30';
    if (score >= 60) return 'text-amber-400 bg-amber-500/15 border-amber-500/30';
    if (score >= 40) return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30';
    return 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-indigo-500/20 to-purple-600/20 border border-indigo-500/40 rounded-xl">
              <Mail className="w-7 h-7 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-black tracking-tight text-white">MailScope</h1>
                <span className="px-2.5 py-0.5 text-xs font-extrabold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 rounded-md">
                  Email Forensics & BEC Defense
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1">
                التحليل الجنائي المتقدم لرسائل البريد الإلكتروني، كشف التصيد، وانتحال هوية المسؤولين التنفيذيين (BEC) مع عزل التهديدات آلياً
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded-lg text-sm font-medium transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            تحديث المؤشرات
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>إجمالي الرسائل</span>
            <Mail className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-white">{stats?.total_analyzed ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">فحص جنائي متكامل</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>التصيد الاحتيالي</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400">{stats?.phishing_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">روابط ومواقع مضللة</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>انتحال الهوية (BEC)</span>
            <Flame className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-black text-purple-400">{stats?.bec_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">احتيال تحويل أموال</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>برمجيات خبيثة</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-black text-red-400">{stats?.malicious_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">مرفقات تنفيذية وماكرو</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>الرسائل المحجوزة</span>
            <Lock className="w-4 h-4 text-pink-400" />
          </div>
          <div className="text-2xl font-black text-pink-400">{stats?.quarantined_count ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1">معزولة عن المستخدمين</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>نسبة البريد السليم</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">{stats?.clean_rate_percent ?? 100}%</div>
          <div className="text-[11px] text-slate-500 mt-1">مطابق للسياسات</div>
        </div>
      </div>

      {/* Live Analyzer Input Section */}
      <div className="bg-slate-900/80 border border-indigo-500/30 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-bold text-white">مختبر الفحص الجنائي المباشر (Live RFC 822 Email Forensics)</h2>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-slate-400 font-medium">نماذج جاهزة للاختبار:</span>
            {SAMPLE_EMAILS.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => setInputContent(sample.content)}
                className="text-xs px-2.5 py-1 bg-slate-800 hover:bg-indigo-900/40 text-indigo-300 border border-slate-700 hover:border-indigo-500/40 rounded transition"
              >
                {sample.name}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <textarea
            value={inputContent}
            onChange={(e) => setInputContent(e.target.value)}
            placeholder="الصق نص الرسالة الخام (RFC 822 / .EML headers & body) هنا لبدء الفحص الجنائي الشامل..."
            className="w-full h-44 bg-slate-950/90 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500 transition resize-y"
            dir="ltr"
          />

          <div className="flex items-center justify-between gap-4">
            <p className="text-xs text-slate-500">
              * يفحص محرك MailScope ترويسات المصادقة SPF/DKIM/DMARC، المسارات، الروابط، وبصمات المرفقات بالكامل داخل بيئة معزولة Air-Gapped.
            </p>

            <button
              onClick={handleAnalyze}
              disabled={analyzing || !inputContent.trim()}
              className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold rounded-lg text-sm transition shadow-lg shadow-indigo-600/20 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {analyzing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  جاري الفحص الجنائي...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  تشغيل التحليل الجنائي الفوري
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Historical Logs & Filter Controls */}
      <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-indigo-400" />
            <h2 className="text-lg font-bold text-white">سجل التحليلات والرسائل المفحوصة</h2>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative">
              <Search className="w-4 h-4 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="بحث بالموضوع أو المرسل..."
                className="bg-slate-950 border border-slate-800 rounded-lg pr-9 pl-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 w-56"
              />
            </div>

            <select
              value={filterVerdict}
              onChange={(e) => setFilterVerdict(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="">جميع النتائج (All)</option>
              <option value="bec_fraud">انتحال تنفيذي (BEC Fraud)</option>
              <option value="phishing">تصيد احتيالي (Phishing)</option>
              <option value="malicious">بريد خبيث (Malicious)</option>
              <option value="suspicious">مشبوه (Suspicious)</option>
              <option value="clean">سليم (Clean)</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-right text-xs">
            <thead className="bg-slate-950 text-slate-400 font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3">تاريخ الفحص</th>
                <th className="p-3">موضوع الرسالة (Subject)</th>
                <th className="p-3">المرسل (Sender)</th>
                <th className="p-3">نتيجة التحليل (Verdict)</th>
                <th className="p-3">درجة الخطورة</th>
                <th className="p-3">حالة العزل</th>
                <th className="p-3 text-center">الإجراءات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    لا توجد سجلات رسائل مطابقة حالياً. استخدم مختبر الفحص المباشر في الأعلى لإجراء أول تحليل.
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3 text-slate-400 font-mono">
                      {new Date(r.analyzed_at).toLocaleString('ar-SA')}
                    </td>
                    <td className="p-3 font-semibold text-white max-w-xs truncate">
                      {r.subject || '(بدون عنوان)'}
                    </td>
                    <td className="p-3 text-slate-300">
                      <div>{r.sender_name || r.sender_address}</div>
                      <div className="text-[10px] text-slate-500 font-mono">{r.sender_address}</div>
                    </td>
                    <td className="p-3">{getVerdictBadge(r.verdict)}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${getScoreColor(r.overall_score)}`}>
                        {r.overall_score} / 100
                      </span>
                    </td>
                    <td className="p-3">
                      {r.is_quarantined ? (
                        <span className="inline-flex items-center gap-1 text-pink-400 font-medium">
                          <Lock className="w-3 h-3" />
                          محجوز
                        </span>
                      ) : (
                        <span className="text-slate-500">غير محجوز</span>
                      )}
                    </td>
                    <td className="p-3 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <button
                          onClick={() => handleOpenReportDetails(r.id)}
                          className="p-1.5 bg-slate-800 hover:bg-indigo-600/30 text-indigo-400 rounded transition"
                          title="عرض التقرير الجنائي الكامل"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleToggleQuarantine(r.id, !!r.is_quarantined)}
                          className={`p-1.5 rounded transition ${
                            r.is_quarantined
                              ? 'bg-emerald-950 hover:bg-emerald-900 text-emerald-400'
                              : 'bg-pink-950 hover:bg-pink-900 text-pink-400'
                          }`}
                          title={r.is_quarantined ? 'فك الحجز' : 'حجز الرسالة'}
                        >
                          <Lock className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Report Details Modal */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-5xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl">
                  <Mail className="w-6 h-6 text-indigo-400" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-lg font-bold text-white">التقرير الجنائي الموسع للرسالة</h3>
                    <span className="font-mono text-xs text-slate-500">[{selectedReport.id}]</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {selectedReport.parsed_email.subject || '(بدون عنوان)'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                {getVerdictBadge(selectedReport.verdict)}
                <button
                  onClick={() => setSelectedReport(null)}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
                >
                  <XCircle className="w-6 h-6" />
                </button>
              </div>
            </div>

            {/* Modal Tabs */}
            <div className="flex items-center gap-2 px-6 pt-3 bg-slate-950/30 border-b border-slate-800 text-xs overflow-x-auto">
              <button
                onClick={() => setActiveTab('overview')}
                className={`pb-2.5 px-3 font-semibold border-b-2 transition ${
                  activeTab === 'overview' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                نظرة عامة والترويسات
              </button>
              <button
                onClick={() => setActiveTab('findings')}
                className={`pb-2.5 px-3 font-semibold border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'findings' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                المؤشرات الأمنية ({selectedReport.findings?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('urls')}
                className={`pb-2.5 px-3 font-semibold border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'urls' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                الروابط ({selectedReport.parsed_email?.urls?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('attachments')}
                className={`pb-2.5 px-3 font-semibold border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'attachments' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                المرفقات ({selectedReport.parsed_email?.attachments?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('hops')}
                className={`pb-2.5 px-3 font-semibold border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'hops' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                مسار التوجيه (Hops: {selectedReport.parsed_email?.hops?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('playbook')}
                className={`pb-2.5 px-3 font-semibold border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'playbook' ? 'border-indigo-500 text-indigo-400' : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                خطة الاستجابة (SOC Playbook)
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
              {/* Tab: Overview */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Score & Risk Banner */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <div>
                        <div className="text-slate-400 text-[11px]">مؤشر التهديد الإجمالي</div>
                        <div className="text-2xl font-black text-white mt-1">{selectedReport.overall_score} / 100</div>
                      </div>
                      <div className={`p-3 rounded-xl border ${getScoreColor(selectedReport.overall_score)}`}>
                        <ShieldAlert className="w-5 h-5" />
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="text-slate-400 text-[11px]">مصادقة SPF</div>
                      <div className="mt-1 flex items-center gap-1.5 font-bold uppercase text-white">
                        {selectedReport.parsed_email.auth_results?.spf_status === 'pass' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400" />
                        )}
                        {selectedReport.parsed_email.auth_results?.spf_status || 'NONE'}
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="text-slate-400 text-[11px]">توقيع DKIM المشفر</div>
                      <div className="mt-1 flex items-center gap-1.5 font-bold uppercase text-white">
                        {selectedReport.parsed_email.auth_results?.dkim_status === 'pass' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400" />
                        )}
                        {selectedReport.parsed_email.auth_results?.dkim_status || 'NONE'}
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
                      <div className="text-slate-400 text-[11px]">سياسة DMARC</div>
                      <div className="mt-1 flex items-center gap-1.5 font-bold uppercase text-white">
                        {selectedReport.parsed_email.auth_results?.dmarc_status === 'pass' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400" />
                        )}
                        {selectedReport.parsed_email.auth_results?.dmarc_status || 'NONE'}
                      </div>
                    </div>
                  </div>

                  {/* Metadata Card */}
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                    <h4 className="font-bold text-white text-sm">بيانات الترويسة والمرسل</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <span className="text-slate-500">المرسل (From):</span>
                        <div className="text-slate-200 font-mono mt-0.5">
                          {selectedReport.parsed_email.sender_name} &lt;{selectedReport.parsed_email.sender_address}&gt;
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-500">المستلم (To):</span>
                        <div className="text-slate-200 font-mono mt-0.5">
                          {selectedReport.parsed_email.to?.join(', ') || '(فارغ)'}
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-500">عنوان الرد (Reply-To):</span>
                        <div className="text-slate-200 font-mono mt-0.5">
                          {selectedReport.parsed_email.reply_to || '(مطابق للمرسل)'}
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-500">معرف الرسالة (Message-ID):</span>
                        <div className="text-slate-200 font-mono mt-0.5 truncate">
                          {selectedReport.parsed_email.message_id || 'N/A'}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Digital Signature */}
                  <div className="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/30 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <Lock className="w-5 h-5 text-indigo-400 shrink-0" />
                      <div>
                        <div className="font-bold text-indigo-300">الختم الرقمي المشفر للتقرير الجنائي (SHA-256 Seal)</div>
                        <div className="font-mono text-[11px] text-slate-400 truncate max-w-xl">
                          {selectedReport.digital_signature}
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={() => copySignature(selectedReport.digital_signature)}
                      className="flex items-center gap-1 px-3 py-1.5 bg-indigo-900/40 hover:bg-indigo-900/60 border border-indigo-500/40 text-indigo-200 rounded-lg transition shrink-0"
                    >
                      {copiedSig ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedSig ? 'تم النسخ' : 'نسخ الختم'}
                    </button>
                  </div>
                </div>
              )}

              {/* Tab: Findings */}
              {activeTab === 'findings' && (
                <div className="space-y-3">
                  {selectedReport.findings?.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 bg-slate-950 rounded-xl">
                      لم يتم تسجيل أي مؤشرات خطر أو انتهاكات أمنية في هذه الرسالة.
                    </div>
                  ) : (
                    selectedReport.findings?.map((f) => (
                      <div
                        key={f.id}
                        className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2 hover:border-slate-700 transition"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 bg-red-500/10 text-red-400 border border-red-500/30 rounded text-[10px] font-bold uppercase">
                              {f.severity}
                            </span>
                            <span className="font-bold text-white">{f.title_ar || f.title}</span>
                          </div>
                          {f.mitre_technique && (
                            <span className="px-2 py-0.5 bg-purple-500/10 text-purple-300 border border-purple-500/30 rounded font-mono text-[10px]">
                              MITRE: {f.mitre_technique}
                            </span>
                          )}
                        </div>
                        <p className="text-slate-300 text-xs leading-relaxed">{f.description_ar || f.description}</p>
                        {f.evidence && (
                          <div className="p-2 bg-slate-900 rounded font-mono text-[11px] text-slate-400 border border-slate-800/60">
                            الدليل: {f.evidence}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab: URLs */}
              {activeTab === 'urls' && (
                <div className="space-y-3">
                  {selectedReport.parsed_email?.urls?.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 bg-slate-950 rounded-xl">
                      لا توجد روابط خارجية مستخرجة من محتوى البريد.
                    </div>
                  ) : (
                    <div className="overflow-x-auto border border-slate-800 rounded-xl">
                      <table className="w-full text-right">
                        <thead className="bg-slate-950 text-slate-400 font-semibold border-b border-slate-800">
                          <tr>
                            <th className="p-3">الرابط الحقيقي (Destination URL)</th>
                            <th className="p-3">النص الظاهر (Display Text)</th>
                            <th className="p-3">النطاق (Domain)</th>
                            <th className="p-3">التقييم</th>
                            <th className="p-3">المؤشرات</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {selectedReport.parsed_email?.urls?.map((u, idx) => (
                            <tr key={idx} className="hover:bg-slate-800/30">
                              <td className="p-3 font-mono text-indigo-300 max-w-xs truncate" dir="ltr">
                                {u.url}
                              </td>
                              <td className="p-3 text-slate-300">{u.display_text || '-'}</td>
                              <td className="p-3 font-mono text-slate-400">{u.domain}</td>
                              <td className="p-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                    u.category === 'phishing'
                                      ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                                  }`}
                                >
                                  {u.category}
                                </span>
                              </td>
                              <td className="p-3 text-slate-400 text-[11px]">
                                {u.threat_flags?.join(' | ') || 'سليم'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Attachments */}
              {activeTab === 'attachments' && (
                <div className="space-y-3">
                  {selectedReport.parsed_email?.attachments?.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 bg-slate-950 rounded-xl">
                      لا توجد مرفقات مرتبطة بهذه الرسالة.
                    </div>
                  ) : (
                    selectedReport.parsed_email?.attachments?.map((a, idx) => (
                      <div key={idx} className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 font-bold text-white">
                            <FileWarning className="w-4 h-4 text-amber-400" />
                            <span>{a.filename}</span>
                            <span className="text-slate-500 text-[11px]">({(a.size_bytes / 1024).toFixed(1)} KB)</span>
                          </div>
                          {a.is_dangerous_type && (
                            <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/40 rounded text-[10px] font-bold">
                              امتداد عالي الخطورة
                            </span>
                          )}
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-400 font-mono text-[11px]">
                          <div>MIME Type: {a.content_type}</div>
                          <div>Entropy: {a.entropy}</div>
                          <div className="col-span-2 truncate">SHA-256: {a.sha256}</div>
                        </div>

                        {a.findings?.length > 0 && (
                          <div className="p-2 bg-red-950/20 border border-red-500/20 rounded text-red-300 text-xs">
                            {a.findings.join(' • ')}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab: Hops */}
              {activeTab === 'hops' && (
                <div className="space-y-3">
                  {selectedReport.parsed_email?.hops?.length === 0 ? (
                    <div className="p-8 text-center text-slate-500 bg-slate-950 rounded-xl">
                      لا توجد بيانات مسار توجيه (Received Headers) مسجلة.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {selectedReport.parsed_email?.hops?.map((hop) => (
                        <div key={hop.hop_number} className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex items-start gap-3">
                          <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg font-mono font-bold">
                            #{hop.hop_number}
                          </div>
                          <div className="space-y-1 flex-1 font-mono text-[11px]">
                            <div className="text-white font-semibold">From: {hop.from_host || 'N/A'}</div>
                            <div className="text-slate-400">By: {hop.by_host || 'N/A'}</div>
                            {hop.source_ip && <div className="text-indigo-300">IP: {hop.source_ip}</div>}
                            <div className="text-slate-500 text-[10px]">{hop.timestamp}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Playbook */}
              {activeTab === 'playbook' && (
                <div className="space-y-3">
                  <div className="p-4 bg-indigo-950/30 border border-indigo-500/30 rounded-xl text-indigo-200">
                    <h4 className="font-bold text-sm mb-1">إجراءات الاستجابة الآلية الموصى بها (SOC Remediation Playbook)</h4>
                    <p className="text-xs text-indigo-300/80">
                      بناءً على نتيجة التحليل الجنائي وتصنيف الخطورة، يُوصى بتنفيذ الإجراءات التالية لاحتواء التهديد:
                    </p>
                  </div>

                  {selectedReport.remediation_playbook?.map((step) => (
                    <div key={step.step} className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-white text-xs">
                          {step.step}
                        </div>
                        <div>
                          <div className="font-bold text-white text-xs">{step.title_ar || step.title_en}</div>
                          <div className="text-slate-500 text-[10px] font-mono">{step.action}</div>
                        </div>
                      </div>

                      <span className="px-2 py-1 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        {step.automated ? 'آلي (Automated)' : 'يدوي (Manual)'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Modal Footer Controls */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleToggleQuarantine(selectedReport.id, !!selectedReport.is_quarantined)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg font-bold text-xs transition ${
                    selectedReport.is_quarantined
                      ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                      : 'bg-pink-600 hover:bg-pink-500 text-white shadow-lg shadow-pink-600/20'
                  }`}
                >
                  <Lock className="w-3.5 h-3.5" />
                  {selectedReport.is_quarantined ? 'فك الحجز واستعادة البريد' : 'حجز وعزل الرسالة فوراً'}
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSelectedReport(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition"
                >
                  إغلاق النافذة
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
