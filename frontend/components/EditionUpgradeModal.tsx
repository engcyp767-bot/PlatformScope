'use client';

import React, { useEffect, useState } from 'react';
import {
  Shield,
  CheckCircle2,
  XCircle,
  Sparkles,
  Zap,
  Building2,
  Lock,
  ArrowRight,
  Download,
  KeyRound,
  FileCheck2,
  X,
  ExternalLink,
} from 'lucide-react';
import { useTranslation } from '../lib/i18n';
import { fetchApi } from '../lib/api';

interface EditionFeature {
  name: string;
  display_name_ar: string;
  display_name_en: string;
  category: string;
  available: boolean;
  daily_limit?: number | null;
  item_limit?: number | null;
  limit_display: string;
}

interface EditionTier {
  edition: string;
  tier: number;
  is_current: boolean;
  features: EditionFeature[];
}

interface EditionInfo {
  edition: string;
  license: any;
  usage_summary: any;
  gcc_compliance: {
    nca_ecc: boolean;
    sama_csf: boolean;
    pdpl_ready: boolean;
    offline_airgapped_certified: boolean;
  };
}

export function EditionUpgradeModal({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const { t, lang } = useTranslation();
  const [editionInfo, setEditionInfo] = useState<EditionInfo | null>(null);
  const [comparison, setComparison] = useState<EditionTier[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'comparison' | 'compliance' | 'activation'>('comparison');
  const [licenseKeyInput, setLicenseKeyInput] = useState('');
  const [activateMsg, setActivateMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [isActivating, setIsActivating] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      Promise.all([
        fetchApi('/api/v1/edition').catch(() => null),
        fetchApi('/api/v1/features').catch(() => null),
      ]).then(([edRes, featRes]) => {
        if (edRes?.data) setEditionInfo(edRes.data);
        if (featRes?.data?.edition_comparison) setComparison(featRes.data.edition_comparison);
        setLoading(false);
      });
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleActivateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!licenseKeyInput.trim()) return;
    setIsActivating(true);
    setActivateMsg(null);
    try {
      const res = await fetchApi('/api/licensing/activate', {
        method: 'POST',
        body: JSON.stringify({ license_key: licenseKeyInput.trim() }),
      });
      if (res?.success) {
        setActivateMsg({
          type: 'success',
          text: lang === 'ar' ? 'تم تفعيل الترخيص بنجاح! جاري تحديث الصلاحيات...' : 'License activated successfully! Refreshing...',
        });
        setTimeout(() => {
          window.location.reload();
        }, 1500);
      } else {
        setActivateMsg({
          type: 'error',
          text: res?.error?.message || (lang === 'ar' ? 'مفتاح الترخيص غير صالح أو منتهي الصلاحية' : 'Invalid or expired license key'),
        });
      }
    } catch (err: any) {
      setActivateMsg({
        type: 'error',
        text: err.message || (lang === 'ar' ? 'حدث خطأ أثناء التفعيل' : 'Activation error occurred'),
      });
    } finally {
      setIsActivating(false);
    }
  };

  const currentEdition = editionInfo?.edition || 'Community';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-5xl max-h-[90vh] overflow-hidden rounded-2xl border border-border/80 bg-card shadow-2xl flex flex-col">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border/60 px-6 py-4 bg-muted/20">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 border border-primary/20 text-primary">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                {lang === 'ar' ? 'طبعات منصة Platform Scope والترقية' : 'Platform Scope Editions & Upgrade'}
                <span className="inline-flex items-center rounded-full bg-primary/15 px-2.5 py-0.5 text-xs font-semibold text-primary border border-primary/25 uppercase">
                  {currentEdition}
                </span>
              </h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                {lang === 'ar'
                  ? 'اختر الطبعة المناسبة لاحتياجات مركز العمليات الأمنية (SOC) والامتثال الوطني'
                  : 'Choose the optimal tier for your SOC operations and GCC regulatory compliance'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-muted-foreground hover:bg-muted/40 hover:text-foreground transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-1 border-b border-border/40 px-6 pt-3 bg-muted/10">
          <button
            onClick={() => setActiveTab('comparison')}
            className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === 'comparison'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <Zap className="h-4 w-4" />
            {lang === 'ar' ? 'مقارنة الباقات والميزات' : 'Edition Matrix & Features'}
          </button>
          <button
            onClick={() => setActiveTab('compliance')}
            className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === 'compliance'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <FileCheck2 className="h-4 w-4" />
            {lang === 'ar' ? 'الامتثال الوطني والمعايير' : 'GCC Compliance Certifications'}
          </button>
          <button
            onClick={() => setActiveTab('activation')}
            className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === 'activation'
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            <KeyRound className="h-4 w-4" />
            {lang === 'ar' ? 'تفعيل مفتاح الترخيص (Offline)' : 'Activate License Key'}
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {loading ? (
            <div className="flex h-64 items-center justify-center">
              <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            </div>
          ) : activeTab === 'comparison' ? (
            <div className="space-y-6">
              {/* Tiers Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* 1. Community */}
                <div className={`rounded-xl border p-4 flex flex-col justify-between transition-all ${
                  currentEdition.toLowerCase() === 'community'
                    ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
                    : 'border-border/60 bg-card/60'
                }`}>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                        {lang === 'ar' ? 'مجتمعية' : 'Community'}
                      </span>
                      {currentEdition.toLowerCase() === 'community' && (
                        <span className="rounded bg-primary/20 text-primary text-[10px] font-bold px-1.5 py-0.5">
                          {lang === 'ar' ? 'الحالية' : 'Current'}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 text-2xl font-black text-foreground">
                      {lang === 'ar' ? 'مجاناً' : 'Free'}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {lang === 'ar' ? 'مفتوحة المصدر للمطورين والباحثين الأمنيين' : 'Open core for researchers and developers'}
                    </p>
                    <div className="mt-4 space-y-2 text-xs">
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>FlowScope / LogScope / ThreatScope</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? '50 قاعدة كشف Sigma' : '50 Sigma rules'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'حتى 10 حوادث أمنية' : 'Up to 10 incidents'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground/60">
                        <XCircle className="h-3.5 w-3.5 text-muted-foreground/40" />
                        <span>{lang === 'ar' ? 'EndpointScope (EDR)' : 'EndpointScope EDR'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground/60">
                        <XCircle className="h-3.5 w-3.5 text-muted-foreground/40" />
                        <span>{lang === 'ar' ? 'تصدير الحزم الجنائية' : 'Forensic Case Export'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Standard */}
                <div className={`rounded-xl border p-4 flex flex-col justify-between transition-all ${
                  currentEdition.toLowerCase() === 'standard'
                    ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
                    : 'border-border/60 bg-card/60'
                }`}>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">
                        {lang === 'ar' ? 'قياسية' : 'Standard'}
                      </span>
                      {currentEdition.toLowerCase() === 'standard' && (
                        <span className="rounded bg-blue-500/20 text-blue-400 text-[10px] font-bold px-1.5 py-0.5">
                          {lang === 'ar' ? 'الحالية' : 'Current'}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 text-2xl font-black text-foreground">
                      {lang === 'ar' ? 'للشركات الصغيرة' : 'SMB'}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {lang === 'ar' ? 'للفرق الأمنية والشركات التي تبدأ بناء SOC' : 'For small teams starting their SOC'}
                    </p>
                    <div className="mt-4 space-y-2 text-xs">
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? '100,000 حدث / يوم' : '100k events / day'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'الارتباط الرسومي Graph' : 'Graph Correlation'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'مساعد الذكاء الاصطناعي (50/يوم)' : 'AI Copilot (50/day)'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'تقارير رسمية DOCX/XLSX' : 'DOCX/XLSX Reports'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-muted-foreground/60">
                        <XCircle className="h-3.5 w-3.5 text-muted-foreground/40" />
                        <span>{lang === 'ar' ? 'EndpointScope (EDR)' : 'EndpointScope EDR'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 3. Professional (Recommended) */}
                <div className={`rounded-xl border-2 p-4 flex flex-col justify-between relative transition-all shadow-lg ${
                  currentEdition.toLowerCase() === 'professional'
                    ? 'border-amber-400 bg-amber-500/10 ring-2 ring-amber-400/30'
                    : 'border-amber-500/50 bg-amber-500/5'
                }`}>
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-gradient-to-r from-amber-500 to-orange-500 px-2.5 py-0.5 text-[10px] font-bold text-white shadow">
                    {lang === 'ar' ? 'الأكثر طلباً للـ SOC' : 'Most Popular SOC'}
                  </div>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">
                        {lang === 'ar' ? 'احترافية' : 'Professional'}
                      </span>
                      {currentEdition.toLowerCase() === 'professional' && (
                        <span className="rounded bg-amber-500/20 text-amber-400 text-[10px] font-bold px-1.5 py-0.5">
                          {lang === 'ar' ? 'الحالية' : 'Current'}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 text-2xl font-black text-foreground">
                      {lang === 'ar' ? 'مراكز SOC' : 'SOC Edition'}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {lang === 'ar' ? 'تحقيق جنائي رقمي كامل مع نقاط النهاية' : 'Full digital forensics with EDR'}
                    </p>
                    <div className="mt-4 space-y-2 text-xs">
                      <div className="flex items-center gap-1.5 text-foreground/90 font-medium text-amber-300">
                        <Sparkles className="h-3.5 w-3.5 text-amber-400" />
                        <span>{lang === 'ar' ? 'EndpointScope (حتى 500 جهاز)' : 'EndpointScope (500 agents)'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'تصدير حزم جنائية رقمية موثقة' : 'Signed Case Packages'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'واجهة REST API العامة' : 'Public REST API'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'قواعد Sigma غير محدودة' : 'Unlimited Sigma rules'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 4. Enterprise */}
                <div className={`rounded-xl border p-4 flex flex-col justify-between transition-all ${
                  currentEdition.toLowerCase() === 'enterprise'
                    ? 'border-primary bg-primary/5 ring-1 ring-primary/30'
                    : 'border-purple-500/40 bg-purple-500/5'
                }`}>
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-purple-400 uppercase tracking-wider">
                        {lang === 'ar' ? 'المؤسسات والحكومة' : 'Enterprise'}
                      </span>
                      {currentEdition.toLowerCase() === 'enterprise' && (
                        <span className="rounded bg-purple-500/20 text-purple-400 text-[10px] font-bold px-1.5 py-0.5">
                          {lang === 'ar' ? 'الحالية' : 'Current'}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 text-2xl font-black text-foreground">
                      {lang === 'ar' ? 'غير محدود' : 'Unlimited'}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {lang === 'ar' ? 'للجهات الحكومية والبيئات المعزولة Air-Gapped' : 'For Government & Air-Gapped environments'}
                    </p>
                    <div className="mt-4 space-y-2 text-xs">
                      <div className="flex items-center gap-1.5 text-purple-300 font-medium">
                        <Building2 className="h-3.5 w-3.5 text-purple-400" />
                        <span>{lang === 'ar' ? 'تعدد المستأجرين Multi-Tenancy' : 'Multi-Tenancy'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'وكلاء EndpointScope غير محدودين' : 'Unlimited EDR agents'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'عزل كامل Air-Gap بدون إنترنت' : '100% Offline Air-Gapped'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 text-foreground/90">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>{lang === 'ar' ? 'دعم فني وتكامل مخصص 24/7' : '24/7 Custom Integration'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Call to action */}
              <div className="rounded-xl border border-border/80 bg-muted/20 p-4 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div>
                  <h4 className="font-semibold text-foreground text-sm">
                    {lang === 'ar' ? 'هل تحتاج إلى ترخيص مخصص أو تجربة معزولة (POC)؟' : 'Need an On-Premise Evaluation License (POC)?'}
                  </h4>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {lang === 'ar'
                      ? 'نوفر تراخيص محلية مخصصة للجهات الحكومية والشركات الخليجية متوافقة 100% مع ضوابط الأمن السيبراني.'
                      : 'We provide dedicated offline licenses for GCC enterprises aligned with NCA & SAMA requirements.'}
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('activation')}
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow hover:bg-primary/90 transition-colors whitespace-nowrap"
                >
                  <KeyRound className="h-4 w-4" />
                  {lang === 'ar' ? 'إدخال مفتاح الترخيص' : 'Enter License Key'}
                </button>
              </div>
            </div>
          ) : activeTab === 'compliance' ? (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* NCA ECC */}
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold">
                    <CheckCircle2 className="h-5 w-5" />
                    <span>NCA ECC-1:2018 (الهيئة الوطنية للأمن السيبراني)</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {lang === 'ar'
                      ? 'مطابقة تامة لضوابط حماية البيانات، تشفير السجلات الجنائية، والتحكم بالوصول المبني على الأدوار (RBAC).'
                      : 'Fully compliant with Essential Cybersecurity Controls for data protection and cryptographically signed audit logs.'}
                  </p>
                </div>

                {/* SAMA CSF */}
                <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-blue-400 font-bold">
                    <CheckCircle2 className="h-5 w-5" />
                    <span>SAMA Cyber Security Framework (البنك المركزي السعودي)</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {lang === 'ar'
                      ? 'جاهزية كاملة لمتطلبات القطاع المالي والمصرفي لعزل التهديدات والتحقيق الجنائي الفوري.'
                      : 'Ready for financial sector incident response, threat containment, and zero data leakage.'}
                  </p>
                </div>

                {/* PDPL */}
                <div className="rounded-xl border border-purple-500/30 bg-purple-500/5 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-purple-400 font-bold">
                    <CheckCircle2 className="h-5 w-5" />
                    <span>نظام حماية البيانات الشخصية (PDPL)</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {lang === 'ar'
                      ? 'جميع البيانات والسجلات واللقطات الأمنية تخزن محلياً داخل خادم العميل دون خروج أي بايت للسحابة.'
                      : 'Zero cloud telemetry. All investigation artifacts remain inside sovereign local boundaries.'}
                  </p>
                </div>

                {/* Air-Gapped */}
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-2">
                  <div className="flex items-center gap-2 text-amber-400 font-bold">
                    <CheckCircle2 className="h-5 w-5" />
                    <span>100% Offline Air-Gapped Architecture</span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {lang === 'ar'
                      ? 'تشفير غير متصل بالمفاتيح التشفيرية RSA/Ed25519 دون الحاجة لأي اتصال بالإنترنت.'
                      : 'Asymmetric offline licensing validation requiring no outbound internet access.'}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="max-w-xl mx-auto space-y-6 py-4">
              <div className="text-center space-y-2">
                <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary border border-primary/20">
                  <KeyRound className="h-6 w-6" />
                </div>
                <h3 className="text-lg font-bold text-foreground">
                  {lang === 'ar' ? 'تفعيل ترخيص المنصة المحلي' : 'Activate Local Offline License'}
                </h3>
                <p className="text-xs text-muted-foreground">
                  {lang === 'ar'
                    ? 'أدخل مفتاح الترخيص الرقمي الموقع تشفيرياً بصيغة JSON أو كود التفعيل المعتمد'
                    : 'Paste your digitally signed offline license key to unlock your edition'}
                </p>
              </div>

              <form onSubmit={handleActivateKey} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-foreground/80 mb-1.5">
                    {lang === 'ar' ? 'مفتاح الترخيص (License Key / Token)' : 'License Key'}
                  </label>
                  <textarea
                    rows={4}
                    value={licenseKeyInput}
                    onChange={(e) => setLicenseKeyInput(e.target.value)}
                    placeholder={lang === 'ar' ? 'الصق كود الترخيص هنا...' : 'Paste license code here...'}
                    className="w-full rounded-xl border border-border/80 bg-background/80 p-3 text-xs font-mono text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
                    required
                  />
                </div>

                {activateMsg && (
                  <div className={`p-3 rounded-xl text-xs font-medium ${
                    activateMsg.type === 'success'
                      ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                      : 'bg-red-500/10 border border-red-500/30 text-red-400'
                  }`}>
                    {activateMsg.text}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isActivating}
                  className="w-full flex items-center justify-center gap-2 rounded-xl bg-primary py-2.5 text-xs font-bold text-primary-foreground shadow hover:bg-primary/90 transition-colors disabled:opacity-60"
                >
                  {isActivating ? (
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                  ) : (
                    <>
                      <KeyRound className="h-4 w-4" />
                      {lang === 'ar' ? 'تفعيل الترخيص الآن' : 'Activate License Now'}
                    </>
                  )}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
