'use client';

import React, { useEffect, useState } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Award,
  CheckCircle2,
  AlertTriangle,
  FileText,
  RotateCw,
  Search,
  ExternalLink,
  Lock,
  Sparkles,
  TrendingUp,
  Download,
  AlertCircle,
  HelpCircle,
  Clock,
  Layers,
  Check,
  ChevronDown,
  ChevronRight,
  Database,
  Server,
  Activity,
  Cpu,
} from 'lucide-react';
import { useTranslation } from '../../lib/i18n';
import { fetchApi } from '../../lib/api';
import { EditionUpgradeModal } from '../../components/EditionUpgradeModal';

interface Control {
  control_id: string;
  framework_id: string;
  domain_id: string;
  title_ar: string;
  title_en: string;
  description_ar: string;
  description_en: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  status: 'compliant' | 'partially_compliant' | 'non_compliant' | 'not_applicable' | 'pending_review';
  score_weight: number;
  evaluation_notes: string;
  remediation_guidance_ar: string;
  remediation_guidance_en: string;
  evidence_items?: Array<{
    source_component: string;
    evidence_type: string;
    description: string;
    is_automated: boolean;
  }>;
}

interface Domain {
  domain_id: string;
  name_ar: string;
  name_en: string;
  description_ar: string;
  description_en: string;
  controls_count: number;
  compliance_score: number;
  controls: Control[];
}

interface Framework {
  framework_id: string;
  name_ar: string;
  name_en: string;
  version: string;
  authority_ar: string;
  authority_en: string;
  description_ar: string;
  description_en: string;
  total_controls: number;
  overall_score: number;
  domains: Domain[];
}

interface GapItem {
  control_id: string;
  framework_id: string;
  title_ar: string;
  title_en: string;
  domain_name_ar: string;
  domain_name_en: string;
  current_status: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  findings_ar: string;
  findings_en: string;
  remediation_action_ar: string;
  remediation_action_en: string;
  estimated_effort_days: number;
}

export default function ComplianceScopePage() {
  const { t, lang } = useTranslation();
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [selectedFwId, setSelectedFwId] = useState<string>('nca_ecc_1_2018');
  const [overallScore, setOverallScore] = useState<number>(0);
  const [totalGaps, setTotalGaps] = useState<number>(0);
  const [criticalGaps, setCriticalGaps] = useState<number>(0);
  const [highGaps, setHighGaps] = useState<number>(0);
  const [gaps, setGaps] = useState<GapItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [assessing, setAssessing] = useState(false);
  const [activeTab, setActiveTab] = useState<'frameworks' | 'gaps' | 'evidence'>('frameworks');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);

  // Upgrade Modal
  const [upgradeModalOpen, setUpgradeModalOpen] = useState(false);
  const [featureLocked, setFeatureLocked] = useState(false);

  const loadComplianceData = async () => {
    setLoading(true);
    try {
      const res = await fetchApi('/api/v1/compliance/assess', { method: 'POST' });
      if (res?.success && res?.data) {
        setFrameworks(res.data.frameworks || []);
        setOverallScore(res.data.overall_posture_score || 0);
        setTotalGaps(res.data.total_gaps || 0);
        setCriticalGaps(res.data.critical_gaps || 0);
        setHighGaps(res.data.high_gaps || 0);
        setGaps(res.data.gaps || []);
        setFeatureLocked(false);
        if (res.data.frameworks?.[0] && !selectedFwId) {
          setSelectedFwId(res.data.frameworks[0].framework_id);
        }
      } else if (res?.error?.code === 'FEATURE_LOCKED') {
        setFeatureLocked(true);
      }
    } catch (err: any) {
      if (err?.code === 'FEATURE_LOCKED' || err?.message?.includes('FEATURE_LOCKED')) {
        setFeatureLocked(true);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadComplianceData();
  }, []);

  const handleRunAssessment = async () => {
    setAssessing(true);
    try {
      const res = await fetchApi('/api/v1/compliance/assess', { method: 'POST' });
      if (res?.success && res?.data) {
        setFrameworks(res.data.frameworks || []);
        setOverallScore(res.data.overall_posture_score || 0);
        setTotalGaps(res.data.total_gaps || 0);
        setCriticalGaps(res.data.critical_gaps || 0);
        setHighGaps(res.data.high_gaps || 0);
        setGaps(res.data.gaps || []);
      }
    } catch (err) {
      console.error('Assessment failed', err);
    } finally {
      setAssessing(false);
    }
  };

  const selectedFramework = frameworks.find((f) => f.framework_id === selectedFwId) || frameworks[0];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'compliant':
        return {
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
          label: lang === 'ar' ? 'ممتثل 100%' : 'Compliant',
          icon: CheckCircle2,
        };
      case 'partially_compliant':
        return {
          bg: 'bg-amber-500/10 text-amber-400 border-amber-500/25',
          label: lang === 'ar' ? 'ممتثل جزئياً' : 'Partially Compliant',
          icon: AlertTriangle,
        };
      case 'non_compliant':
        return {
          bg: 'bg-rose-500/10 text-rose-400 border-rose-500/25',
          label: lang === 'ar' ? 'غير ممتثل' : 'Non-Compliant',
          icon: ShieldAlert,
        };
      default:
        return {
          bg: 'bg-slate-500/10 text-slate-400 border-slate-500/25',
          label: lang === 'ar' ? 'قيد المراجعة' : 'Pending',
          icon: Clock,
        };
    }
  };

  const getPriorityBadge = (p: string) => {
    switch (p) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* ── Top Header & Actions ──────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-dark-900/90 via-dark-900/60 to-dark-950/80 border border-white/10 rounded-2xl p-5 shadow-xl backdrop-blur-md">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/20 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/10 shrink-0">
            <Award className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-white tracking-wide">
                {lang === 'ar' ? 'إدارة الامتثال والضوابط السيبرانية (ComplianceScope)' : 'ComplianceScope — Regulatory Governance'}
              </h1>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 uppercase tracking-wider">
                NCA ECC & SAMA Ready
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              {lang === 'ar'
                ? 'التقييم المستمر وإدارة فجوات الامتثال للضوابط السعودية والخليجية (NCA ECC, SAMA CSF, PDPL, ISO 27001)'
                : 'Continuous automated compliance posture and gap assessment for Saudi & GCC cybersecurity mandates.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={handleRunAssessment}
            disabled={assessing || loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 text-xs font-bold transition-all shadow-md active:scale-95 disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${assessing ? 'animate-spin' : ''}`} />
            <span>{assessing ? (lang === 'ar' ? 'جاري الفحص الآلي...' : 'Assessing...') : (lang === 'ar' ? 'تشغيل فحص الامتثال اللحظي' : 'Run Live Assessment')}</span>
          </button>

          <button
            type="button"
            onClick={() => setUpgradeModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-purple-500/15 hover:bg-purple-500/25 border border-purple-500/30 text-purple-200 text-xs font-bold transition-all"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
            <span>{lang === 'ar' ? 'شهادات الاعتماد' : 'Certifications'}</span>
          </button>
        </div>
      </div>

      {/* ── Feature Locked Overlay (If Community Edition) ──────────────────────── */}
      {featureLocked && (
        <div className="p-6 rounded-2xl bg-gradient-to-br from-purple-950/40 via-dark-900 to-dark-950 border border-purple-500/30 text-center space-y-4 shadow-2xl">
          <div className="w-14 h-14 rounded-2xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300 mx-auto">
            <Lock className="w-7 h-7" />
          </div>
          <div className="max-w-xl mx-auto">
            <h2 className="text-lg font-bold text-white">
              {lang === 'ar' ? 'تطبيق ComplianceScope متاح في الطبعة الاحترافية (Professional)' : 'ComplianceScope is locked in Community Edition'}
            </h2>
            <p className="text-xs text-slate-300 mt-2 leading-relaxed">
              {lang === 'ar'
                ? 'يتطلب تقييم ضوابط الهيئة الوطنية للأمن السيبراني (NCA ECC) وإطار SAMA CSF ونظام PDPL الترقية إلى الطبعة الاحترافية أو المؤسسية مع دعم التقييم والتقارير التنفيذية.'
                : 'Compliance evaluation for NCA ECC, SAMA CSF, and PDPL frameworks is available in Professional and Enterprise editions.'}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setUpgradeModalOpen(true)}
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-primary text-white text-xs font-bold shadow-lg shadow-purple-500/20 hover:opacity-95 transition-all inline-flex items-center gap-2"
          >
            <Sparkles className="w-4 h-4" />
            <span>{lang === 'ar' ? 'استعراض الطبعات والترقية الفورية' : 'Upgrade Edition'}</span>
          </button>
        </div>
      )}

      {/* ── Executive Compliance Posture KPIs ─────────────────────────────────── */}
      {!featureLocked && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* KPI 1: Overall Posture Score */}
            <div className="p-4 rounded-2xl bg-dark-900/80 border border-white/10 flex items-center justify-between gap-4">
              <div>
                <span className="text-[11px] font-medium text-slate-400 block">
                  {lang === 'ar' ? 'مؤشر الامتثال السيبراني العام' : 'Overall Compliance Score'}
                </span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-2xl font-black text-emerald-400 tracking-tight">{overallScore}%</span>
                  <span className="text-[10px] text-emerald-400/80 font-bold bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    {lang === 'ar' ? 'جاهزية عالية' : 'High Posture'}
                  </span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                <TrendingUp className="w-6 h-6" />
              </div>
            </div>

            {/* KPI 2: Total Frameworks Assessed */}
            <div className="p-4 rounded-2xl bg-dark-900/80 border border-white/10 flex items-center justify-between gap-4">
              <div>
                <span className="text-[11px] font-medium text-slate-400 block">
                  {lang === 'ar' ? 'أطر العمل والتشريعات المفحوصة' : 'Active Frameworks'}
                </span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-2xl font-black text-white">{frameworks.length}</span>
                  <span className="text-[10px] text-purple-400 font-bold bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
                    NCA / SAMA / PDPL
                  </span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400 shrink-0">
                <Layers className="w-6 h-6" />
              </div>
            </div>

            {/* KPI 3: Total Controls Evaluated */}
            <div className="p-4 rounded-2xl bg-dark-900/80 border border-white/10 flex items-center justify-between gap-4">
              <div>
                <span className="text-[11px] font-medium text-slate-400 block">
                  {lang === 'ar' ? 'إجمالي الضوابط الأمنية' : 'Evaluated Controls'}
                </span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-2xl font-black text-blue-400">
                    {frameworks.reduce((acc, f) => acc + f.total_controls, 0)}
                  </span>
                  <span className="text-[10px] text-blue-400/80 font-bold bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/20">
                    100% {lang === 'ar' ? 'مفحوص' : 'Covered'}
                  </span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0">
                <ShieldCheck className="w-6 h-6" />
              </div>
            </div>

            {/* KPI 4: Critical & High Gaps */}
            <div className="p-4 rounded-2xl bg-dark-900/80 border border-white/10 flex items-center justify-between gap-4">
              <div>
                <span className="text-[11px] font-medium text-slate-400 block">
                  {lang === 'ar' ? 'الفجوات المعلقة للمعالجة' : 'Remediation Gaps'}
                </span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-2xl font-black text-amber-400">{totalGaps}</span>
                  <span className="text-[10px] text-rose-400 font-bold bg-rose-500/10 px-1.5 py-0.5 rounded border border-rose-500/20">
                    {criticalGaps} {lang === 'ar' ? 'حرجة' : 'Critical'}
                  </span>
                </div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                <AlertCircle className="w-6 h-6" />
              </div>
            </div>
          </div>

          {/* ── Main View Switcher (Frameworks vs Gaps) ─────────────────────────── */}
          <div className="flex items-center justify-between gap-3 border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setActiveTab('frameworks')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                  activeTab === 'frameworks'
                    ? 'bg-primary/20 border border-primary/40 text-primary shadow-sm'
                    : 'bg-white/5 border border-white/10 text-slate-300 hover:text-white'
                }`}
              >
                <Award className="w-4 h-4" />
                <span>{lang === 'ar' ? 'أطر وضوابط الامتثال' : 'Frameworks & Controls'}</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('gaps')}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                  activeTab === 'gaps'
                    ? 'bg-amber-500/20 border border-amber-500/40 text-amber-300 shadow-sm'
                    : 'bg-white/5 border border-white/10 text-slate-300 hover:text-white'
                }`}
              >
                <AlertTriangle className="w-4 h-4" />
                <span>{lang === 'ar' ? `فجوات المعالجة والتوصيات (${totalGaps})` : `Remediation Gaps (${totalGaps})`}</span>
              </button>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
              <input
                type="text"
                placeholder={lang === 'ar' ? 'بحث في الضوابط والفجوات...' : 'Search controls & gaps...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pr-8 pl-3 py-1.5 rounded-xl bg-dark-950 border border-white/10 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-primary w-48 sm:w-64"
              />
            </div>
          </div>

          {/* ── TAB 1: Frameworks & Controls Detail ─────────────────────────────── */}
          {activeTab === 'frameworks' && (
            <div className="space-y-6">
              {/* Framework Selector Pills */}
              <div className="flex items-center gap-2.5 overflow-x-auto pb-1">
                {frameworks.map((fw) => (
                  <button
                    key={fw.framework_id}
                    type="button"
                    onClick={() => setSelectedFwId(fw.framework_id)}
                    className={`flex items-center gap-2.5 px-4 py-3 rounded-xl border text-right transition-all shrink-0 ${
                      selectedFwId === fw.framework_id
                        ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200 shadow-md shadow-emerald-500/10'
                        : 'bg-white/5 border-white/10 text-slate-300 hover:bg-white/10'
                    }`}
                  >
                    <div className="flex flex-col">
                      <span className="text-xs font-bold">{lang === 'ar' ? fw.name_ar : fw.name_en}</span>
                      <span className="text-[10px] text-slate-400 mt-0.5">
                        {lang === 'ar' ? fw.authority_ar : fw.authority_en} • {fw.overall_score}% {lang === 'ar' ? 'امتثال' : 'Score'}
                      </span>
                    </div>
                  </button>
                ))}
              </div>

              {/* Selected Framework Banner */}
              {selectedFramework && (
                <div className="p-5 rounded-2xl bg-dark-900/60 border border-white/10 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h2 className="text-base font-bold text-white">
                        {lang === 'ar' ? selectedFramework.name_ar : selectedFramework.name_en}
                      </h2>
                      <p className="text-xs text-slate-400 mt-1 max-w-3xl">
                        {lang === 'ar' ? selectedFramework.description_ar : selectedFramework.description_en}
                      </p>
                    </div>
                    <div className="text-left sm:text-right shrink-0">
                      <span className="text-2xl font-black text-emerald-400">{selectedFramework.overall_score}%</span>
                      <span className="text-[10px] text-slate-400 block font-mono">
                        {selectedFramework.total_controls} {lang === 'ar' ? 'ضابطاً أمنياً' : 'Controls'}
                      </span>
                    </div>
                  </div>

                  {/* Domains and Controls Accordion */}
                  <div className="space-y-3 pt-2">
                    {selectedFramework.domains.map((domain) => {
                      const isExpanded = expandedDomain === domain.domain_id || expandedDomain === null;
                      return (
                        <div key={domain.domain_id} className="rounded-xl border border-white/10 bg-dark-950/60 overflow-hidden">
                          {/* Domain Header */}
                          <div
                            onClick={() => setExpandedDomain(expandedDomain === domain.domain_id ? null : domain.domain_id)}
                            className="p-4 flex items-center justify-between gap-3 cursor-pointer hover:bg-white/5 transition-colors"
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <span className="text-slate-400">
                                {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                              </span>
                              <div>
                                <span className="text-xs font-bold text-white block truncate">
                                  {lang === 'ar' ? domain.name_ar : domain.name_en}
                                </span>
                                <span className="text-[10px] text-slate-400">
                                  {domain.controls_count} {lang === 'ar' ? 'ضابطاً' : 'Controls'}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center gap-3 shrink-0">
                              <div className="w-24 bg-dark-800 rounded-full h-2 overflow-hidden hidden sm:block">
                                <div
                                  className="bg-emerald-400 h-full rounded-full transition-all"
                                  style={{ width: `${domain.compliance_score}%` }}
                                />
                              </div>
                              <span className="text-xs font-bold text-emerald-400 font-mono">
                                {domain.compliance_score}%
                              </span>
                            </div>
                          </div>

                          {/* Domain Controls List */}
                          {isExpanded && (
                            <div className="p-3 border-t border-white/5 space-y-2.5 bg-dark-900/40">
                              {domain.controls
                                .filter((c) =>
                                  !searchQuery ||
                                  c.title_ar.includes(searchQuery) ||
                                  c.title_en.toLowerCase().includes(searchQuery.toLowerCase()) ||
                                  c.control_id.toLowerCase().includes(searchQuery.toLowerCase())
                                )
                                .map((control) => {
                                  const statusInfo = getStatusBadge(control.status);
                                  const StatusIcon = statusInfo.icon;
                                  return (
                                    <div
                                      key={control.control_id}
                                      className="p-3.5 rounded-xl bg-dark-950 border border-white/5 space-y-2.5"
                                    >
                                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                        <div className="flex items-center gap-2.5 min-w-0">
                                          <span className="px-2 py-0.5 rounded bg-primary/10 border border-primary/25 font-mono text-[10px] font-bold text-primary shrink-0">
                                            {control.control_id}
                                          </span>
                                          <span className="text-xs font-bold text-white truncate">
                                            {lang === 'ar' ? control.title_ar : control.title_en}
                                          </span>
                                        </div>
                                        <div className="flex items-center gap-2 shrink-0">
                                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getPriorityBadge(control.priority)} uppercase`}>
                                            {control.priority}
                                          </span>
                                          <span className={`flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${statusInfo.bg}`}>
                                            <StatusIcon className="w-3 h-3" />
                                            <span>{statusInfo.label}</span>
                                          </span>
                                        </div>
                                      </div>

                                      <p className="text-[11px] text-slate-400 leading-relaxed">
                                        {lang === 'ar' ? control.description_ar : control.description_en}
                                      </p>

                                      {/* Automated Evidence Badges */}
                                      {control.evidence_items && control.evidence_items.length > 0 && (
                                        <div className="pt-2 border-t border-white/5 flex flex-wrap items-center gap-2">
                                          <span className="text-[10px] text-slate-500 flex items-center gap-1">
                                            <Sparkles className="w-3 h-3 text-emerald-400" />
                                            <span>{lang === 'ar' ? 'الأدلة التلقائية المجمعة:' : 'Automated Evidence:'}</span>
                                          </span>
                                          {control.evidence_items.map((ev, idx) => (
                                            <span
                                              key={idx}
                                              className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-[10px] font-medium text-emerald-300"
                                            >
                                              {ev.source_component}: {ev.description}
                                            </span>
                                          ))}
                                        </div>
                                      )}

                                      {/* Evaluation Notes */}
                                      {control.evaluation_notes && (
                                        <div className="text-[10px] text-slate-300 bg-white/5 p-2 rounded-lg font-mono">
                                          <span className="text-slate-400">{lang === 'ar' ? 'ملاحظات الفحص: ' : 'Evaluation: '}</span>
                                          {control.evaluation_notes}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── TAB 2: Remediation Gaps & Action Items ─────────────────────────── */}
          {activeTab === 'gaps' && (
            <div className="space-y-4">
              <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
                  <div>
                    <h3 className="text-xs font-bold text-amber-200">
                      {lang === 'ar' ? 'خطة المعالجة ذات الأولوية (Remediation Roadmap)' : 'Priority Remediation Action Plan'}
                    </h3>
                    <p className="text-[11px] text-amber-300/80 mt-0.5">
                      {lang === 'ar'
                        ? 'توضح هذه القائمة الإجراءات التصحيحية الفورية المطلوبة للوصول إلى نسبة امتثال 100% لضوابط NCA ECC و SAMA.'
                        : 'Actionable recommendations to achieve 100% full compliance posture.'}
                    </p>
                  </div>
                </div>
              </div>

              {gaps.length === 0 ? (
                <div className="p-8 text-center rounded-2xl bg-dark-900/60 border border-white/10 text-emerald-400 space-y-2">
                  <CheckCircle2 className="w-10 h-10 mx-auto" />
                  <h3 className="text-sm font-bold text-white">{lang === 'ar' ? 'تهانينا! لا توجد أي فجوات أمنية معلقة' : 'No compliance gaps detected'}</h3>
                  <p className="text-xs text-slate-400">{lang === 'ar' ? 'كافة الضوابط الأمنية محققة ومطابقة للأطر التنظيمية بنسبة 100%.' : 'All evaluated controls are fully compliant.'}</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-3.5">
                  {gaps
                    .filter((g) =>
                      !searchQuery ||
                      g.title_ar.includes(searchQuery) ||
                      g.title_en.toLowerCase().includes(searchQuery.toLowerCase()) ||
                      g.control_id.toLowerCase().includes(searchQuery.toLowerCase())
                    )
                    .map((gap) => (
                      <div
                        key={gap.control_id}
                        className="p-4 rounded-xl bg-dark-900/80 border border-white/10 space-y-3 hover:border-amber-500/30 transition-all"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="px-2 py-0.5 rounded bg-primary/10 border border-primary/25 font-mono text-[10px] font-bold text-primary shrink-0">
                              {gap.control_id}
                            </span>
                            <span className="text-xs font-bold text-white truncate">
                              {lang === 'ar' ? gap.title_ar : gap.title_en}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${getPriorityBadge(gap.priority)} uppercase`}>
                              {gap.priority}
                            </span>
                            <span className="text-[10px] text-slate-400 font-mono bg-white/5 px-2 py-0.5 rounded">
                              {lang === 'ar' ? `الجهد التقديري: ${gap.estimated_effort_days} أيام` : `Effort: ${gap.estimated_effort_days}d`}
                            </span>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                          <div className="p-3 rounded-lg bg-rose-500/5 border border-rose-500/15 text-rose-300 space-y-1">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-rose-400 block">
                              {lang === 'ar' ? 'النتائج والفجوة المكتشفة:' : 'Findings & Gap:'}
                            </span>
                            <p className="text-[11px] leading-relaxed">{lang === 'ar' ? gap.findings_ar : gap.findings_en}</p>
                          </div>

                          <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/15 text-emerald-300 space-y-1">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 block">
                              {lang === 'ar' ? 'الإجراء التصحيحي الموصى به:' : 'Recommended Action:'}
                            </span>
                            <p className="text-[11px] leading-relaxed">{lang === 'ar' ? gap.remediation_action_ar : gap.remediation_action_en}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Commercial Upgrade Modal ─────────────────────────────────────────── */}
      <EditionUpgradeModal
        isOpen={upgradeModalOpen}
        onClose={() => setUpgradeModalOpen(false)}
      />
    </div>
  );
}
