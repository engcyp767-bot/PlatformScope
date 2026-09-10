'use client';

import React, { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import {
  Shield,
  Activity,
  Cpu,
  RefreshCw,
  Download,
  Upload,
  Search,
  Filter,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Terminal,
  Server,
  Cloud,
  Database,
  Globe,
  Plus,
  Play,
  FileCode,
  BookOpen,
} from 'lucide-react';
import { Navbar } from '../../components/Navbar';
import { RuleDrawer } from '../../components/detections/RuleDrawer';
import { SigmaStudioModal } from '../../components/detections/SigmaStudioModal';
import { DetectionRule, DetectionSummary, User } from '../../lib/types';
import {
  getDetections,
  getDetectionsSummary,
  toggleDetectionRule,
  reloadDetectionRules,
  exportDetectionRules,
  importDetectionRules,
  getAuthStatus,
} from '../../lib/api';

const CATEGORIES = [
  { id: 'all', label: 'الكل (All Domains)', icon: Layers },
  { id: 'sigma', label: 'قواعد Sigma', icon: Cpu },
  { id: 'windows', label: 'Windows & AD', icon: Server },
  { id: 'network', label: 'الشبكة (Network)', icon: Globe },
  { id: 'malware', label: 'برمجيات خبيثة (Malware)', icon: Terminal },
  { id: 'cloud', label: 'السحابية (Cloud)', icon: Cloud },
  { id: 'database', label: 'قواعد البيانات (Database)', icon: Database },
];

export default function DetectionsPage() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [summary, setSummary] = useState<DetectionSummary | null>(null);
  const [loading, setLoading] = useState(true);

  // Filters
  const [activeCategory, setActiveCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [lifecycleFilter, setLifecycleFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  // Drawer state
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Sigma Studio modal state
  const [sigmaStudioOpen, setSigmaStudioOpen] = useState(false);

  // Actions state
  const [reloading, setReloading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);

  const fetchAllData = async () => {
    try {
      setLoading(true);
      const [userRes, detRes, sumRes] = await Promise.all([
        getAuthStatus(),
        getDetections({ category: activeCategory, limit: 150 }),
        getDetectionsSummary(),
      ]);
      if (userRes.authenticated && userRes.user) {
        setCurrentUser(userRes.user);
      }
      setRules(detRes.rules || []);
      setSummary(sumRes || detRes.summary || null);
    } catch (err: any) {
      console.error('Failed to load detections:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, [activeCategory]);

  const handleReload = async () => {
    try {
      setReloading(true);
      const res = await reloadDetectionRules();
      await fetchAllData();
      alert(`تمت إعادة تحميل ${res.count} قاعدة كشف بنجاح من القرص.`);
    } catch (err: any) {
      alert(err.message || 'فشل إعادة التحميل');
    } finally {
      setReloading(false);
    }
  };

  const handleExport = async () => {
    try {
      setExporting(true);
      const pkg = await exportDetectionRules();
      const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `detection_rules_pack_${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || 'فشل تصدير حزمة القواعد');
    } finally {
      setExporting(false);
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setImporting(true);
      const text = await file.text();
      const pkg = JSON.parse(text);
      const res = await importDetectionRules(pkg);
      if (res.success) {
        alert(`تم استيراد ${res.imported_count} قاعدة بنجاح مع التحقق من تجزئة SHA-256.`);
      } else {
        alert(`تم الاستيراد جزئياً: نجح ${res.imported_count}، فشل ${res.error_count} في فحص التجزئة.`);
      }
      await fetchAllData();
    } catch (err: any) {
      alert(err.message || 'فشل استيراد الحزمة: ملف غير صالح');
    } finally {
      setImporting(false);
      e.target.value = '';
    }
  };

  const handleToggle = async (ruleId: string, currentEnabled: boolean) => {
    try {
      const updated = await toggleDetectionRule(ruleId, !currentEnabled);
      setRules((prev) => prev.map((r) => (r.id === ruleId ? updated : r)));
      if (selectedRule?.id === ruleId) {
        setSelectedRule(updated);
      }
    } catch (err: any) {
      alert(err.message || 'فشل تبديل حالة القاعدة');
    }
  };

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matches =
          r.id.toLowerCase().includes(q) ||
          r.name.toLowerCase().includes(q) ||
          r.name_en.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          (r.tags || []).some((t) => t.toLowerCase().includes(q)) ||
          (r.mitre_attack?.techniques || []).some((tech) => tech.toLowerCase().includes(q));
        if (!matches) return false;
      }
      if (activeCategory === 'sigma') {
        const isSigma = r.source_format === 'sigma' || r.id.startsWith('SIGMA-') || (r.tags || []).includes('sigma') || r.category.toLowerCase() === 'sigma';
        if (!isSigma) return false;
      }
      if (severityFilter !== 'all' && r.severity.toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (lifecycleFilter !== 'all' && r.lifecycle.toLowerCase() !== lifecycleFilter.toLowerCase()) {
        return false;
      }
      if (statusFilter === 'active' && !r.enabled) return false;
      if (statusFilter === 'inactive' && r.enabled) return false;
      return true;
    });
  }, [rules, searchQuery, activeCategory, severityFilter, lifecycleFilter, statusFilter]);

  const canManage = currentUser?.permissions?.includes('detections.manage');

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">حرج</span>;
      case 'high':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/30">مرتفع</span>;
      case 'medium':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">متوسط</span>;
      case 'low':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">منخفض</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-700/20 text-slate-400 border border-slate-700">{sev}</span>;
    }
  };

  const getLifecycleBadge = (lifecycle: string) => {
    switch (lifecycle.toLowerCase()) {
      case 'production':
        return <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">Production</span>;
      case 'testing':
        return <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">Testing</span>;
      case 'development':
        return <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30">Development</span>;
      case 'deprecated':
        return <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-700/20 text-slate-400 border border-slate-700">Deprecated</span>;
      default:
        return <span className="px-2 py-0.5 rounded-md text-[11px] font-semibold bg-slate-700/20 text-slate-400 border border-slate-700">{lifecycle}</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-amber-500 selection:text-slate-950">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Top Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-6">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 to-orange-500 flex items-center justify-center shadow-lg shadow-amber-500/20 text-slate-950">
                <Cpu className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white tracking-wide flex items-center gap-2">
                  <span>هندسة قواعد الكشف الأمني</span>
                  <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-amber-500/15 text-amber-400 border border-amber-500/30">
                    Detection Engineering
                  </span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  محرك القواعد التصريحية المستقل، مصفوفة MITRE ATT&CK v14.1، وإدارة دورة حياة التهديدات مع محاكي الاختبارات التراجعية.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <Link
              href="/help#detection-engineering"
              className="px-3.5 py-2 rounded-xl bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-xs font-semibold text-amber-300 transition-colors flex items-center gap-1.5"
              title="فتح دليل هندسة الكشف واستوديو Sigma"
            >
              <BookOpen className="w-3.5 h-3.5 text-amber-400" />
              <span>دليل قواعد الكشف</span>
            </Link>

            <button
              type="button"
              onClick={() => setSigmaStudioOpen(true)}
              className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-purple-500/20 to-amber-500/20 hover:from-purple-500/30 hover:to-amber-500/30 border border-purple-500/30 text-xs font-semibold text-purple-200 transition-all flex items-center gap-1.5 shadow-md shadow-purple-500/10"
              title="استوديو Sigma: فحص التوافق، المحاكاة، ومعاينة المحول والاستيراد"
            >
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              <span>استوديو Sigma (Sigma Studio)</span>
            </button>

            <button
              type="button"
              onClick={handleReload}
              disabled={reloading}
              className="px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition-colors flex items-center gap-1.5"
              title="إعادة تحميل القواعد من القرص بدون إعادة تشغيل"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-primary ${reloading ? 'animate-spin' : ''}`} />
              <span>إعادة تحميل</span>
            </button>

            <button
              type="button"
              onClick={handleExport}
              disabled={exporting}
              className="px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition-colors flex items-center gap-1.5"
              title="تصدير حزمة القواعد مع ملف البيان وتجزئة SHA-256"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>تصدير الحزمة</span>
            </button>

            {canManage && (
              <label className="px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition-colors flex items-center gap-1.5 cursor-pointer">
                <Upload className="w-3.5 h-3.5 text-amber-400" />
                <span>{importing ? 'جاري الفحص...' : 'استيراد حزمة'}</span>
                <input type="file" accept=".json" onChange={handleImportFile} disabled={importing} className="hidden" />
              </label>
            )}
          </div>
        </div>

        {/* KPI Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 rounded-2xl bg-gradient-to-b from-white/5 to-white/[0.02] border border-white/10 shadow-lg">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">إجمالي القواعد</span>
              <div className="w-8 h-8 rounded-lg bg-amber-500/10 flex items-center justify-center text-amber-400">
                <Layers className="w-4 h-4" />
              </div>
            </div>
            <div className="text-3xl font-mono font-bold text-white mt-2">
              {summary?.total_rules?.toLocaleString('en-US') || rules.length}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
              <span>نشطة في الإنتاج:</span>
              <span className="text-emerald-400 font-bold font-mono">
                {summary?.by_lifecycle?.production || 0}
              </span>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-gradient-to-b from-white/5 to-white/[0.02] border border-white/10 shadow-lg">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">تغطية تكتيكات MITRE</span>
              <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                <Shield className="w-4 h-4" />
              </div>
            </div>
            <div className="text-3xl font-mono font-bold text-primary mt-2">
              {summary?.mitre_coverage?.tactics_count || 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
              <span>تقنيات مرصودة:</span>
              <span className="text-white font-bold font-mono">
                {summary?.mitre_coverage?.techniques_count || 0} ({summary?.mitre_coverage?.matrix_version || 'v14.1'})
              </span>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-gradient-to-b from-white/5 to-white/[0.02] border border-white/10 shadow-lg">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">كواشف التهديدات الحرجة</span>
              <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center text-red-400">
                <AlertTriangle className="w-4 h-4" />
              </div>
            </div>
            <div className="text-3xl font-mono font-bold text-red-400 mt-2">
              {summary?.by_severity?.critical || 0}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
              <span>مرتفعة:</span>
              <span className="text-orange-400 font-bold font-mono">
                {summary?.by_severity?.high || 0}
              </span>
            </div>
          </div>

          <div className="p-5 rounded-2xl bg-gradient-to-b from-white/5 to-white/[0.02] border border-white/10 shadow-lg">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">السجلات المفحوصة</span>
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                <Activity className="w-4 h-4" />
              </div>
            </div>
            <div className="text-3xl font-mono font-bold text-emerald-400 mt-2">
              {(summary?.telemetry?.total_evaluated_events || 0).toLocaleString('en-US')}
            </div>
            <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
              <span>تطابقات:</span>
              <span className="text-amber-400 font-bold font-mono">
                {(summary?.telemetry?.total_matches || 0).toLocaleString('en-US')}
              </span>
            </div>
          </div>
        </div>

        {/* Category Tabs */}
        <div className="border-b border-white/10">
          <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
            {CATEGORIES.map((cat) => {
              const Icon = cat.icon;
              const isActive = activeCategory === cat.id;
              return (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => setActiveCategory(cat.id)}
                  className={`px-4 py-2.5 rounded-xl text-xs font-medium transition-all flex items-center gap-2 whitespace-nowrap ${
                    isActive
                      ? 'bg-amber-500 text-slate-950 font-bold shadow-md shadow-amber-500/20'
                      : 'bg-white/5 text-slate-400 hover:bg-white/10 hover:text-slate-200'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{cat.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Search & Filter Toolbar */}
        <div className="p-4 rounded-2xl bg-slate-900/60 border border-white/10 flex flex-col md:flex-row items-center justify-between gap-3">
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="بحث بالمعرف، الاسم، التقنية، أو الوسم..."
              className="w-full pr-9 pl-3 py-2 rounded-xl bg-slate-950/80 border border-white/10 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-amber-400"
            />
          </div>

          <div className="flex items-center gap-2.5 w-full md:w-auto flex-wrap justify-end">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Filter className="w-3.5 h-3.5" />
              <span>تصفية:</span>
            </div>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-amber-400"
            >
              <option value="all">كافة مستويات الخطورة</option>
              <option value="critical">حرجة (Critical)</option>
              <option value="high">مرتفعة (High)</option>
              <option value="medium">متوسطة (Medium)</option>
              <option value="low">منخفضة (Low)</option>
            </select>

            <select
              value={lifecycleFilter}
              onChange={(e) => setLifecycleFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-amber-400"
            >
              <option value="all">كافة دورات الحياة</option>
              <option value="production">Production (إنتاج)</option>
              <option value="testing">Testing (اختبار)</option>
              <option value="development">Development (تطوير)</option>
              <option value="deprecated">Deprecated (موقوفة)</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-white/10 text-xs text-slate-200 focus:outline-none focus:border-amber-400"
            >
              <option value="all">كافة الحالات</option>
              <option value="active">مفعلة فقط (Active)</option>
              <option value="inactive">معطلة فقط (Inactive)</option>
            </select>
          </div>
        </div>

        {/* Rules Table */}
        <div className="rounded-2xl bg-slate-900/60 border border-white/10 overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead className="bg-slate-950/80 border-b border-white/10 text-slate-400">
                <tr>
                  <th className="py-3.5 px-4 font-semibold">المعرف</th>
                  <th className="py-3.5 px-4 font-semibold">اسم القاعدة وتصنيف التهديد</th>
                  <th className="py-3.5 px-4 font-semibold">الخطورة</th>
                  <th className="py-3.5 px-4 font-semibold">دورة الحياة</th>
                  <th className="py-3.5 px-4 font-semibold">مستوى الثقة</th>
                  <th className="py-3.5 px-4 font-semibold">تكتيكات وتقنيات MITRE</th>
                  <th className="py-3.5 px-4 font-semibold">المطابقات</th>
                  <th className="py-3.5 px-4 font-semibold">الحالة</th>
                  <th className="py-3.5 px-4 font-semibold text-center">الإجراءات</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {loading ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-400">
                      <div className="flex items-center justify-center gap-2">
                        <RefreshCw className="w-4 h-4 animate-spin text-primary" />
                        <span>جاري تحميل قواعد الكشف...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredRules.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-400">
                      لم يتم العثور على قواعد كشف تطابق معايير البحث الحالية.
                    </td>
                  </tr>
                ) : (
                  filteredRules.map((rule) => (
                    <tr
                      key={rule.id}
                      className="hover:bg-white/[0.02] transition-colors group cursor-pointer"
                      onClick={() => {
                        setSelectedRule(rule);
                        setDrawerOpen(true);
                      }}
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-amber-400 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span>{rule.id}</span>
                          {(rule.source_format === 'sigma' || rule.id.startsWith('SIGMA-')) && (
                            <span
                              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/15 text-purple-300 border border-purple-500/30"
                              title="قاعدة Sigma معيارية محولة عبر Adapter"
                            >
                              Sigma ({rule.compatibility_score ?? 100}%)
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="font-bold text-white group-hover:text-amber-400 transition-colors">
                          {rule.name}
                        </div>
                        <div className="text-[11px] text-slate-400 font-sans mt-0.5 truncate max-w-sm">
                          {rule.name_en}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getSeverityBadge(rule.severity)}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        {getLifecycleBadge(rule.lifecycle)}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono font-bold text-slate-200">
                        {rule.confidence}%
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {(rule.mitre_attack?.techniques || []).slice(0, 2).map((tech, i) => (
                            <span key={i} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/5 text-slate-300 border border-white/5 truncate max-w-[140px]">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono font-bold text-amber-400">
                        {rule.metrics?.match_count || 0}
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => handleToggle(rule.id, rule.enabled)}
                          disabled={!canManage}
                          className={`w-9 h-5 rounded-full transition-colors relative focus:outline-none ${
                            rule.enabled ? 'bg-emerald-500' : 'bg-slate-700'
                          } ${!canManage ? 'opacity-60 cursor-not-allowed' : ''}`}
                        >
                          <span
                            className={`w-3.5 h-3.5 rounded-full bg-white absolute top-0.5 transition-transform ${
                              rule.enabled ? 'right-5' : 'right-1'
                            }`}
                          />
                        </button>
                      </td>
                      <td className="py-3.5 px-4 whitespace-nowrap text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedRule(rule);
                            setDrawerOpen(true);
                          }}
                          className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white border border-white/10 text-[11px] font-medium transition-colors"
                        >
                          فحص ومحاكاة
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* Rule Drawer */}
      {drawerOpen && (
        <RuleDrawer
          rule={selectedRule}
          onClose={() => {
            setDrawerOpen(false);
            setSelectedRule(null);
          }}
          onRuleUpdated={(updated) => {
            setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
            setSelectedRule(updated);
          }}
          userPermissions={currentUser?.permissions}
        />
      )}

      {/* Sigma Studio Modal */}
      <SigmaStudioModal
        isOpen={sigmaStudioOpen}
        onClose={() => setSigmaStudioOpen(false)}
        onRuleImported={() => fetchAllData()}
      />
    </div>
  );
}
