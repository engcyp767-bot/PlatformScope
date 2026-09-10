'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  Server, Shield, AlertTriangle, Search, Filter, Download,
  UploadCloud, RefreshCw, Plus, Activity, Lock, CheckCircle2,
  HardDrive, Cpu, Radio, ShieldAlert, ChevronLeft, ChevronRight,
  Eye, Laptop, Database, Globe
} from 'lucide-react';
import { getAssets, getAssetsSummary, discoverAssets, exportAssetsUrl } from '../../lib/api';
import { Asset, AssetsSummary, AssetCriticality, AssetStatus } from '../../lib/types';
import { Navbar } from '../../components/Navbar';
import { AssetInvestigationDrawer } from '../../components/assets/AssetInvestigationDrawer';
import { AddAssetModal } from '../../components/assets/AddAssetModal';
import { AssetImportModal } from '../../components/assets/AssetImportModal';

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [summary, setSummary] = useState<AssetsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  // Filters
  const [search, setSearch] = useState('');
  const [criticality, setCriticality] = useState('all');
  const [assetType, setAssetType] = useState('all');
  const [status, setStatus] = useState('all');
  const [department, setDepartment] = useState('all');
  const [page, setPage] = useState(1);
  const limit = 20;

  // Modals & Drawer
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [addModalOpen, setAddModalOpen] = useState(false);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [drawerDefaultTab, setDrawerDefaultTab] = useState<'overview' | 'mesh' | 'timeline' | 'containment'>('overview');
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 4000);
  };

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [listRes, sumRes] = await Promise.all([
        getAssets({
          search: search.trim() || undefined,
          criticality: criticality !== 'all' ? criticality : undefined,
          asset_type: assetType !== 'all' ? assetType : undefined,
          status: status !== 'all' ? status : undefined,
          department: department !== 'all' ? department : undefined,
          limit,
          offset: (page - 1) * limit,
          sort_by: 'risk_score',
          sort_order: 'desc'
        }),
        getAssetsSummary()
      ]);
      setAssets(listRes.assets || []);
      setTotal(listRes.total || 0);
      setSummary(sumRes);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [search, criticality, assetType, status, department, page]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleAutoDiscover = async () => {
    try {
      showToast('جاري فحص واكتشاف الأصول من مهام التحليل...');
      const res = await discoverAssets();
      showToast(`تم الاكتشاف بنجاح: تم رصد ${res.discovered} أصل جديد وتحديث ${res.updated} أصل.`);
      loadData();
    } catch (err: any) {
      showToast(err.message || 'فشل الاكتشاف التلقائي');
    }
  };

  const openDrawer = (ast: Asset, tab: 'overview' | 'mesh' | 'timeline' | 'containment' = 'overview') => {
    setSelectedAsset(ast);
    setDrawerDefaultTab(tab);
  };

  const getCriticalityBadge = (crit: string) => {
    const map: Record<string, { label: string; cls: string }> = {
      mission_critical: { label: 'حرج للغاية', cls: 'bg-purple-500/10 text-purple-400 border-purple-500/30' },
      high: { label: 'عالي', cls: 'bg-red-500/10 text-red-400 border-red-500/30' },
      medium: { label: 'متوسط', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
      low: { label: 'منخفض', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    };
    return map[crit] || { label: crit, cls: 'bg-white/5 text-slate-400 border-white/10' };
  };

  const getStatusBadge = (st: string) => {
    const map: Record<string, { label: string; cls: string }> = {
      active: { label: 'نشط', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
      isolated: { label: 'معزول أمنياً', cls: 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse font-bold' },
      unknown: { label: 'غير مصنف', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30 font-semibold' },
      maintenance: { label: 'صيانة', cls: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
      decommissioned: { label: 'خارج الخدمة', cls: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
    };
    return map[st] || { label: st, cls: 'bg-white/5 text-slate-400 border-white/10' };
  };

  const getRiskMeter = (score: number) => {
    let barColor = 'bg-emerald-400';
    let textColor = 'text-emerald-400';
    if (score >= 80) {
      barColor = 'bg-red-500';
      textColor = 'text-red-400 font-bold';
    } else if (score >= 60) {
      barColor = 'bg-orange-500';
      textColor = 'text-orange-400 font-bold';
    } else if (score >= 40) {
      barColor = 'bg-amber-400';
      textColor = 'text-amber-400';
    }

    return (
      <div className="flex items-center gap-2">
        <div className="w-14 h-1.5 bg-dark-800 rounded-full overflow-hidden border border-white/10">
          <div className={`h-full ${barColor} rounded-full`} style={{ width: `${Math.min(100, score)}%` }} />
        </div>
        <span className={`font-mono text-xs ${textColor}`}>{score}</span>
      </div>
    );
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'database': return <Database className="w-4 h-4 text-amber-400" />;
      case 'firewall': return <Shield className="w-4 h-4 text-red-400" />;
      case 'workstation': return <Laptop className="w-4 h-4 text-blue-400" />;
      case 'cloud_instance': return <Globe className="w-4 h-4 text-cyan-400" />;
      default: return <Server className="w-4 h-4 text-primary" />;
    }
  };

  return (
    <div className="min-h-screen bg-dark-950 text-slate-100 flex flex-col">
      <Navbar />

      {toastMsg && (
        <div className="fixed bottom-5 left-5 z-50 p-4 rounded-xl bg-dark-900 border border-primary/40 shadow-2xl text-xs text-white flex items-center gap-3 animate-slide-up">
          <CheckCircle2 className="w-5 h-5 text-primary shrink-0" />
          <span>{toastMsg}</span>
        </div>
      )}

      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight flex items-center gap-3">
              <Server className="w-7 h-7 text-primary" />
              سجل وذكاء الأصول الأمنية
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              إدارة دورة حياة الأصول، وربط الهوية التلقائي، ومصفوفة الخطورة الديناميكية، وخطط العزل الفوري
            </p>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              onClick={handleAutoDiscover}
              className="px-3.5 py-2 rounded-xl bg-dark-900 hover:bg-dark-800 text-slate-200 border border-white/10 text-xs font-semibold flex items-center gap-2 transition-colors shadow-sm"
              title="اكتشاف الأصول تلقائياً من مهام LogScope و FlowScope"
            >
              <Radio className="w-4 h-4 text-primary" />
              <span>اكتشاف تلقائي</span>
            </button>

            <a
              href={exportAssetsUrl('csv')}
              className="px-3 py-2 rounded-xl bg-dark-900 hover:bg-dark-800 text-slate-200 border border-white/10 text-xs font-semibold flex items-center gap-1.5 transition-colors"
              title="تصدير الأصول بصيغة CSV"
            >
              <Download className="w-3.5 h-3.5" />
              <span>CSV</span>
            </a>

            <a
              href={exportAssetsUrl('json')}
              className="px-3 py-2 rounded-xl bg-dark-900 hover:bg-dark-800 text-slate-200 border border-white/10 text-xs font-semibold flex items-center gap-1.5 transition-colors"
              title="تصدير الأصول بصيغة JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span>JSON</span>
            </a>

            <button
              onClick={() => setImportModalOpen(true)}
              className="px-3.5 py-2 rounded-xl bg-dark-900 hover:bg-dark-800 text-slate-200 border border-white/10 text-xs font-semibold flex items-center gap-2 transition-colors"
            >
              <UploadCloud className="w-4 h-4 text-amber-400" />
              <span>استيراد CMDB</span>
            </button>

            <button
              onClick={() => setAddModalOpen(true)}
              className="px-4 py-2 rounded-xl bg-primary hover:bg-primary/90 text-dark-950 text-xs font-bold flex items-center gap-1.5 transition-colors shadow-lg shadow-primary/10"
            >
              <Plus className="w-4 h-4" />
              <span>إضافة أصل جديد</span>
            </button>
          </div>
        </div>

        {/* KPI Metrics Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl bg-dark-900/80 border border-white/10 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-400">إجمالي الأصول المسجلة</span>
              <Server className="w-4 h-4 text-primary" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl sm:text-3xl font-bold text-white font-mono">
                {summary?.total_assets || 0}
              </span>
              <span className="text-xs text-slate-500">أصل رقمي</span>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-dark-900/80 border border-purple-500/20 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-purple-300">أصول حرجة للغاية</span>
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl sm:text-3xl font-bold text-purple-400 font-mono">
                {summary?.mission_critical_count || 0}
              </span>
              <span className="text-xs text-slate-500">Mission Critical</span>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-dark-900/80 border border-red-500/20 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-red-400">أصول في خطر أمني</span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl sm:text-3xl font-bold text-red-400 font-mono">
                {summary?.high_risk_count || 0}
              </span>
              <span className="text-xs text-slate-500">Risk ≥ 60</span>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-dark-900/80 border border-amber-500/20 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-amber-300">معزولة / غير مصنفة</span>
              <Lock className="w-4 h-4 text-amber-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl sm:text-3xl font-bold text-amber-400 font-mono">
                {summary?.unknown_status_count || 0}
              </span>
              <span className="text-xs text-slate-500">تتطلب مراجعة</span>
            </div>
          </div>
        </div>

        {/* Search & Filters Bar */}
        <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 space-y-3">
          <div className="flex flex-col md:flex-row items-center gap-3">
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 text-slate-400 absolute right-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                placeholder="بحث بالاسم، عنوان الـ IP، عنوان الـ MAC، القسم، أو المالك..."
                className="w-full bg-dark-800/80 border border-white/10 rounded-xl pr-10 pl-4 py-2 text-xs text-white placeholder-slate-500 focus:border-primary outline-none transition-colors"
              />
            </div>

            <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto no-scrollbar">
              <select
                value={criticality}
                onChange={(e) => { setCriticality(e.target.value); setPage(1); }}
                className="bg-dark-800 border border-white/10 rounded-xl px-3 py-2 text-xs text-white outline-none focus:border-primary"
              >
                <option value="all">كل الحرجيات</option>
                <option value="mission_critical">حرج للغاية</option>
                <option value="high">عالي</option>
                <option value="medium">متوسط</option>
                <option value="low">منخفض</option>
              </select>

              <select
                value={status}
                onChange={(e) => { setStatus(e.target.value); setPage(1); }}
                className="bg-dark-800 border border-white/10 rounded-xl px-3 py-2 text-xs text-white outline-none focus:border-primary"
              >
                <option value="all">كل الحالات</option>
                <option value="unknown">غير مصنف (Unknown)</option>
                <option value="active">نشط (Active)</option>
                <option value="isolated">معزول أمنياً (Isolated)</option>
                <option value="maintenance">صيانة</option>
              </select>

              <select
                value={assetType}
                onChange={(e) => { setAssetType(e.target.value); setPage(1); }}
                className="bg-dark-800 border border-white/10 rounded-xl px-3 py-2 text-xs text-white outline-none focus:border-primary"
              >
                <option value="all">كل الأنواع</option>
                <option value="server">خوادم (Server)</option>
                <option value="workstation">محطات عمل</option>
                <option value="domain_controller">متحكم نطاق (DC)</option>
                <option value="firewall">جدران حماية</option>
                <option value="database">قواعد بيانات</option>
              </select>

              <button
                onClick={loadData}
                className="p-2 rounded-xl bg-dark-800 hover:bg-dark-700 border border-white/10 text-slate-300 transition-colors shrink-0"
                title="تحديث"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>
        </div>

        {/* Assets Table */}
        <div className="bg-dark-900/80 border border-white/10 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead className="bg-dark-800/80 text-slate-400 border-b border-white/10 select-none">
                <tr>
                  <th className="p-3.5 pr-5 font-semibold">الأصل والمضيف</th>
                  <th className="p-3.5 font-semibold">عناوين الشبكة (IP / MAC)</th>
                  <th className="p-3.5 font-semibold">النوع والنظام</th>
                  <th className="p-3.5 font-semibold">القسم والمالك</th>
                  <th className="p-3.5 font-semibold">الحرجية</th>
                  <th className="p-3.5 font-semibold">درجة الخطورة</th>
                  <th className="p-3.5 font-semibold">الحالة</th>
                  <th className="p-3.5 font-semibold">الموثوقية</th>
                  <th className="p-3.5 pl-5 text-center font-semibold">الإجراءات</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 text-slate-300">
                {loading && assets.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="p-12 text-center text-slate-500 text-sm">
                      <RefreshCw className="w-6 h-6 animate-spin mx-auto text-primary mb-2" />
                      جاري تحميل بيانات الأصول الأمنية...
                    </td>
                  </tr>
                ) : assets.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="p-12 text-center text-slate-500 text-sm">
                      لا توجد أصول مطابقة لمعايير البحث الحالية.
                    </td>
                  </tr>
                ) : (
                  assets.map((ast) => (
                    <tr
                      key={ast.id}
                      className="hover:bg-white/[0.02] transition-colors cursor-pointer group"
                      onClick={() => openDrawer(ast, 'overview')}
                    >
                      <td className="p-3.5 pr-5">
                        <div className="flex items-center gap-2.5">
                          <div className="w-8 h-8 rounded-lg bg-dark-800 border border-white/10 flex items-center justify-center shrink-0">
                            {getTypeIcon(ast.asset_type)}
                          </div>
                          <div>
                            <span className="font-bold text-white block group-hover:text-primary transition-colors">
                              {ast.hostname}
                            </span>
                            <span className="text-[11px] text-slate-500 font-mono">{ast.id}</span>
                          </div>
                        </div>
                      </td>

                      <td className="p-3.5 font-mono text-xs">
                        <span className="text-primary font-semibold block">{ast.primary_ip}</span>
                        <span className="text-[11px] text-slate-500 block">{ast.mac_address || '--'}</span>
                      </td>

                      <td className="p-3.5">
                        <span className="capitalize text-slate-200 block font-medium">{ast.asset_type.replace('_', ' ')}</span>
                        <span className="text-[11px] text-slate-500 block truncate max-w-[140px]">{ast.os}</span>
                      </td>

                      <td className="p-3.5">
                        <span className="text-slate-200 block font-medium">{ast.department}</span>
                        <span className="text-[11px] text-slate-500 block">{ast.owner}</span>
                      </td>

                      <td className="p-3.5">
                        <span className={`text-[11px] px-2.5 py-1 rounded-full border font-semibold inline-block ${getCriticalityBadge(ast.criticality).cls}`}>
                          {getCriticalityBadge(ast.criticality).label}
                        </span>
                      </td>

                      <td className="p-3.5">
                        {getRiskMeter(ast.risk_score)}
                      </td>

                      <td className="p-3.5">
                        <span className={`text-[11px] px-2 py-0.5 rounded-full border inline-block ${getStatusBadge(ast.status).cls}`}>
                          {getStatusBadge(ast.status).label}
                        </span>
                      </td>

                      <td className="p-3.5 font-mono text-slate-400 text-xs">
                        {ast.confidence_score}%
                      </td>

                      <td className="p-3.5 pl-5 text-center" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-center gap-1.5">
                          <button
                            onClick={() => openDrawer(ast, 'overview')}
                            className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
                            title="التحقيق الجنائي"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => openDrawer(ast, 'containment')}
                            className={`p-1.5 rounded-lg border text-xs transition-colors ${
                              ast.status === 'isolated'
                                ? 'bg-red-500/20 border-red-500/40 text-red-400 hover:bg-red-500/30'
                                : 'bg-white/5 border-white/10 text-slate-400 hover:text-red-400 hover:border-red-500/30'
                            }`}
                            title="خطة العزل والاحتواء"
                          >
                            <Lock className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {total > limit && (
            <div className="p-4 border-t border-white/10 bg-dark-800/40 flex items-center justify-between text-xs text-slate-400">
              <span>
                عرض {((page - 1) * limit) + 1} إلى {Math.min(page * limit, total)} من أصل {total} أصل
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="p-1.5 rounded-lg bg-dark-900 border border-white/10 hover:bg-dark-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
                <span className="font-mono px-2">صفحة {page} من {Math.ceil(total / limit)}</span>
                <button
                  onClick={() => setPage((p) => Math.min(Math.ceil(total / limit), p + 1))}
                  disabled={page >= Math.ceil(total / limit)}
                  className="p-1.5 rounded-lg bg-dark-900 border border-white/10 hover:bg-dark-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Drawer & Modals */}
      {selectedAsset && (
        <AssetInvestigationDrawer
          asset={selectedAsset}
          onClose={() => setSelectedAsset(null)}
          onRefresh={loadData}
          defaultTab={drawerDefaultTab}
        />
      )}

      {addModalOpen && (
        <AddAssetModal
          onClose={() => setAddModalOpen(false)}
          onSuccess={(newAsset) => {
            showToast(`تمت إضافة الأصل ${newAsset.hostname} بنجاح`);
            loadData();
          }}
        />
      )}

      {importModalOpen && (
        <AssetImportModal
          onClose={() => setImportModalOpen(false)}
          onSuccess={() => {
            showToast('تم استيراد الأصول بنجاح!');
            loadData();
          }}
        />
      )}
    </div>
  );
}
