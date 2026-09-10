'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Navbar } from '../../components/Navbar';
import {
  ShieldAlert, Shield, AlertTriangle, CheckCircle, Clock,
  Filter, Search, RefreshCw, Plus, ChevronLeft, ChevronRight,
  User, ExternalLink, ArrowRight, Layers, Flame, FileText,
  SlidersHorizontal, Check, X, BookOpen, ShieldCheck
} from 'lucide-react';
import {
  Incident, IncidentSummary, IncidentStatus, IncidentSeverity,
  IncidentPriority, User as UserType
} from '../../lib/types';
import {
  getIncidents, getIncidentSummary, createIncident,
  syncIncidents, getAuthStatus, fetchApi
} from '../../lib/api';
import { IncidentDrawer } from '../../components/incidents/IncidentDrawer';
import { VerifyCaseModal } from '../../components/incidents/VerifyCaseModal';

export default function IncidentsPage() {
  const [currentUser, setCurrentUser] = useState<UserType | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [summary, setSummary] = useState<IncidentSummary | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  // Pagination & Filtering state (Server-side)
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(15);
  const [search, setSearch] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedPriority, setSelectedPriority] = useState<string>('');
  const [selectedApp, setSelectedApp] = useState<string>('');
  const [selectedAssignee, setSelectedAssignee] = useState<string>('');

  // Drawer state
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  // New Incident Modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [verifyModalOpen, setVerifyModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState<IncidentSeverity>('high');
  const [newAssetCrit, setNewAssetCrit] = useState('high');
  const [newBizImpact, setNewBizImpact] = useState('medium');
  const [newApp, setNewApp] = useState('manual');
  const [newDescription, setNewDescription] = useState('');
  const [newEntities, setNewEntities] = useState('');
  const [newReason, setNewReason] = useState('');
  const [creating, setCreating] = useState(false);

  // Load user
  useEffect(() => {
    getAuthStatus().then((res) => {
      if (res.authenticated && res.user) {
        setCurrentUser(res.user);
      }
    });
  }, []);

  const loadSummary = useCallback(async () => {
    try {
      const data = await getIncidentSummary();
      setSummary(data);
    } catch (err) {
      console.error('Failed to load incident summary:', err);
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string | number> = {
        page,
        limit,
      };
      if (search.trim()) params.search = search.trim();
      if (selectedStatus) params.status = selectedStatus;
      if (selectedSeverity) params.severity = selectedSeverity;
      if (selectedPriority) params.priority = selectedPriority;
      if (selectedApp) params.source_app = selectedApp;
      if (selectedAssignee) params.assigned_to = selectedAssignee;

      const res = await getIncidents(params);
      setIncidents(res.incidents || []);
      setTotalCount(res.total || 0);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  }, [page, limit, search, selectedStatus, selectedSeverity, selectedPriority, selectedApp, selectedAssignee]);

  useEffect(() => {
    loadSummary();
    loadIncidents();
  }, [loadSummary, loadIncidents]);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const res = await syncIncidents();
      alert(`تمت مزامنة ${res.synced} حادث بنجاح من مهام التحليل السابقة.`);
      loadSummary();
      loadIncidents();
    } catch (err: any) {
      alert(err.message || 'فشلت المزامنة');
    } finally {
      setSyncing(false);
    }
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    setCreating(true);
    try {
      const entitiesList = newEntities
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean);

      const created = await createIncident({
        title: newTitle.trim(),
        severity: newSeverity,
        source_app: newApp as any,
        description: newDescription.trim(),
        asset_criticality: newAssetCrit,
        business_impact: newBizImpact,
        entities: entitiesList,
        reason: newReason.trim() || 'Manual incident creation by analyst',
      });

      setCreateModalOpen(false);
      setNewTitle('');
      setNewDescription('');
      setNewEntities('');
      setNewReason('');
      loadSummary();
      loadIncidents();
      setSelectedIncidentId(created.id);
      setDrawerOpen(true);
    } catch (err: any) {
      alert(err.message || 'فشل إنشاء الحادث');
    } finally {
      setCreating(false);
    }
  };

  const resetFilters = () => {
    setSearch('');
    setSelectedStatus('');
    setSelectedSeverity('');
    setSelectedPriority('');
    setSelectedApp('');
    setSelectedAssignee('');
    setPage(1);
  };

  const totalPages = Math.ceil(totalCount / limit) || 1;
  const canManage = currentUser?.permissions?.includes('incidents.manage');
  const canExport = currentUser?.permissions?.includes('incidents.export');

  return (
    <div className="min-h-screen flex flex-col bg-dark-950 text-slate-100">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        
        {/* Header Title and Actions */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-semibold uppercase tracking-wider">
                SOC Incident Management
              </span>
              <span className="text-xs text-slate-400 font-mono">
                {totalCount} حوادث مسجلة
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              مركز إدارة الحوادث الأمنية والتحقيق الجنائي
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              إدارة دورة حياة الحوادث كاملة عبر محركات LogScope و FlowScope و ThreatScope وتوثيق الأدلة وسجلات التدقيق.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <Link
              href="/help#incident-management"
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-xs font-semibold text-red-300 transition-colors"
              title="دليل إدارة الحوادث الأمنية"
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">دليل الحوادث</span>
            </Link>

            {(canExport || canManage) && (
              <button
                onClick={() => setVerifyModalOpen(true)}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-semibold text-emerald-300 transition-colors"
                title="فحص سلامة حزمة التحقيق الجنائي التشفيرية (SHA-256 Forensic Integrity Verifier)"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                <span>فحص ملف تحقيق (Verify)</span>
              </button>
            )}

            {canManage && (
              <button
                onClick={handleSync}
                disabled={syncing}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition-colors"
                title="استيراد وتحديث الحوادث من مهام التحليل السابقة"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin text-primary' : 'text-slate-400'}`} />
                <span>{syncing ? 'جاري المزامنة...' : 'مزامنة التحليلات'}</span>
              </button>
            )}

            {canManage && (
              <button
                onClick={() => setCreateModalOpen(true)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 text-dark-950 font-bold text-xs transition-colors shadow-lg shadow-primary/20"
              >
                <Plus className="w-4 h-4" />
                <span>إنشاء حادث أمني</span>
              </button>
            )}
          </div>
        </div>

        {/* KPI Metric Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
          <div
            onClick={() => { setSelectedStatus(''); setPage(1); }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              selectedStatus === '' ? 'bg-white/10 border-primary/50 shadow-md shadow-primary/5' : 'bg-white/[0.02] border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
              <span>إجمالي الحوادث</span>
              <ShieldAlert className="w-4 h-4 text-slate-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-white">
              {summary?.total || 0}
            </div>
          </div>

          <div
            onClick={() => { setSelectedStatus('new'); setPage(1); }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              selectedStatus === 'new' ? 'bg-blue-500/15 border-blue-500/50 shadow-md shadow-blue-500/5' : 'bg-white/[0.02] border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-blue-400 mb-1">
              <span>جديد (New)</span>
              <Clock className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-blue-400">
              {summary?.by_status?.new || 0}
            </div>
          </div>

          <div
            onClick={() => { setSelectedStatus('investigating'); setPage(1); }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              selectedStatus === 'investigating' ? 'bg-amber-500/15 border-amber-500/50 shadow-md shadow-amber-500/5' : 'bg-white/[0.02] border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-amber-400 mb-1">
              <span>قيد التحقيق</span>
              <Flame className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-amber-400">
              {(summary?.by_status?.investigating || 0) + (summary?.by_status?.triaged || 0)}
            </div>
          </div>

          <div
            onClick={() => { setSelectedStatus('contained'); setPage(1); }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              selectedStatus === 'contained' ? 'bg-purple-500/15 border-purple-500/50 shadow-md shadow-purple-500/5' : 'bg-white/[0.02] border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-purple-400 mb-1">
              <span>تم الاحتواء (Contained)</span>
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-purple-400">
              {summary?.by_status?.contained || 0}
            </div>
          </div>

          <div
            onClick={() => { setSelectedStatus('resolved'); setPage(1); }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              selectedStatus === 'resolved' ? 'bg-emerald-500/15 border-emerald-500/50 shadow-md shadow-emerald-500/5' : 'bg-white/[0.02] border-white/10 hover:border-white/20'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-emerald-400 mb-1">
              <span>تم الحل والمغلقة</span>
              <CheckCircle className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-400">
              {(summary?.by_status?.resolved || 0) + (summary?.by_status?.closed || 0)}
            </div>
          </div>
        </div>

        {/* Server-side Filter Bar */}
        <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2.5">
            
            {/* Search Input */}
            <div className="relative sm:col-span-2">
              <Search className="w-4 h-4 absolute right-3 top-2.5 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                placeholder="بحث بالمعرف، العنوان، IP، أو Correlation ID..."
                className="w-full bg-dark-900 border border-white/10 rounded-lg pr-9 pl-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-primary"
              />
            </div>

            {/* Status Filter */}
            <div>
              <select
                value={selectedStatus}
                onChange={(e) => { setSelectedStatus(e.target.value); setPage(1); }}
                className="w-full bg-dark-900 border border-white/10 rounded-lg px-2.5 py-2 text-xs text-white focus:outline-none focus:border-primary"
              >
                <option value="">جميع الحالات</option>
                <option value="new">جديد (New)</option>
                <option value="triaged">مفروز (Triaged)</option>
                <option value="investigating">قيد التحقيق (Investigating)</option>
                <option value="contained">تم الاحتواء (Contained)</option>
                <option value="resolved">تم الحل (Resolved)</option>
                <option value="closed">مغلق (Closed)</option>
                <option value="rejected">مرفوض (Rejected)</option>
              </select>
            </div>

            {/* Priority Filter */}
            <div>
              <select
                value={selectedPriority}
                onChange={(e) => { setSelectedPriority(e.target.value); setPage(1); }}
                className="w-full bg-dark-900 border border-white/10 rounded-lg px-2.5 py-2 text-xs text-white focus:outline-none focus:border-primary"
              >
                <option value="">جميع الأولويات</option>
                <option value="P1">P1 - حرجة جداً</option>
                <option value="P2">P2 - عالية</option>
                <option value="P3">P3 - متوسطة</option>
                <option value="P4">P4 - منخفضة</option>
              </select>
            </div>

            {/* Source App Filter */}
            <div>
              <select
                value={selectedApp}
                onChange={(e) => { setSelectedApp(e.target.value); setPage(1); }}
                className="w-full bg-dark-900 border border-white/10 rounded-lg px-2.5 py-2 text-xs text-white focus:outline-none focus:border-primary"
              >
                <option value="">كافة المحركات</option>
                <option value="logscope">LogScope</option>
                <option value="flowscope">FlowScope</option>
                <option value="threatscope">ThreatScope</option>
                <option value="manual">Manual</option>
              </select>
            </div>

            {/* Reset Filters */}
            <div>
              <button
                onClick={resetFilters}
                className="w-full py-2 px-3 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-300 transition-colors flex items-center justify-center gap-1"
              >
                <X className="w-3.5 h-3.5" />
                <span>إعادة تعيين</span>
              </button>
            </div>

          </div>
        </div>

        {/* Incidents Table */}
        <div className="rounded-xl border border-white/10 bg-white/[0.02] overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead className="bg-dark-900/80 border-b border-white/10 text-slate-400 font-semibold">
                <tr>
                  <th className="p-3.5">معرف الحادث والأولوية</th>
                  <th className="p-3.5">عنوان الحادث وسياق التهديد</th>
                  <th className="p-3.5 text-center">الحالة</th>
                  <th className="p-3.5 text-center">المحرك المصدر</th>
                  <th className="p-3.5">المحلل المعين</th>
                  <th className="p-3.5">تاريخ التحديث</th>
                  <th className="p-3.5 text-center">الإجراءات</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-sans">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="p-10 text-center text-slate-400">
                      <div className="flex flex-col items-center gap-2">
                        <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
                        <span>جاري تحميل الحوادث الأمنية...</span>
                      </div>
                    </td>
                  </tr>
                ) : incidents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-12 text-center text-slate-400 space-y-2">
                      <ShieldAlert className="w-8 h-8 text-slate-500 mx-auto" />
                      <p className="text-sm font-bold text-white">لا توجد حوادث أمنية مطابقة لمعايير البحث</p>
                      <p className="text-xs text-slate-500">جرب تعديل الفلاتر أو اضغط على &quot;مزامنة التحليلات&quot; لجلب الحوادث من المهام السابقة.</p>
                    </td>
                  </tr>
                ) : (
                  incidents.map((inc) => (
                    <tr
                      key={inc.id}
                      onClick={() => {
                        setSelectedIncidentId(inc.id);
                        setDrawerOpen(true);
                      }}
                      className="hover:bg-white/[0.03] transition-colors cursor-pointer group"
                    >
                      <td className="p-3.5">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono uppercase ${
                            inc.priority === 'P1' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                            inc.priority === 'P2' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                            inc.priority === 'P3' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                            'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                          }`}>
                            {inc.priority}
                          </span>
                          <span className="font-mono text-xs font-bold text-primary group-hover:underline">
                            {inc.id}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono block mt-0.5">
                          {inc.correlation_id}
                        </span>
                      </td>

                      <td className="p-3.5 max-w-md">
                        <div className="font-bold text-white group-hover:text-primary transition-colors line-clamp-1">
                          {inc.title}
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-[10px] font-bold uppercase ${
                            inc.severity === 'critical' ? 'text-red-400' :
                            inc.severity === 'high' ? 'text-orange-400' :
                            inc.severity === 'medium' ? 'text-amber-400' :
                            'text-slate-400'
                          }`}>
                            {inc.severity}
                          </span>
                          {inc.entities && inc.entities.length > 0 && (
                            <span className="text-[10px] text-slate-400 font-mono">
                              • {inc.entities.slice(0, 2).join(', ')}{inc.entities.length > 2 ? ` (+${inc.entities.length - 2})` : ''}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="p-3.5 text-center">
                        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-medium ${
                          inc.status === 'new' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30' :
                          inc.status === 'triaged' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' :
                          inc.status === 'investigating' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                          inc.status === 'contained' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/30' :
                          inc.status === 'resolved' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                          inc.status === 'closed' ? 'bg-slate-500/10 text-slate-400 border border-slate-500/30' :
                          'bg-red-500/15 text-red-400 border border-red-500/30'
                        }`}>
                          {inc.status}
                        </span>
                      </td>

                      <td className="p-3.5 text-center">
                        <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-white/5 text-slate-300 border border-white/10">
                          {inc.source_app}
                        </span>
                      </td>

                      <td className="p-3.5">
                        {inc.assigned_to ? (
                          <div className="flex items-center gap-1.5 text-xs text-slate-300 font-medium">
                            <User className="w-3.5 h-3.5 text-cyan-400" />
                            <span>{inc.assigned_to}</span>
                          </div>
                        ) : (
                          <span className="text-slate-500 text-xs italic">غير معين</span>
                        )}
                      </td>

                      <td className="p-3.5 text-[11px] text-slate-400 font-mono">
                        {new Date(inc.updated_at || inc.created_at).toLocaleString('en-US')}
                      </td>

                      <td className="p-3.5 text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => {
                            setSelectedIncidentId(inc.id);
                            setDrawerOpen(true);
                          }}
                          className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-primary/20 text-slate-300 hover:text-primary border border-white/10 hover:border-primary/30 text-xs font-medium transition-all inline-flex items-center gap-1"
                        >
                          <span>فتح التحقيق</span>
                          <ChevronLeft className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="p-4 border-t border-white/10 bg-dark-900/40 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
            <div>
              عرض {incidents.length > 0 ? (page - 1) * limit + 1 : 0} إلى {Math.min(page * limit, totalCount)} من أصل {totalCount} حادث مسجل
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                title="الصفحة السابقة"
              >
                <ChevronRight className="w-4 h-4" />
              </button>

              <span className="px-3 py-1 bg-white/5 rounded border border-white/10 font-mono text-white">
                {page} / {totalPages}
              </span>

              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                title="الصفحة التالية"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

      </main>

      {/* Incident Details Drawer */}
      <IncidentDrawer
        incidentId={selectedIncidentId}
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onUpdated={() => {
          loadSummary();
          loadIncidents();
        }}
        currentUser={currentUser}
      />

      {/* Verify Case Modal */}
      <VerifyCaseModal
        isOpen={verifyModalOpen}
        onClose={() => setVerifyModalOpen(false)}
      />

      {/* CREATE MANUAL INCIDENT MODAL */}
      {createModalOpen && (
        <div className="fixed inset-0 z-60 bg-black/80 flex items-center justify-center p-4">
          <form onSubmit={handleCreateIncident} className="w-full max-w-xl bg-dark-900 border border-white/15 rounded-xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/10 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-primary" />
                <span>إنشاء حادث أمني يدوي جديد</span>
              </h3>
              <button type="button" onClick={() => setCreateModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1">عنوان الحادث الأمني</label>
              <input
                type="text"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                placeholder="مثال: رصد هجوم Brute-force على خادم قاعدة البيانات"
                required
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              />
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">مستوى الخطورة</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as IncidentSeverity)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2 text-xs text-white"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">حرجية الأصل</label>
                <select
                  value={newAssetCrit}
                  onChange={(e) => setNewAssetCrit(e.target.value)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2 text-xs text-white"
                >
                  <option value="mission_critical">Mission Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-bold text-slate-300 block mb-1">أثر العمليات</label>
                <select
                  value={newBizImpact}
                  onChange={(e) => setNewBizImpact(e.target.value)}
                  className="w-full bg-dark-950 border border-white/10 rounded-lg p-2 text-xs text-white"
                >
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="none">None</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1">الوصف وسياق الهجوم</label>
              <textarea
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                placeholder="اشرح تفاصيل الهجوم أو التهديد المرصود..."
                rows={3}
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              />
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1">الكيانات المستهدفة (عناوين IP، نطاقات، حسابات - مفصولة بفواصل)</label>
              <input
                type="text"
                value={newEntities}
                onChange={(e) => setNewEntities(e.target.value)}
                placeholder="10.0.0.15, SRV-APP-01, admin_user"
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white font-mono focus:outline-none focus:border-primary"
              />
            </div>

            <div>
              <label className="text-xs font-bold text-slate-300 block mb-1">سبب الإنشاء (لتوثيق التدقيق الأمني)</label>
              <input
                type="text"
                value={newReason}
                onChange={(e) => setNewReason(e.target.value)}
                placeholder="مثال: تم التنبيه عبر نظام مراقبة خارجي"
                className="w-full bg-dark-950 border border-white/10 rounded-lg p-2.5 text-xs text-white focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-white/10">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-medium"
              >
                إلغاء
              </button>
              <button
                type="submit"
                disabled={creating || !newTitle.trim()}
                className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 text-dark-950 font-bold text-xs"
              >
                {creating ? 'جاري الإنشاء...' : 'تأكيد إنشاء الحادث'}
              </button>
            </div>
          </form>
        </div>
      )}

    </div>
  );
}
