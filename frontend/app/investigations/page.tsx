'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  FolderKanban, Briefcase, Shield, ShieldAlert, AlertTriangle,
  Search, Filter, Plus, Clock, User as UserIcon, Tag,
  FileText, Trash2, ExternalLink, ChevronRight, ChevronLeft,
  RefreshCw, CheckCircle2, X, MessageSquare, Calendar,
  History, Activity, Layers, Link2, Eye, Send, ArrowRight
} from 'lucide-react';
import { Navbar } from '../../components/Navbar';
import {
  getInvestigations, getInvestigationSummary, getInvestigation,
  createInvestigation, updateInvestigation, addInvestigationItem,
  removeInvestigationItem, addInvestigationNote
} from '../../lib/api';
import {
  InvestigationCase, InvestigationSummary, InvestigationItem, InvestigationNote
} from '../../lib/types';

export default function InvestigationsPage() {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [summary, setSummary] = useState<InvestigationSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [page, setPage] = useState(1);
  const limit = 15;

  // Selected investigation & details
  const [selectedCase, setSelectedCase] = useState<InvestigationCase | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [activeTab, setActiveTab] = useState<'items' | 'notes' | 'timeline'>('items');

  // Modals
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newPriority, setNewPriority] = useState('P2');
  const [newLead, setNewLead] = useState('');
  const [newHypothesis, setNewHypothesis] = useState('');
  const [newTags, setNewTags] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Add Item state
  const [addItemType, setAddItemType] = useState('incident');
  const [addItemId, setAddItemId] = useState('');
  const [addItemTitle, setAddItemTitle] = useState('');

  // Add Note state
  const [noteContent, setNoteContent] = useState('');
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 4000);
  };

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [listRes, sumRes] = await Promise.all([
        getInvestigations({
          search: search.trim() || undefined,
          status: statusFilter !== 'all' ? statusFilter : undefined,
          priority: priorityFilter !== 'all' ? priorityFilter : undefined,
          limit,
          offset: (page - 1) * limit,
        }),
        getInvestigationSummary(),
      ]);
      setCases(listRes.investigations || []);
      setTotal(listRes.total || 0);
      setSummary(sumRes);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, priorityFilter, page]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const selectCase = async (id: string) => {
    setLoadingDetails(true);
    try {
      const details = await getInvestigation(id);
      setSelectedCase(details);
    } catch (err) {
      showToast('تعذر تحميل تفاصيل التحقيق');
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    setSubmitting(true);
    try {
      const tagsList = newTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      const created = await createInvestigation({
        title: newTitle.trim(),
        description: newDesc.trim() || undefined,
        priority: newPriority,
        lead_analyst: newLead.trim() || 'Unassigned',
        tags: tagsList,
        hypothesis: newHypothesis.trim() || undefined,
      });
      showToast(`تم فتح قضية التحقيق بنجاح: ${created.id}`);
      setCreateModalOpen(false);
      setNewTitle('');
      setNewDesc('');
      setNewPriority('P2');
      setNewLead('');
      setNewHypothesis('');
      setNewTags('');
      loadData();
      selectCase(created.id);
    } catch (err: any) {
      showToast(err?.message || 'فشل إنشاء القضية');
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateStatus = async (status: any) => {
    if (!selectedCase) return;
    try {
      const updated = await updateInvestigation(selectedCase.id, { status });
      setSelectedCase(updated);
      loadData();
      showToast(`تم تحديث حالة القضية إلى ${status}`);
    } catch (err: any) {
      showToast(err?.message || 'تعذر تحديث الحالة');
    }
  };

  const handleUpdatePriority = async (priority: any) => {
    if (!selectedCase) return;
    try {
      const updated = await updateInvestigation(selectedCase.id, { priority });
      setSelectedCase(updated);
      loadData();
      showToast(`تم تحديث الأولوية إلى ${priority}`);
    } catch (err: any) {
      showToast(err?.message || 'تعذر تحديث الأولوية');
    }
  };

  const handleAddItem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !addItemId.trim() || !addItemTitle.trim()) return;
    try {
      await addInvestigationItem(selectedCase.id, {
        item_type: addItemType,
        item_id: addItemId.trim(),
        title: addItemTitle.trim(),
      });
      const refreshed = await getInvestigation(selectedCase.id);
      setSelectedCase(refreshed);
      loadData();
      setAddItemId('');
      setAddItemTitle('');
      showToast('تم ربط العنصر بالقضية');
    } catch (err: any) {
      showToast(err?.message || 'تعذر ربط العنصر');
    }
  };

  const handleRemoveItem = async (itemId: string) => {
    if (!selectedCase) return;
    try {
      await removeInvestigationItem(selectedCase.id, itemId);
      const refreshed = await getInvestigation(selectedCase.id);
      setSelectedCase(refreshed);
      loadData();
      showToast('تم فك ربط العنصر');
    } catch (err: any) {
      showToast(err?.message || 'تعذر فك ربط العنصر');
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !noteContent.trim()) return;
    try {
      await addInvestigationNote(selectedCase.id, noteContent.trim());
      const refreshed = await getInvestigation(selectedCase.id);
      setSelectedCase(refreshed);
      loadData();
      setNoteContent('');
      showToast('تمت إضافة الملاحظة التحليلية');
    } catch (err: any) {
      showToast(err?.message || 'تعذر إضافة الملاحظة');
    }
  };

  // Helper labels & badges
  const statusLabels: Record<string, { label: string; color: string; bg: string }> = {
    open: { label: 'مفتوحة حديثاً', color: 'text-sky-400', bg: 'bg-sky-500/10 border-sky-500/30' },
    active_triage: { label: 'فحص وتصنيف أولي', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
    in_depth_analysis: { label: 'تحليل جنائي متعمق', color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/30' },
    containment: { label: 'احتواء واستجابة', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30' },
    closed: { label: 'مغلقة ومؤرشفة', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' },
  };

  const priorityBadges: Record<string, { label: string; color: string; bg: string }> = {
    P1: { label: 'P1 حرجة جداً', color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/30' },
    P2: { label: 'P2 عالية', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
    P3: { label: 'P3 متوسطة', color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30' },
    P4: { label: 'P4 منخفضة', color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/30' },
  };

  const itemTypeBadges: Record<string, { label: string; color: string; icon: any }> = {
    incident: { label: 'حادثة أمنية', color: 'text-rose-400 bg-rose-500/10 border-rose-500/25', icon: AlertTriangle },
    asset: { label: 'أصل شبكي', color: 'text-sky-400 bg-sky-500/10 border-sky-500/25', icon: Shield },
    ioc: { label: 'مؤشر اختراق IOC', color: 'text-purple-400 bg-purple-500/10 border-purple-500/25', icon: ShieldAlert },
    evidence: { label: 'دليل جنائي', color: 'text-amber-400 bg-amber-500/10 border-amber-500/25', icon: FileText },
    log_snippet: { label: 'مقتطف سجلات', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25', icon: Activity },
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans" dir="rtl">
      <Navbar />

      {toastMsg && (
        <div className="fixed bottom-6 left-6 z-50 bg-slate-900 border border-purple-500/40 text-purple-200 px-4 py-2.5 rounded-xl shadow-2xl flex items-center gap-2 text-sm">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{toastMsg}</span>
        </div>
      )}

      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
                <FolderKanban className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                  مساحة التحقيقات الأمنية الموحدة
                  <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/20 border border-purple-500/30 text-purple-300 font-mono">
                    SOC Cases
                  </span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  إدارة قضايا التحقيق الجنائي الشامل، وربط الحوادث والأصول والأدلة ومؤشرات التهديد في ملف تحقيق موحد.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setCreateModalOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold rounded-xl bg-purple-600 hover:bg-purple-500 text-white shadow-lg shadow-purple-600/20 transition"
            >
              <Plus className="w-4 h-4" />
              <span>فتح قضية جديدة</span>
            </button>

            <button
              onClick={loadData}
              disabled={loading}
              className="p-2 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 transition"
              title="تحديث البيانات"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-purple-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* KPIs */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 shadow-sm backdrop-blur-sm">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">إجمالي قضايا التحقيق</span>
              <FolderKanban className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white font-mono">{summary?.total ?? total}</div>
            <div className="text-[11px] text-slate-500 mt-1">مسجلة في قاعدة التحقيقات الجنائية</div>
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 shadow-sm backdrop-blur-sm">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">قيد الفحص والتحليل النشط</span>
              <Activity className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400 font-mono">
              {(summary?.by_status?.active_triage || 0) + (summary?.by_status?.in_depth_analysis || 0)}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">تتطلب تدخلاً ومتابعة لحظية من الفريق</div>
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 shadow-sm backdrop-blur-sm">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">قضايا حرجة وعالية الخطورة (P1/P2)</span>
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 font-mono">
              {(summary?.by_priority?.P1 || 0) + (summary?.by_priority?.P2 || 0)}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">ذات أولوية قصوى واستهداف مباشر</div>
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 shadow-sm backdrop-blur-sm">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium">قضايا مكتملة ومغلقة</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-emerald-400 font-mono">{summary?.closed ?? 0}</div>
            <div className="text-[11px] text-slate-500 mt-1">تمت صياغة الاستنتاج والأرشفة</div>
          </div>
        </div>

        {/* Filters Bar */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-3 flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-slate-500 absolute right-3 top-2.5" />
            <input
              type="text"
              placeholder="البحث بالمعرف أو العنوان أو الفرضية..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 text-xs text-white rounded-xl pr-9 pl-3 py-2 focus:outline-none focus:border-purple-500 transition"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:border-purple-500"
            >
              <option value="all">جميع الحالات</option>
              <option value="open">مفتوحة حديثاً</option>
              <option value="active_triage">فحص وتصنيف أولي</option>
              <option value="in_depth_analysis">تحليل متعمق</option>
              <option value="containment">احتواء واستجابة</option>
              <option value="closed">مغلقة ومؤرشفة</option>
            </select>

            <select
              value={priorityFilter}
              onChange={(e) => {
                setPriorityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-xl px-3 py-2 focus:outline-none focus:border-purple-500"
            >
              <option value="all">جميع الأولويات</option>
              <option value="P1">P1 حرجة جداً</option>
              <option value="P2">P2 عالية</option>
              <option value="P3">P3 متوسطة</option>
              <option value="P4">P4 منخفضة</option>
            </select>
          </div>
        </div>

        {/* Table of Investigations */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs text-slate-300">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-3 px-4">معرف القضية</th>
                  <th className="py-3 px-4">عنوان القضية والمحتوى</th>
                  <th className="py-3 px-4">الأولوية</th>
                  <th className="py-3 px-4">الحالة</th>
                  <th className="py-3 px-4">المحلل المسؤول</th>
                  <th className="py-3 px-4">العناصر المرتبطة</th>
                  <th className="py-3 px-4">الملاحظات</th>
                  <th className="py-3 px-4">تاريخ الإنشاء</th>
                  <th className="py-3 px-4 text-center">الإجراء</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {loading ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-500">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
                        <span>جاري تحميل ملفات التحقيق الأمني...</span>
                      </div>
                    </td>
                  </tr>
                ) : cases.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-12 text-center text-slate-500">
                      <FolderKanban className="w-8 h-8 mx-auto text-slate-600 mb-2" />
                      <span>لا توجد قضايا تحقيق تطابق الفلاتر المحددة.</span>
                    </td>
                  </tr>
                ) : (
                  cases.map((inv) => {
                    const st = statusLabels[inv.status] || { label: inv.status, color: 'text-slate-400', bg: 'bg-slate-800' };
                    const pr = priorityBadges[inv.priority] || { label: inv.priority, color: 'text-slate-400', bg: 'bg-slate-800' };
                    return (
                      <tr
                        key={inv.id}
                        className="hover:bg-slate-800/40 transition cursor-pointer"
                        onClick={() => selectCase(inv.id)}
                      >
                        <td className="py-3.5 px-4 font-mono font-bold text-purple-400 whitespace-nowrap">
                          {inv.id}
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="font-semibold text-white">{inv.title}</div>
                          {inv.description && (
                            <div className="text-slate-400 line-clamp-1 text-[11px] mt-0.5">
                              {inv.description}
                            </div>
                          )}
                          {inv.tags && inv.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1.5">
                              {inv.tags.map((tg, i) => (
                                <span
                                  key={i}
                                  className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono"
                                >
                                  #{tg}
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className={`px-2 py-1 rounded-md text-[11px] font-semibold border ${pr.bg} ${pr.color}`}>
                            {pr.label}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className={`px-2 py-1 rounded-md text-[11px] font-medium border ${st.bg} ${st.color}`}>
                            {st.label}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <UserIcon className="w-3.5 h-3.5 text-slate-500" />
                            <span>{inv.lead_analyst || 'Unassigned'}</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                            <Layers className="w-3 h-3 text-cyan-400" />
                            {inv.items_count ?? 0}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                            <MessageSquare className="w-3 h-3 text-amber-400" />
                            {inv.notes_count ?? 0}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                          {inv.created_at ? new Date(inv.created_at).toLocaleDateString('ar-EG') : '-'}
                        </td>
                        <td className="py-3.5 px-4 text-center whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              selectCase(inv.id);
                            }}
                            className="p-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/25 transition"
                            title="عرض تفاصيل القضية"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {total > limit && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 bg-slate-950/60 text-xs">
              <span className="text-slate-400">
                عرض {(page - 1) * limit + 1} إلى {Math.min(page * limit, total)} من أصل {total} قضية
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 text-slate-300"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
                <span className="font-mono text-slate-300 px-2">صفحة {page}</span>
                <button
                  disabled={page * limit >= total}
                  onClick={() => setPage((p) => p + 1)}
                  className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 text-slate-300"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Case Details Drawer / Modal */}
      {selectedCase && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-3xl bg-slate-950 border-r border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-left duration-200">
            {/* Drawer Header */}
            <div className="p-5 border-b border-slate-800 flex items-start justify-between bg-slate-900/60">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    {selectedCase.id}
                  </span>
                  <span className="text-xs text-slate-400">بواسطة {selectedCase.created_by}</span>
                </div>
                <h2 className="text-lg font-bold text-white">{selectedCase.title}</h2>
                {selectedCase.description && (
                  <p className="text-xs text-slate-400">{selectedCase.description}</p>
                )}
              </div>

              <button
                onClick={() => setSelectedCase(null)}
                className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Controls: Status & Priority & Lead */}
            <div className="px-5 py-3 border-b border-slate-800/80 bg-slate-900/30 flex flex-wrap items-center gap-4 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-medium">الحالة:</span>
                <select
                  value={selectedCase.status}
                  onChange={(e) => handleUpdateStatus(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-white rounded-lg px-2.5 py-1 focus:outline-none focus:border-purple-500 font-medium"
                >
                  <option value="open">مفتوحة حديثاً (Open)</option>
                  <option value="active_triage">فحص وتصنيف أولي (Active Triage)</option>
                  <option value="in_depth_analysis">تحليل متعمق (In-Depth Analysis)</option>
                  <option value="containment">احتواء واستجابة (Containment)</option>
                  <option value="closed">مغلقة ومؤرشفة (Closed)</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-medium">الأولوية:</span>
                <select
                  value={selectedCase.priority}
                  onChange={(e) => handleUpdatePriority(e.target.value)}
                  className="bg-slate-950 border border-slate-700 text-white rounded-lg px-2.5 py-1 focus:outline-none focus:border-purple-500 font-mono font-bold"
                >
                  <option value="P1">P1 حرجة جداً</option>
                  <option value="P2">P2 عالية</option>
                  <option value="P3">P3 متوسطة</option>
                  <option value="P4">P4 منخفضة</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5 text-slate-400 mr-auto">
                <UserIcon className="w-3.5 h-3.5 text-slate-500" />
                <span>المحلل: <strong className="text-slate-200">{selectedCase.lead_analyst}</strong></span>
              </div>
            </div>

            {/* Hypothesis Box if any */}
            {selectedCase.hypothesis && (
              <div className="mx-5 mt-4 p-3 rounded-xl bg-purple-950/30 border border-purple-900/50 text-xs text-purple-200">
                <span className="font-bold text-purple-300 block mb-1">الفرضية الجنائية ومسار التهديد:</span>
                {selectedCase.hypothesis}
              </div>
            )}

            {/* Drawer Tabs */}
            <div className="px-5 pt-4 flex border-b border-slate-800 gap-4 text-xs font-semibold">
              <button
                onClick={() => setActiveTab('items')}
                className={`pb-3 border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'items'
                    ? 'border-purple-500 text-purple-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>العناصر المرتبطة ({selectedCase.items?.length || 0})</span>
              </button>

              <button
                onClick={() => setActiveTab('notes')}
                className={`pb-3 border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'notes'
                    ? 'border-purple-500 text-purple-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <MessageSquare className="w-3.5 h-3.5" />
                <span>الملاحظات والتحليلات ({selectedCase.notes?.length || 0})</span>
              </button>

              <button
                onClick={() => setActiveTab('timeline')}
                className={`pb-3 border-b-2 transition flex items-center gap-1.5 ${
                  activeTab === 'timeline'
                    ? 'border-purple-500 text-purple-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <History className="w-3.5 h-3.5" />
                <span>الخط الزمني الجنائي ({selectedCase.timeline?.length || 0})</span>
              </button>
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {activeTab === 'items' && (
                <div className="space-y-4">
                  {/* Form to add item */}
                  <form onSubmit={handleAddItem} className="bg-slate-900 border border-slate-800 rounded-xl p-3 space-y-2">
                    <span className="text-xs font-semibold text-slate-300 block">ربط عنصر جديد بالقضية</span>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <select
                        value={addItemType}
                        onChange={(e) => setAddItemType(e.target.value)}
                        className="bg-slate-950 border border-slate-800 text-xs text-slate-200 rounded-lg p-2 focus:outline-none focus:border-purple-500"
                      >
                        <option value="incident">حادثة أمنية (Incident)</option>
                        <option value="asset">أصل شبكي (Asset)</option>
                        <option value="ioc">مؤشر تهديد (IOC)</option>
                        <option value="evidence">دليل جنائي (Evidence)</option>
                        <option value="log_snippet">مقتطف سجلات (Log)</option>
                      </select>

                      <input
                        type="text"
                        placeholder="معرف العنصر (e.g. INC-001)"
                        value={addItemId}
                        onChange={(e) => setAddItemId(e.target.value)}
                        className="bg-slate-950 border border-slate-800 text-xs text-white rounded-lg p-2 focus:outline-none focus:border-purple-500 font-mono"
                        required
                      />

                      <input
                        type="text"
                        placeholder="عنوان أو وصف العنصر"
                        value={addItemTitle}
                        onChange={(e) => setAddItemTitle(e.target.value)}
                        className="bg-slate-950 border border-slate-800 text-xs text-white rounded-lg p-2 focus:outline-none focus:border-purple-500"
                        required
                      />
                    </div>
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>إضافة العنصر</span>
                      </button>
                    </div>
                  </form>

                  {/* List of items */}
                  <div className="space-y-2">
                    {!selectedCase.items || selectedCase.items.length === 0 ? (
                      <div className="text-center py-8 text-slate-500 text-xs">
                        لا توجد عناصر مرتبطة بهذه القضية حتى الآن.
                      </div>
                    ) : (
                      selectedCase.items.map((item) => {
                        const badge = itemTypeBadges[item.item_type] || { label: item.item_type, color: 'text-slate-400 bg-slate-800 border-slate-700', icon: FileText };
                        const IconComp = badge.icon;
                        return (
                          <div
                            key={item.id}
                            className="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between gap-3 hover:border-slate-700 transition"
                          >
                            <div className="flex items-center gap-3">
                              <div className={`p-2 rounded-lg border ${badge.color}`}>
                                <IconComp className="w-4 h-4" />
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-xs font-bold text-white">{item.item_id}</span>
                                  <span className={`text-[10px] px-1.5 py-0.2 rounded border ${badge.color}`}>
                                    {badge.label}
                                  </span>
                                </div>
                                <div className="text-xs text-slate-300 mt-0.5">{item.title}</div>
                                <div className="text-[10px] text-slate-500 mt-1">
                                  أضيف بواسطة {item.added_by} في {new Date(item.added_at).toLocaleString('ar-EG')}
                                </div>
                              </div>
                            </div>

                            <button
                              onClick={() => handleRemoveItem(item.id)}
                              className="p-1.5 rounded-lg bg-slate-950 hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 border border-slate-800 hover:border-rose-500/30 transition"
                              title="فك ربط العنصر"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              )}

              {activeTab === 'notes' && (
                <div className="space-y-4">
                  {/* Form to add note */}
                  <form onSubmit={handleAddNote} className="space-y-2">
                    <textarea
                      placeholder="أضف ملاحظة تحليلية، فرضية جديدة، أو توثيق لنتائج الفحص..."
                      value={noteContent}
                      onChange={(e) => setNoteContent(e.target.value)}
                      rows={3}
                      className="w-full bg-slate-900 border border-slate-800 text-xs text-white rounded-xl p-3 focus:outline-none focus:border-purple-500 transition resize-none"
                      required
                    />
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center gap-1.5 transition"
                      >
                        <Send className="w-3.5 h-3.5" />
                        <span>تسجيل الملاحظة</span>
                      </button>
                    </div>
                  </form>

                  {/* List of notes */}
                  <div className="space-y-3">
                    {!selectedCase.notes || selectedCase.notes.length === 0 ? (
                      <div className="text-center py-8 text-slate-500 text-xs">
                        لا توجد ملاحظات مسجلة في ملف التحقيق حتى الآن.
                      </div>
                    ) : (
                      selectedCase.notes.map((note) => (
                        <div key={note.id} className="bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 space-y-1.5">
                          <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span className="font-semibold text-purple-400 flex items-center gap-1">
                              <UserIcon className="w-3 h-3" />
                              {note.author}
                            </span>
                            <span className="font-mono text-slate-500">
                              {new Date(note.created_at).toLocaleString('ar-EG')}
                            </span>
                          </div>
                          <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                            {note.content}
                          </p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}

              {activeTab === 'timeline' && (
                <div className="space-y-3">
                  {!selectedCase.timeline || selectedCase.timeline.length === 0 ? (
                    <div className="text-center py-8 text-slate-500 text-xs">
                      لا يوجد نشاط مسجل في الخط الزمني بعد.
                    </div>
                  ) : (
                    <div className="relative border-r border-slate-800 mr-3 space-y-4 py-2">
                      {selectedCase.timeline.map((tl) => (
                        <div key={tl.id} className="relative pr-6">
                          <div className="absolute -right-1.5 top-1 w-3 h-3 rounded-full bg-purple-500 border-2 border-slate-950" />
                          <div className="text-xs font-semibold text-white flex items-center gap-2">
                            <span>{tl.action}</span>
                            <span className="text-[10px] text-slate-500 font-mono">
                              {new Date(tl.timestamp).toLocaleString('ar-EG')}
                            </span>
                          </div>
                          {tl.details && <div className="text-xs text-slate-400 mt-0.5">{tl.details}</div>}
                          <div className="text-[10px] text-purple-400/80 mt-1">بواسطة: {tl.actor}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FolderKanban className="w-5 h-5 text-purple-400" />
                <span>فتح قضية تحقيق أمني جديدة</span>
              </h3>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateCase} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  عنوان قضية التحقيق <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  placeholder="مثال: تحقيق في محاولات وصول مشبوهة لخوادم الإنتاج"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">مستوى الأولوية</label>
                  <select
                    value={newPriority}
                    onChange={(e) => setNewPriority(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
                  >
                    <option value="P1">P1 - حرجة جداً (Critical)</option>
                    <option value="P2">P2 - عالية (High)</option>
                    <option value="P3">P3 - متوسطة (Medium)</option>
                    <option value="P4">P4 - منخفضة (Low)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">المحلل المسؤول</label>
                  <input
                    type="text"
                    placeholder="اسم المحلل (e.g. analyst1)"
                    value={newLead}
                    onChange={(e) => setNewLead(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">الفرضية المبدئية للتهديد</label>
                <textarea
                  rows={2}
                  placeholder="صياغة مبدئية لسيناريو الهجوم أو سبب فتح التحقيق..."
                  value={newHypothesis}
                  onChange={(e) => setNewHypothesis(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-white focus:outline-none focus:border-purple-500 resize-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">الوصف والملاحظات الإضافية</label>
                <textarea
                  rows={2}
                  placeholder="وصف مختصر لمجال التحقيق وسياق العمل..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-white focus:outline-none focus:border-purple-500 resize-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  الوسوم (مفصولة بفواصل)
                </label>
                <input
                  type="text"
                  placeholder="malware, lateral_movement, powershell"
                  value={newTags}
                  onChange={(e) => setNewTags(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
                >
                  إلغاء
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-xs font-semibold text-white transition flex items-center gap-1.5"
                >
                  {submitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>إنشاء ملف التحقيق</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
