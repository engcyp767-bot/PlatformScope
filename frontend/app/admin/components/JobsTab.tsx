'use client';

import React, { useEffect, useState, useCallback } from 'react';
import {
  ListTodo,
  RefreshCw,
  Search,
  Filter,
  Play,
  RotateCcw,
  XCircle,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Zap,
  Server,
  Terminal,
} from 'lucide-react';
import { getEnterpriseTasks, cancelEnterpriseTask, retryEnterpriseTask } from '../../../lib/api';
import { EnterpriseTaskItem, EnterpriseTaskMetrics } from '../../../lib/types';

export function JobsTab() {
  const [tasks, setTasks] = useState<EnterpriseTaskItem[]>([]);
  const [metrics, setMetrics] = useState<EnterpriseTaskMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [selectedTask, setSelectedTask] = useState<EnterpriseTaskItem | null>(null);

  const fetchTasks = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getEnterpriseTasks({
        status: statusFilter || undefined,
        search: search || undefined,
        limit: 50,
      });
      setTasks(res.tasks || []);
      if (res.metrics) setMetrics(res.metrics);
    } catch (err) {
      console.error('Failed to load enterprise tasks:', err);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, search]);

  useEffect(() => {
    fetchTasks();
    const timer = setInterval(fetchTasks, 8000);
    return () => clearInterval(timer);
  }, [fetchTasks]);

  const handleCancel = async (taskId: string) => {
    setActionLoading(taskId);
    try {
      await cancelEnterpriseTask(taskId);
      await fetchTasks();
    } catch (err) {
      console.error('Failed to cancel task:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRetry = async (taskId: string) => {
    setActionLoading(taskId);
    try {
      await retryEnterpriseTask(taskId);
      await fetchTasks();
    } catch (err) {
      console.error('Failed to retry task:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" /> مكتمل
          </span>
        );
      case 'running':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-blue-500/15 text-blue-300 border border-blue-500/30 animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin" /> قيد المعالجة
          </span>
        );
      case 'queued':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <Clock className="w-3 h-3" /> في الانتظار
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30">
            <AlertTriangle className="w-3 h-3" /> فاشل
          </span>
        );
      case 'cancelled':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
            <XCircle className="w-3 h-3" /> ملغي
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 rounded-full text-[11px] font-bold bg-slate-800 text-slate-300">
            {status}
          </span>
        );
    }
  };

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-black bg-rose-500/20 text-rose-300 border border-rose-500/30">
            حرج (P1)
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-black bg-amber-500/20 text-amber-300 border border-amber-500/30">
            عالي (P2)
          </span>
        );
      case 'NORMAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-blue-300 border border-blue-500/20">
            عادي (P3)
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">
            منخفض
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-white/10 bg-gradient-to-r from-amber-900/10 via-dark-900 to-dark-900">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
              <ListTodo className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>إدارة المهام والوظائف الخلفية (Background Tasks & Workers)</span>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  طابور المهام الدائم (SQLite WAL)
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                متابعة لحظية لمهام التحليل الجنائي، فحص الأدلة، التصدير، معالجة السجلات، والتحكم الفوري بالإلغاء وإعادة المحاولة.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchTasks}
              disabled={loading}
              className="px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white text-xs font-bold transition-all flex items-center gap-2"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>تحديث الطابور</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
        <div className="glass-panel p-4 rounded-xl border border-white/10 space-y-1">
          <div className="text-slate-400 text-[11px]">عمال المعالجة</div>
          <div className="text-xl font-black text-white">{metrics?.active_workers || 0} Worker</div>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-white/10 space-y-1">
          <div className="text-slate-400 text-[11px]">في الانتظار</div>
          <div className="text-xl font-black text-amber-400">{metrics?.queued_tasks || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-white/10 space-y-1">
          <div className="text-slate-400 text-[11px]">قيد التنفيذ</div>
          <div className="text-xl font-black text-blue-400">{metrics?.running_tasks || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-white/10 space-y-1">
          <div className="text-slate-400 text-[11px]">مكتملة بنجاح</div>
          <div className="text-xl font-black text-emerald-400">{metrics?.completed_tasks || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-white/10 space-y-1">
          <div className="text-slate-400 text-[11px]">مهام فاشلة</div>
          <div className="text-xl font-black text-rose-400">{metrics?.failed_tasks || 0}</div>
        </div>
        <div className="glass-panel p-4 rounded-xl border border-white/10 space-y-1">
          <div className="text-slate-400 text-[11px]">إجمالي المهام</div>
          <div className="text-xl font-black text-purple-400">{metrics?.total_submitted || 0}</div>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="بحث باسم المهمة أو المعرّف..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-3 pr-10 py-2 rounded-xl bg-slate-900 border border-white/10 text-white placeholder-slate-500 text-xs focus:outline-hidden focus:border-amber-500/50"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto max-w-full pb-1 sm:pb-0">
          {[
            { id: '', label: 'الكل' },
            { id: 'running', label: 'قيد التنفيذ' },
            { id: 'queued', label: 'في الانتظار' },
            { id: 'completed', label: 'مكتمل' },
            { id: 'failed', label: 'فاشل' },
            { id: 'cancelled', label: 'ملغي' },
          ].map((pill) => (
            <button
              key={pill.id}
              onClick={() => setStatusFilter(pill.id)}
              className={`px-3 py-1.5 rounded-lg font-bold transition-colors whitespace-nowrap ${
                statusFilter === pill.id
                  ? 'bg-amber-600 text-white shadow-sm'
                  : 'bg-white/5 text-slate-400 hover:text-white border border-white/5'
              }`}
            >
              {pill.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tasks Table */}
      <div className="glass-panel rounded-2xl border border-white/10 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-right text-xs">
            <thead className="bg-white/5 border-b border-white/10 text-slate-400 font-bold">
              <tr>
                <th className="px-5 py-3.5">معرف المهمة والاسم</th>
                <th className="px-5 py-3.5">الأولوية</th>
                <th className="px-5 py-3.5">الحالة</th>
                <th className="px-5 py-3.5">الإنجاز اللحظي</th>
                <th className="px-5 py-3.5">المدة والزمن</th>
                <th className="px-5 py-3.5 text-center">الإجراءات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {tasks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-500">
                    {loading ? 'جاري تحميل المهام...' : 'لا توجد مهام مطابقة للشروط الحالية.'}
                  </td>
                </tr>
              ) : (
                tasks.map((task) => {
                  const isActionBusy = actionLoading === task.id;
                  return (
                    <tr key={task.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-5 py-4">
                        <div className="font-bold text-white font-mono text-sm">{task.name}</div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">{task.id}</div>
                      </td>
                      <td className="px-5 py-4">{getPriorityBadge(task.priority)}</td>
                      <td className="px-5 py-4">{getStatusBadge(task.status)}</td>
                      <td className="px-5 py-4 w-52">
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-[11px]">
                            <span className="text-slate-400 truncate max-w-[140px]" title={task.step_message}>
                              {task.step_message || 'جاهز'}
                            </span>
                            <span className="font-mono text-white font-bold">{task.progress}%</span>
                          </div>
                          <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                            <div
                              className={`h-full transition-all duration-300 ${
                                task.status === 'completed'
                                  ? 'bg-emerald-500'
                                  : task.status === 'failed'
                                  ? 'bg-rose-500'
                                  : task.status === 'cancelled'
                                  ? 'bg-slate-600'
                                  : 'bg-amber-500'
                              }`}
                              style={{ width: `${task.progress}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="px-5 py-4 text-[11px] font-mono text-slate-400">
                        <div>{new Date(task.created_at).toLocaleTimeString()}</div>
                        <div className="text-slate-500 text-[10px]">
                          {task.duration_ms > 0 ? `${task.duration_ms} ms` : '—'}
                        </div>
                      </td>
                      <td className="px-5 py-4 text-center">
                        <div className="flex items-center justify-center gap-1.5">
                          {(task.status === 'queued' || task.status === 'running') && (
                            <button
                              onClick={() => handleCancel(task.id)}
                              disabled={isActionBusy}
                              className="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[11px] font-bold transition-all disabled:opacity-50 flex items-center gap-1"
                              title="إلغاء المهمة"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>إلغاء</span>
                            </button>
                          )}

                          {(task.status === 'failed' || task.status === 'cancelled') && (
                            <button
                              onClick={() => handleRetry(task.id)}
                              disabled={isActionBusy}
                              className="px-2.5 py-1 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[11px] font-bold transition-all disabled:opacity-50 flex items-center gap-1"
                              title="إعادة المحاولة"
                            >
                              <RotateCcw className="w-3.5 h-3.5" />
                              <span>إعادة</span>
                            </button>
                          )}

                          <button
                            onClick={() => setSelectedTask(task)}
                            className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
                            title="عرض التفاصيل"
                          >
                            <Terminal className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Details Modal */}
      {selectedTask && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-xl p-6 rounded-2xl border border-white/15 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center gap-2 font-bold text-white text-sm">
                <Terminal className="w-4 h-4 text-amber-400" />
                <span>تفاصيل المهمة: {selectedTask.name}</span>
              </div>
              <button
                onClick={() => setSelectedTask(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3 bg-white/5 p-3 rounded-xl">
                <div>
                  <span className="text-slate-500">معرف المهمة:</span>
                  <div className="text-slate-200 mt-0.5">{selectedTask.id}</div>
                </div>
                <div>
                  <span className="text-slate-500">الحالة:</span>
                  <div className="mt-0.5">{getStatusBadge(selectedTask.status)}</div>
                </div>
                <div>
                  <span className="text-slate-500">زمن الإنشاء:</span>
                  <div className="text-slate-300 mt-0.5">{selectedTask.created_at}</div>
                </div>
                <div>
                  <span className="text-slate-500">زمن الانتهاء:</span>
                  <div className="text-slate-300 mt-0.5">{selectedTask.completed_at || '—'}</div>
                </div>
              </div>

              {selectedTask.error && (
                <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300">
                  <div className="font-bold mb-1">تفاصيل الخطأ:</div>
                  <pre className="whitespace-pre-wrap text-[11px]">{selectedTask.error}</pre>
                </div>
              )}

              {selectedTask.result && (
                <div className="space-y-1">
                  <div className="text-slate-400 font-bold">النتيجة المُعادة (Result):</div>
                  <pre className="p-3 rounded-xl bg-black/50 border border-white/10 text-emerald-400 text-[11px] overflow-x-auto">
                    {JSON.stringify(selectedTask.result, null, 2)}
                  </pre>
                </div>
              )}

              {selectedTask.payload && Object.keys(selectedTask.payload).length > 0 && (
                <div className="space-y-1">
                  <div className="text-slate-400 font-bold">حمولة المهمة (Payload):</div>
                  <pre className="p-3 rounded-xl bg-black/50 border border-white/10 text-slate-300 text-[11px] overflow-x-auto">
                    {JSON.stringify(selectedTask.payload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

