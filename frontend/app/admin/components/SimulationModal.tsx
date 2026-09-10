'use client';

import React from 'react';
import {
  Shield,
  Eye,
  X,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { SimulatedAccess } from '../../../lib/types';

interface SimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
  loading: boolean;
  data: SimulatedAccess | null;
}

export function SimulationModal({ isOpen, onClose, loading, data }: SimulationModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl border-white/15 overflow-hidden rounded-2xl bg-dark-900">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <Eye className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">
                محاكاة الصلاحيات (View As User)
              </h3>
              <p className="text-xs text-slate-400">
                رؤية المنصة من منظور هذا المستخدم وتدقيق الصلاحيات الفعلية Server-Side
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {loading && (
            <div className="py-12 text-center text-slate-400 flex flex-col items-center gap-3">
              <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
              <span>جارٍ تجميع ومحاكاة صلاحيات المستخدم...</span>
            </div>
          )}

          {data && (
            <>
              {/* User Profile Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-xl bg-white/5 border border-white/10">
                <div>
                  <span className="text-slate-500 block text-[10px]">المستخدم</span>
                  <span className="font-bold text-white text-sm">{data.simulated_user.username}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">الدور الفعّال</span>
                  <span className="font-bold text-blue-400 text-sm">{data.simulated_user.role_label_ar}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">نطاق البيانات</span>
                  <span className="font-bold text-amber-300 text-sm">{data.simulated_user.scope_label_ar}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">القسم</span>
                  <span className="font-bold text-emerald-400 text-sm">{data.simulated_user.department || 'غير محدد'}</span>
                </div>
              </div>

              {/* Policy Evaluation Sample */}
              <div>
                <h4 className="font-bold text-white mb-2 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <span>عينة من نتائج فحص السياسات الأمنية (Policy Decisions):</span>
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(data.evaluation_sample).map(([action, allowed]) => (
                    <div
                      key={action}
                      className={`p-2.5 rounded-xl border flex items-center justify-between ${
                        allowed
                          ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
                          : 'bg-rose-500/10 border-rose-500/20 text-rose-300'
                      }`}
                    >
                      <span className="font-mono text-[11px]">{action}</span>
                      <span className="font-bold text-[11px] flex items-center gap-1">
                        {allowed ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                        <span>{allowed ? 'مسموح' : 'مرفوض'}</span>
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Effective Permissions List */}
              <div>
                <h4 className="font-bold text-white mb-2 flex items-center justify-between">
                  <span>الصلاحيات الفعّالة الإجمالية ({data.simulated_user.effective_permissions.length}):</span>
                  <span className="text-[10px] text-slate-500">ممنوحة عبر الدور + المجموعات + التخصيص</span>
                </h4>
                <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto p-3 bg-black/40 rounded-xl border border-white/5">
                  {data.simulated_user.effective_permissions.map((p) => (
                    <span
                      key={p}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        <div className="p-4 border-t border-white/10 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-white/10 hover:bg-white/15 text-white text-xs font-bold transition-colors"
          >
            إغلاق المحاكاة
          </button>
        </div>
      </div>
    </div>
  );
}

