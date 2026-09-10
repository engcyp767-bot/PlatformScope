'use client';

import React from 'react';
import { Copy, Edit3, Trash2 } from 'lucide-react';
import { Role } from '../../../lib/types';

interface RolesTabProps {
  roles: Role[];
  onClone: (role: Role) => void;
  onEdit: (role: Role) => void;
  onDelete: (roleId: string) => void;
}

export function RolesTab({ roles, onClone, onEdit, onDelete }: RolesTabProps) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {roles.map((r) => (
          <div
            key={r.id}
            className="glass-panel p-5 rounded-2xl border border-white/10 flex flex-col justify-between hover:border-white/20 transition-all"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-3">
                <span
                  className={`px-2 py-0.5 rounded-lg text-[10px] font-bold ${
                    r.is_builtin
                      ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                      : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  }`}
                >
                  {r.is_builtin ? 'دور قياسي مدمج' : 'دور مخصص'}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  {r.permissions?.length || 0} صلاحية
                </span>
              </div>

              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>{r.label_ar}</span>
                <span className="text-xs text-slate-500 font-mono">({r.name})</span>
              </h3>

              <p className="text-xs text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                {r.description || 'لا يوجد وصف متاح لهذا الدور.'}
              </p>

              <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] text-slate-400">
                <span>النطاق الافتراضي:</span>
                <span className="font-bold text-amber-300 font-mono">{r.default_scope}</span>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-end gap-2">
              <button
                onClick={() => onClone(r)}
                className="px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-bold flex items-center gap-1.5 transition-colors"
                title="استنساخ دور جديد من هذا الدور"
              >
                <Copy className="w-3.5 h-3.5 text-blue-400" />
                <span>استنساخ</span>
              </button>
              {!r.is_builtin && (
                <>
                  <button
                    onClick={() => onEdit(r)}
                    className="p-1.5 rounded-xl bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 transition-colors"
                    title="تعديل الدور"
                  >
                    <Edit3 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => onDelete(r.id)}
                    className="p-1.5 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 transition-colors"
                    title="حذف الدور"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
      {roles.length === 0 && (
        <div className="p-8 text-center text-slate-500 text-xs glass-panel rounded-2xl border border-white/10">
          لا توجد أدوار مسجلة.
        </div>
      )}
    </div>
  );
}

