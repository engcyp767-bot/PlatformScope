'use client';

import React from 'react';
import { Edit3, Trash2 } from 'lucide-react';
import { Group, Role } from '../../../lib/types';

interface GroupsTabProps {
  groups: Group[];
  roles: Role[];
  onEdit: (group: Group) => void;
  onDelete: (groupId: string) => void;
}

export function GroupsTab({ groups, roles, onEdit, onDelete }: GroupsTabProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-4">
      {groups.map((g) => (
        <div
          key={g.id}
          className="glass-panel p-6 rounded-2xl border border-white/10 flex flex-col justify-between hover:border-white/20 transition-all"
        >
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="px-2.5 py-0.5 rounded-lg text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                مجموعة عمل (Work Group)
              </span>
              <span className="text-[11px] font-mono text-slate-400">
                {g.members?.length || 0} أعضاء
              </span>
            </div>

            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <span>{g.label_ar}</span>
              <span className="text-xs text-slate-500 font-mono">({g.name})</span>
            </h3>

            <p className="text-xs text-slate-400 mt-2 line-clamp-2 leading-relaxed">
              {g.description || 'لا يوجد وصف لمجموعة العمل هذه.'}
            </p>

            <div className="mt-4 pt-3 border-t border-white/5 space-y-2 text-xs">
              <div className="flex items-center justify-between text-slate-400">
                <span>القسم التابع:</span>
                <span className="font-bold text-slate-200">{g.department || 'غير محدد'}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>نطاق البيانات:</span>
                <span className="font-bold text-amber-300 font-mono">{g.default_scope}</span>
              </div>
            </div>

            {/* Group Roles */}
            {g.roles && g.roles.length > 0 && (
              <div className="mt-3 pt-3 border-t border-white/5">
                <span className="text-[11px] text-slate-400 block mb-1.5">
                  الأدوار الممنوحة لأعضاء المجموعة:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {g.roles.map((rid) => {
                    const r = roles.find((role) => role.id === rid);
                    return (
                      <span
                        key={rid}
                        className="px-2 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-300 border border-blue-500/20 font-medium"
                      >
                        {r ? r.label_ar : rid}
                      </span>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-end gap-2">
            <button
              onClick={() => onEdit(g)}
              className="p-1.5 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 transition-colors"
              title="تعديل المجموعة"
            >
              <Edit3 className="w-4 h-4" />
            </button>
            <button
              onClick={() => onDelete(g.id)}
              className="p-1.5 rounded-xl bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 transition-colors"
              title="حذف المجموعة"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>
      ))}
      {groups.length === 0 && (
        <div className="col-span-2 p-8 text-center text-slate-500 text-xs glass-panel rounded-2xl border border-white/10">
          لا توجد مجموعات عمل مسجلة.
        </div>
      )}
    </div>
  );
}

