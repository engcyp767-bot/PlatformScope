'use client';

import React from 'react';
import {
  UserCheck,
  UserX,
  Eye,
  Edit3,
  Trash2,
} from 'lucide-react';
import { User, Group } from '../../../lib/types';
import { useTranslation } from '../../../lib/i18n';

interface UserManagementTabProps {
  users: User[];
  groups: Group[];
  onSimulate: (user: User) => void;
  onEdit: (user: User) => void;
  onDelete: (userId: string) => void;
}

export function UserManagementTab({
  users,
  groups,
  onSimulate,
  onEdit,
  onDelete,
}: UserManagementTabProps) {
  const { lang } = useTranslation();

  return (
    <div className="glass-panel overflow-hidden border border-white/10 rounded-2xl">
      <div className="overflow-x-auto">
        <table className={`w-full text-xs ${lang === 'ar' ? 'text-right' : 'text-left'}`}>
          <thead className="bg-white/5 text-slate-400 border-b border-white/5 font-semibold">
            <tr>
              <th className="p-4">المستخدم</th>
              <th className="p-4">الاسم المعروض</th>
              <th className="p-4">الدور الوظيفي</th>
              <th className="p-4">نطاق البيانات</th>
              <th className="p-4">القسم / المجموعات</th>
              <th className="p-4">الحالة</th>
              <th className="p-4">الصلاحيات</th>
              <th className={`p-4 ${lang === 'ar' ? 'text-left' : 'text-right'}`}>الإجراءات</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-slate-300">
            {users.map((u) => (
              <tr key={u.id} className="hover:bg-white/5 transition-colors">
                <td className="p-4 font-bold text-white font-mono">{u.username}</td>
                <td className="p-4">{u.display_name}</td>
                <td className="p-4">
                  <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-blue-500/10 text-blue-300 border border-blue-500/20">
                    {u.role_label_ar || u.role_name || u.role_id || 'محلل'}
                  </span>
                </td>
                <td className="p-4">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/20">
                    {u.data_scope || 'own_shared'}
                  </span>
                </td>
                <td className="p-4">
                  <div className="flex flex-col gap-1">
                    <span className="text-white text-[11px]">{u.department || '—'}</span>
                    {u.groups && u.groups.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {u.groups.map((gid) => {
                          const grp = groups.find((g) => g.id === gid);
                          return (
                            <span
                              key={gid}
                              className="px-1.5 py-0.5 rounded text-[9px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-medium"
                            >
                              {grp ? grp.label_ar : gid}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </td>
                <td className="p-4">
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold ${
                      u.active
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }`}
                  >
                    {u.active ? <UserCheck className="w-3 h-3" /> : <UserX className="w-3 h-3" />}
                    <span>{u.active ? 'نشط' : 'معطل'}</span>
                  </span>
                </td>
                <td className="p-4 font-mono text-slate-400">
                  {u.permissions?.length || 0} صلاحية
                </td>
                <td className={`p-4 ${lang === 'ar' ? 'text-left space-x-reverse' : 'text-right'} space-x-1.5`}>
                  <button
                    onClick={() => onSimulate(u)}
                    className="p-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/20 transition-colors"
                    title="محاكاة الصلاحيات (View As User)"
                  >
                    <Eye className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => onEdit(u)}
                    className="p-1.5 rounded-lg bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 transition-colors"
                    title="تعديل المستخدم"
                  >
                    <Edit3 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => onDelete(u.id)}
                    className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-colors"
                    title="حذف المستخدم"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr>
                <td colSpan={8} className="p-8 text-center text-slate-500 text-xs">
                  لا يوجد مستخدمون مطابقون للبحث.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

