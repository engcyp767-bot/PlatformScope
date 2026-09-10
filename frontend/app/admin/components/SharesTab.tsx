'use client';

import React from 'react';
import { ResourceShare } from '../../../lib/types';
import { useTranslation } from '../../../lib/i18n';

interface SharesTabProps {
  shares: ResourceShare[];
  onRevoke: (shareId: string) => void;
}

export function SharesTab({ shares, onRevoke }: SharesTabProps) {
  const { lang } = useTranslation();

  return (
    <div className="glass-panel overflow-hidden border border-white/10 rounded-2xl">
      <div className="overflow-x-auto">
        <table className={`w-full text-xs ${lang === 'ar' ? 'text-right' : 'text-left'}`}>
          <thead className="bg-white/5 text-slate-400 border-b border-white/5 font-semibold">
            <tr>
              <th className="p-4">نوع المورد</th>
              <th className="p-4">معرف المورد</th>
              <th className="p-4">مشارك بواسطة</th>
              <th className="p-4">الجهة المستفيدة</th>
              <th className="p-4">الصلاحيات الممنوحة</th>
              <th className="p-4">تاريخ المشاركة</th>
              <th className="p-4">تاريخ الانتهاء</th>
              <th className={`p-4 ${lang === 'ar' ? 'text-left' : 'text-right'}`}>الإجراء</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-slate-300">
            {shares.map((s) => (
              <tr key={s.id} className="hover:bg-white/5 transition-colors">
                <td className="p-4 font-bold text-white">
                  <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-300 border border-purple-500/20">
                    {s.resource_type}
                  </span>
                </td>
                <td className="p-4 font-mono text-slate-300">{s.resource_id}</td>
                <td className="p-4 text-slate-400">{s.shared_by}</td>
                <td className="p-4">
                  <span className="font-medium text-white">{s.grantee_id}</span>
                  <span className="text-[10px] text-slate-500 block">({s.grantee_type})</span>
                </td>
                <td className="p-4">
                  <div className="flex flex-wrap gap-1">
                    {s.permissions.map((p) => (
                      <span
                        key={p}
                        className="px-1.5 py-0.5 rounded text-[9px] bg-blue-500/10 text-blue-300 border border-blue-500/20 font-mono"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="p-4 text-slate-400">
                  {new Date(s.created_at).toLocaleDateString(lang === 'ar' ? 'ar-SA' : 'en-US')}
                </td>
                <td className="p-4 text-slate-400 font-mono">
                  {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'دائم (لا ينتهي)'}
                </td>
                <td className={`p-4 ${lang === 'ar' ? 'text-left' : 'text-right'}`}>
                  <button
                    onClick={() => onRevoke(s.id)}
                    className="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 text-[11px] font-bold transition-colors"
                  >
                    إلغاء المشاركة
                  </button>
                </td>
              </tr>
            ))}
            {shares.length === 0 && (
              <tr>
                <td colSpan={8} className="p-8 text-center text-slate-500 text-xs">
                  لا توجد موارد مشاركة نشطة حالياً.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

