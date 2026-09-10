'use client';

import React from 'react';
import { InsiderThreat } from '../../lib/types';
import { UserCheck, ShieldAlert } from 'lucide-react';

interface InsiderThreatsListProps {
  threats: InsiderThreat[];
}

export function InsiderThreatsList({ threats }: InsiderThreatsListProps) {
  if (threats.length === 0) {
    return (
      <div className="p-12 text-center rounded-2xl bg-dark-900/50 border border-white/10">
        <UserCheck className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h4 className="text-base font-bold text-white mb-1">لا توجد مؤشرات تهديد داخلي شاذة</h4>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          يقوم المحرك بتحليل وصول المستخدمين للأصول الحساسة ومطابقة الأنماط مع خط الأساس السلوكي.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {threats.map((t) => (
        <div
          key={t.threat_id}
          className="p-5 rounded-2xl bg-dark-900/80 border border-white/10 hover:border-white/20 transition-all shadow-lg"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white">اشتباه نشاط شاذ للحساب [{t.username}]</h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-500/20 text-purple-400 border border-purple-500/30">
                    الخطورة: {t.risk_score}
                  </span>
                </div>
                <span className="text-xs text-slate-400">
                  نوع الشذوذ: {t.anomaly_type === 'multi_critical_access' ? 'وصول متزامن لأصول حرجة متعددة' : 'وصول غير معتاد'}
                </span>
              </div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-dark-950 border border-white/5 mb-3 flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400">الأصول المستهدفة:</span>
            {t.accessed_assets.map((asset) => (
              <span
                key={asset}
                className="px-2.5 py-1 rounded bg-white/5 border border-white/10 text-slate-200 text-xs font-mono"
              >
                {asset}
              </span>
            ))}
          </div>

          <div className="text-[11px] text-slate-400 space-y-1">
            {t.evidence.map((ev, i) => (
              <p key={i}>• {ev}</p>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
