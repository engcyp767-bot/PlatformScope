'use client';

import React from 'react';
import { LateralMovement } from '../../lib/types';
import { Network, Server, ArrowLeft } from 'lucide-react';

interface LateralMovementsListProps {
  movements: LateralMovement[];
  onPromote: (movementId: string) => void;
}

export function LateralMovementsList({ movements, onPromote }: LateralMovementsListProps) {
  if (movements.length === 0) {
    return (
      <div className="p-12 text-center rounded-2xl bg-dark-900/50 border border-white/10">
        <Network className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h4 className="text-base font-bold text-white mb-1">لا توجد حركات تنقل أفقي مرصودة</h4>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          يقوم المحرك برصد محطات القفز الوسيطة (Pivot Jumpboxes) واستخدام أوراق الاعتماد عبر بروتوكولات الإدارة مثل RDP و SMB.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {movements.map((m) => (
        <div
          key={m.movement_id}
          className="p-5 rounded-2xl bg-dark-900/80 border border-white/10 hover:border-white/20 transition-all shadow-lg"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white">قفزة تنقل أفقي عبر المحطة الوسيطة [{m.pivot_host}]</h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                    الخطورة: {m.risk_score}
                  </span>
                </div>
                <span className="text-xs text-slate-400">
                  تم رصد انتقال الحساب [{m.source_user}] إلى {m.hop_count} أجهزة داخلية مستهدفة.
                </span>
              </div>
            </div>

            <button
              onClick={() => onPromote(m.movement_id)}
              className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-xs font-bold text-amber-300 transition-colors"
            >
              ترقية إلى حادث أمني
            </button>
          </div>

          {/* Target Hosts Badges */}
          <div className="p-3 rounded-xl bg-dark-950 border border-white/5 flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 font-mono text-xs">
              <Server className="w-3.5 h-3.5" />
              <span>المحطة المصدر: {m.pivot_host}</span>
            </div>
            <ArrowLeft className="w-4 h-4 text-slate-500" />
            {m.target_hosts.map((target) => (
              <div
                key={target}
                className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 font-mono text-xs"
              >
                <Server className="w-3.5 h-3.5" />
                <span>{target}</span>
              </div>
            ))}
          </div>

          {/* Evidence lines */}
          <div className="mt-3 text-[11px] text-slate-400 space-y-1">
            {m.evidence.map((ev, i) => (
              <p key={i}>• {ev}</p>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
