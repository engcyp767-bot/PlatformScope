'use client';

import React from 'react';
import { AttackChain } from '../../lib/types';
import { ShieldAlert, ArrowLeft, Activity } from 'lucide-react';

interface AttackChainsListProps {
  chains: AttackChain[];
  onPromote: (chainId: string) => void;
  onViewInGraph: (chain: AttackChain) => void;
}

export function AttackChainsList({ chains, onPromote, onViewInGraph }: AttackChainsListProps) {
  if (chains.length === 0) {
    return (
      <div className="p-12 text-center rounded-2xl bg-dark-900/50 border border-white/10">
        <Activity className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h4 className="text-base font-bold text-white mb-1">لا توجد سلاسل هجوم نشطة حالياً</h4>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          يقوم المحرك برصد السلاسل المترابطة تلقائياً عند تتابع أحداث الوصول، تصعيد الصلاحيات، وتشغيل العمليات المشبوهة.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {chains.map((chain) => (
        <div
          key={chain.chain_id}
          className="p-5 rounded-2xl bg-dark-900/80 border border-white/10 hover:border-white/20 transition-all shadow-lg"
        >
          {/* Chain Top Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white">{chain.title}</h3>
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                    الخطورة: {chain.risk_score}
                  </span>
                </div>
                <span className="text-xs text-slate-400">{chain.description}</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => onViewInGraph(chain)}
                className="px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition-colors"
              >
                معاينة في الرسم
              </button>
              <button
                onClick={() => onPromote(chain.chain_id)}
                className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-xs font-bold text-red-300 transition-colors shadow-sm shadow-red-500/10"
              >
                ترقية إلى حادث أمني (SOC Incident)
              </button>
            </div>
          </div>

          {/* Attack Chain Stages Progression */}
          <div className="p-4 rounded-xl bg-dark-950/80 border border-white/5 mb-3">
            <h4 className="text-[11px] font-bold text-slate-400 uppercase mb-3">مراحل تتابع الهجوم (Chain Stages):</h4>
            <div className="flex flex-wrap items-center gap-2">
              {chain.stages.map((stg, idx) => (
                <React.Fragment key={stg.stage_number}>
                  <div className="flex items-center gap-2 p-2.5 rounded-lg bg-white/5 border border-white/10">
                    <span className="w-5 h-5 rounded-full bg-primary/20 text-primary font-bold text-[10px] flex items-center justify-center font-mono">
                      {stg.stage_number}
                    </span>
                    <div>
                      <span className="text-xs font-bold text-slate-200 block">{stg.title_ar}</span>
                      <span className="text-[10px] text-slate-400 font-mono">{stg.entity}</span>
                    </div>
                  </div>
                  {idx < chain.stages.length - 1 && (
                    <ArrowLeft className="w-4 h-4 text-slate-500 shrink-0" />
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Involved Entities Summary */}
          <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400 pt-2 border-t border-white/5 font-mono">
            <span>المستخدمون: <strong className="text-slate-200">{chain.involved_entities.users?.join(', ') || 'N/A'}</strong></span>
            <span>الأجهزة: <strong className="text-slate-200">{chain.involved_entities.hosts?.join(', ') || 'N/A'}</strong></span>
            <span>العمليات: <strong className="text-slate-200">{chain.involved_entities.processes?.join(', ') || 'N/A'}</strong></span>
            {chain.involved_entities.external_ips && chain.involved_entities.external_ips.length > 0 && (
              <span>C2 الخارجي: <strong className="text-red-400">{chain.involved_entities.external_ips.join(', ')}</strong></span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
