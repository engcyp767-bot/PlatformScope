'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { ArrowLeft, X, RefreshCw, Filter, History } from 'lucide-react';
import { OperationHistoryItem } from '../lib/types';
import { getHistory } from '../lib/api';
import { useTranslation } from '../lib/i18n';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onItemClick?: () => void;
}

export function HistoryModal({ isOpen, onClose, onItemClick }: HistoryModalProps) {
  const { t } = useTranslation();
  const [historyItems, setHistoryItems] = useState<OperationHistoryItem[]>([]);
  const [filterApp, setFilterApp] = useState('');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const res = await getHistory();
      setHistoryItems(res.operations || []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    if (isOpen) {
      loadHistory();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const filteredHistory = historyItems.filter((item) => {
    const matchApp = !filterApp || item.application === filterApp;
    const matchSearch =
      !search ||
      `${item.job_id} ${item.source_system_label} ${item.data_type}`.toLowerCase().includes(search.toLowerCase());
    return matchApp && matchSearch;
  });

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="glass-panel w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl border-white/15 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <History className="w-5 h-5 text-primary" />
              {t('dashboard.history_title')}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {t('dashboard.history_desc')}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadHistory}
              disabled={loading}
              className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
              title="تحديث العمليات"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
              title="إغلاق"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-4 bg-dark-950/40 border-b border-white/5 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <select
              value={filterApp}
              onChange={(e) => setFilterApp(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-dark-950 border border-white/10 text-xs text-slate-200"
            >
              <option value="">{t('dashboard.all_apps')}</option>
              <option value="flowscope">FlowScope</option>
              <option value="threatscope">ThreatScope</option>
              <option value="logscope">LogScope</option>
            </select>
          </div>

          <input
            type="text"
            placeholder={t('dashboard.search_placeholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 min-w-[200px] px-3 py-1.5 rounded-lg bg-dark-950 border border-white/10 text-xs text-slate-200 placeholder-slate-500"
          />

          <span className="text-xs text-slate-400 font-mono">
            {filteredHistory.length} {t('dashboard.operations_count')}
          </span>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {filteredHistory.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-sm">
              {t('dashboard.no_operations')}
            </div>
          ) : (
            filteredHistory.map((item) => (
              <Link
                key={item.id}
                href={item.target_url}
                onClick={() => {
                  onClose();
                  if (onItemClick) onItemClick();
                }}
                className="p-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/5 hover:border-white/15 flex items-center justify-between transition-all group"
              >
                <div className="flex items-center gap-4">
                  <div
                    className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-xs ${
                      item.application === 'flowscope'
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : item.application === 'logscope'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    {item.application === 'flowscope' ? 'FS' : item.application === 'logscope' ? 'LS' : 'TS'}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white uppercase tracking-wide">
                        {item.job_id}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-white/10 text-slate-300">
                        {item.source_system_label}
                      </span>
                      <span className="text-xs text-slate-400">
                        {item.operation === 'analysis' ? t('dashboard.analysis_operation') : t('dashboard.scan_operation')}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1 flex items-center gap-3">
                      <span>{item.records} {t('dashboard.records')}</span>
                      <span>•</span>
                      <span>{new Date(item.timestamp).toLocaleString('en-US')}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-xs px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {item.status}
                  </span>
                  <ArrowLeft className="w-4 h-4 text-slate-400 group-hover:text-primary group-hover:-translate-x-1 transition-all" />
                </div>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
