'use client';

import React from 'react';
import { Search, Filter, X, RotateCcw } from 'lucide-react';

export interface ActiveFilters {
  severity?: string;
  action?: string;
  conclusion_level?: string;
  incident_id?: string;
  event_id?: string;
  user?: string;
  ip?: string;
  device?: string;
}

interface AdvancedFilterBarProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  filters: ActiveFilters;
  onFilterChange: (filters: ActiveFilters) => void;
  onResetFilters: () => void;
  totalRecordsCount?: number;
}

export function AdvancedFilterBar({
  searchQuery,
  onSearchChange,
  filters,
  onFilterChange,
  onResetFilters,
  totalRecordsCount,
}: AdvancedFilterBarProps) {
  const activeFiltersCount =
    Object.values(filters).filter(Boolean).length + (searchQuery.trim() ? 1 : 0);

  const updateFilter = (key: keyof ActiveFilters, value: string) => {
    const updated = { ...filters };
    if (!value || value === 'all') {
      delete updated[key];
    } else {
      updated[key] = value;
    }
    onFilterChange(updated);
  };

  const removeFilter = (key: keyof ActiveFilters) => {
    const updated = { ...filters };
    delete updated[key];
    onFilterChange(updated);
  };

  return (
    <div className="space-y-3 bg-dark-900/60 p-4 rounded-2xl border border-white/10">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[240px]">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="بحث نصي فوري (IP، مستخدم، معرف الحدث، التوصيف الجنائي...)"
            className="w-full bg-black/40 border border-white/10 rounded-xl px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 focus:outline-none pr-9 pl-8 transition-colors"
          />
          <Search className="w-4 h-4 text-slate-400 absolute right-3 top-2.5" />
          {searchQuery && (
            <button
              type="button"
              onClick={() => onSearchChange('')}
              className="absolute left-2.5 top-2.5 text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Severity Selector */}
        <div className="flex items-center gap-2">
          <select
            value={filters.severity || 'all'}
            onChange={(e) => updateFilter('severity', e.target.value)}
            className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:border-emerald-500 focus:outline-none"
          >
            <option value="all">كافة مستويات الخطورة</option>
            <option value="حرج">حرج (Critical)</option>
            <option value="مرتفع">مرتفع (High)</option>
            <option value="متوسط">متوسط (Medium)</option>
            <option value="منخفض">منخفض (Low)</option>
          </select>

          {/* Action Selector */}
          <select
            value={filters.action || 'all'}
            onChange={(e) => updateFilter('action', e.target.value)}
            className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:border-emerald-500 focus:outline-none"
          >
            <option value="all">كافة الإجراءات</option>
            <option value="block">إحباط ومنع (Block / Drop)</option>
            <option value="allow">سماح ومرور (Allow / Permit)</option>
            <option value="alert">تنبيه فقط (Alert)</option>
          </select>

          {/* Conclusion Level Selector */}
          <select
            value={filters.conclusion_level || 'all'}
            onChange={(e) => updateFilter('conclusion_level', e.target.value)}
            className="bg-black/40 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-300 focus:border-emerald-500 focus:outline-none"
          >
            <option value="all">كافة مستويات الاستنتاج</option>
            <option value="confirmed">مؤكد بالأدلة (Confirmed)</option>
            <option value="likely_successful">يرجح نجاحه (Likely Successful)</option>
            <option value="correlated_suspicious">نشاط مترابط مشبوه</option>
            <option value="observed">مرصود (Observed)</option>
          </select>

          {activeFiltersCount > 0 && (
            <button
              type="button"
              onClick={onResetFilters}
              className="flex items-center gap-1 px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-bold text-slate-300 hover:text-white transition-colors"
              title="إلغاء كافة الفلاتر"
            >
              <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
              <span>إعادة ضبط</span>
            </button>
          )}
        </div>
      </div>

      {/* Active Filter Chips */}
      {activeFiltersCount > 0 && (
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-white/5 text-xs">
          <span className="text-slate-400 text-[11px] font-medium">الفلاتر المطبقة:</span>

          {searchQuery.trim() && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px]">
              <span>بحث: &quot;{searchQuery}&quot;</span>
              <button type="button" onClick={() => onSearchChange('')}>
                <X className="w-3 h-3 text-emerald-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.severity && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[11px]">
              <span>الخطورة: {filters.severity}</span>
              <button type="button" onClick={() => removeFilter('severity')}>
                <X className="w-3 h-3 text-rose-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.action && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 text-[11px]">
              <span>الإجراء: {filters.action}</span>
              <button type="button" onClick={() => removeFilter('action')}>
                <X className="w-3 h-3 text-cyan-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.conclusion_level && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-purple-500/15 border border-purple-500/30 text-purple-300 text-[11px]">
              <span>الاستنتاج: {filters.conclusion_level}</span>
              <button type="button" onClick={() => removeFilter('conclusion_level')}>
                <X className="w-3 h-3 text-purple-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.incident_id && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px] font-mono">
              <span>الحادثة: {filters.incident_id}</span>
              <button type="button" onClick={() => removeFilter('incident_id')}>
                <X className="w-3 h-3 text-emerald-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.user && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px]">
              <span>المستخدم: {filters.user}</span>
              <button type="button" onClick={() => removeFilter('user')}>
                <X className="w-3 h-3 text-emerald-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.ip && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono">
              <span>IP: {filters.ip}</span>
              <button type="button" onClick={() => removeFilter('ip')}>
                <X className="w-3 h-3 text-cyan-400 hover:text-white" />
              </button>
            </span>
          )}

          {filters.device && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-purple-500/15 border border-purple-500/30 text-purple-300 text-[11px] font-mono">
              <span>الجهاز: {filters.device}</span>
              <button type="button" onClick={() => removeFilter('device')}>
                <X className="w-3 h-3 text-purple-400 hover:text-white" />
              </button>
            </span>
          )}
        </div>
      )}
    </div>
  );
}
