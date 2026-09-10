'use client';

import React, { useState } from 'react';
import { IncidentCard, IncidentData } from './IncidentCard';
import { ShieldCheck, ShieldAlert, Filter, Search } from 'lucide-react';

interface IncidentDashboardProps {
  incidents: IncidentData[];
  onSelectIncident: (incident: IncidentData) => void;
  onFilterEntity?: (type: 'user' | 'ip' | 'device', value: string) => void;
}

export function IncidentDashboard({
  incidents,
  onSelectIncident,
  onFilterEntity,
}: IncidentDashboardProps) {
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredIncidents = incidents.filter((inc) => {
    if (filterSeverity !== 'all' && inc.severity !== filterSeverity) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = inc.incident_id.toLowerCase().includes(q);
      const matchTitle = inc.title_ar.toLowerCase().includes(q);
      const matchDesc = inc.description_ar.toLowerCase().includes(q);
      const matchUser = inc.usernames?.some((u) => u.toLowerCase().includes(q));
      const matchIp = inc.source_ips?.some((ip) => ip.includes(q));
      return matchId || matchTitle || matchDesc || matchUser || matchIp;
    }
    return true;
  });

  const criticalCount = incidents.filter((i) => i.severity === 'حرج').length;
  const highCount = incidents.filter((i) => i.severity === 'مرتفع').length;

  if (incidents.length === 0) {
    return (
      <div className="rounded-2xl border border-white/10 bg-dark-900/40 p-12 text-center space-y-3">
        <div className="mx-auto w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 grid place-items-center">
          <ShieldCheck className="w-6 h-6" />
        </div>
        <h3 className="text-base font-bold text-white">لم يتم رصد حوادث أمنية مترابطة متعددة المراحل</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
          جميع السجلات المحللة تخضع للرصد الفردي أو الكشف الموضعي، دون تشكل سلاسل هجوم زمنية مترابطة تتجاوز عتبات الحوادث المركبة.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Filter & Quick Metrics Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-dark-900/50 p-4 rounded-2xl border border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/25 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-extrabold text-white">
              لوحة الحوادث الأمنية المكتشفة ({incidents.length})
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              سلاسل هجوم وتحركات أمنية تم ربط أحداثها زمنياً وسياقياً عبر محرك الترابط
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="بحث في الحوادث، المستخدم، أو الـ IP..."
              className="bg-black/30 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 focus:outline-none w-56 pr-8"
            />
            <Search className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-2.5" />
          </div>

          <div className="flex items-center gap-1.5 bg-black/30 p-1 rounded-xl border border-white/10 text-xs">
            <button
              type="button"
              onClick={() => setFilterSeverity('all')}
              className={`px-3 py-1 rounded-lg font-bold transition-colors ${
                filterSeverity === 'all' ? 'bg-white/10 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              الكل ({incidents.length})
            </button>
            <button
              type="button"
              onClick={() => setFilterSeverity('حرج')}
              className={`px-3 py-1 rounded-lg font-bold transition-colors ${
                filterSeverity === 'حرج' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              الحرجة ({criticalCount})
            </button>
            <button
              type="button"
              onClick={() => setFilterSeverity('مرتفع')}
              className={`px-3 py-1 rounded-lg font-bold transition-colors ${
                filterSeverity === 'مرتفع' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              المرتفعة ({highCount})
            </button>
          </div>
        </div>
      </div>

      {/* Grid of Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {filteredIncidents.map((incident) => (
          <IncidentCard
            key={incident.incident_id}
            incident={incident}
            onSelectIncident={onSelectIncident}
            onFilterEntity={onFilterEntity}
          />
        ))}
      </div>

      {filteredIncidents.length === 0 && (
        <div className="p-8 text-center text-slate-400 text-xs bg-black/20 rounded-xl border border-white/5">
          لا توجد حوادث تطابق معايير البحث والفلترة المحددة.
        </div>
      )}
    </div>
  );
}
