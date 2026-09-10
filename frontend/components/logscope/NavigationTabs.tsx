'use client';

import React from 'react';
import { ShieldAlert, Radio, ListFilter, Users, Crosshair, BarChart3 } from 'lucide-react';

export type LogScopeTab = 'incidents' | 'detections' | 'events' | 'entities' | 'mitre' | 'analytics';

interface TabItem {
  id: LogScopeTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  count?: number;
  highlight?: boolean;
}

interface NavigationTabsProps {
  activeTab: LogScopeTab;
  onChangeTab: (tab: LogScopeTab) => void;
  counts: {
    incidents?: number;
    detections?: number;
    events?: number;
    entities?: number;
    mitre?: number;
  };
}

export function NavigationTabs({ activeTab, onChangeTab, counts }: NavigationTabsProps) {
  const tabs: TabItem[] = [
    {
      id: 'incidents',
      label: 'الحوادث الأمنية (Incidents)',
      icon: ShieldAlert,
      count: counts.incidents,
      highlight: (counts.incidents || 0) > 0,
    },
    {
      id: 'detections',
      label: 'الكشفات والأنماط (Detections)',
      icon: Radio,
      count: counts.detections,
    },
    {
      id: 'events',
      label: 'الأحداث الفردية (Events)',
      icon: ListFilter,
      count: counts.events,
    },
    {
      id: 'entities',
      label: 'الكيانات المستهدفة (Entities)',
      icon: Users,
      count: counts.entities,
    },
    {
      id: 'mitre',
      label: 'مصفوفة MITRE ATT&CK',
      icon: Crosshair,
      count: counts.mitre,
    },
    {
      id: 'analytics',
      label: 'التدفق والإحصائيات (Analytics)',
      icon: BarChart3,
    },
  ];

  return (
    <div className="border-b border-white/10 pb-px overflow-x-auto scrollbar-none">
      <div className="flex items-center gap-2 min-w-max">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;

          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onChangeTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 rounded-t-xl text-xs font-bold transition-all relative ${
                isActive
                  ? 'text-emerald-400 bg-emerald-500/10 border-t border-x border-emerald-500/30 shadow-[0_-4px_12px_rgba(16,185,129,0.1)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border-t border-x border-transparent'
              }`}
            >
              <Icon
                className={`w-4 h-4 ${
                  isActive ? 'text-emerald-400' : tab.highlight ? 'text-rose-400' : 'text-slate-500'
                }`}
              />
              <span>{tab.label}</span>

              {tab.count !== undefined && (
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-extrabold ${
                    isActive
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : tab.highlight
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
                      : 'bg-white/10 text-slate-300'
                  }`}
                >
                  {tab.count.toLocaleString('en-US')}
                </span>
              )}

              {isActive && (
                <div className="absolute bottom-[-1px] left-0 right-0 h-[2px] bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
