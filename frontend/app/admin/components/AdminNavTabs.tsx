'use client';

import React from 'react';
import {
  Users,
  Key,
  Layers,
  ShieldAlert,
  Share2,
  ScrollText,
  SlidersHorizontal,
  Activity,
  ListTodo,
  Bell,
  ShieldCheck,
} from 'lucide-react';
import { AdminTab } from './types';

interface AdminNavTabsProps {
  activeTab: AdminTab;
  onTabChange: (tab: AdminTab) => void;
  counts: {
    users: number;
    roles: number;
    groups: number;
    scopes: number;
    shares: number;
  };
}

export function AdminNavTabs({ activeTab, onTabChange, counts }: AdminNavTabsProps) {
  const tabs = [
    {
      id: 'users' as AdminTab,
      label: 'المستخدمون',
      count: counts.users,
      icon: Users,
      color: 'purple',
    },
    {
      id: 'roles' as AdminTab,
      label: 'الأدوار والمصفوفة',
      count: counts.roles,
      icon: Key,
      color: 'blue',
    },
    {
      id: 'groups' as AdminTab,
      label: 'مجموعات العمل',
      count: counts.groups,
      icon: Layers,
      color: 'emerald',
    },
    {
      id: 'data-access' as AdminTab,
      label: 'نطاق البيانات',
      count: counts.scopes,
      icon: ShieldAlert,
      color: 'amber',
    },
    {
      id: 'shares' as AdminTab,
      label: 'الموارد المشتركة',
      count: counts.shares,
      icon: Share2,
      color: 'rose',
    },
    {
      id: 'jobs' as AdminTab,
      label: 'المهام والوظائف',
      icon: ListTodo,
      color: 'amber',
    },
    {
      id: 'notifications' as AdminTab,
      label: 'الإشعارات والتنبيهات',
      icon: Bell,
      color: 'purple',
    },
    {
      id: 'audit' as AdminTab,
      label: 'سجلات التدقيق',
      icon: ScrollText,
      color: 'cyan',
    },
    {
      id: 'settings' as AdminTab,
      label: 'إعدادات النظام',
      icon: SlidersHorizontal,
      color: 'slate',
    },
    {
      id: 'health' as AdminTab,
      label: 'صحة المنصة',
      icon: Activity,
      color: 'emerald',
    },
    {
      id: 'licensing' as AdminTab,
      label: 'الترخيص وفترة التجربة',
      icon: ShieldCheck,
      color: 'purple',
    },
  ];

  return (
    <div className="flex items-center gap-1.5 p-1 bg-white/5 rounded-2xl border border-white/10 overflow-x-auto max-w-full scrollbar-none">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;

        return (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
              isActive
                ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                : 'text-slate-400 hover:text-white hover:bg-white/5'
            }`}
          >
            <Icon className="w-3.5 h-3.5 shrink-0" />
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono font-normal ${
                  isActive ? 'bg-white/20 text-white' : 'bg-white/10 text-slate-400'
                }`}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

