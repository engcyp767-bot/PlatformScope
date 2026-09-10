import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import {
  Search, ChevronDown, ChevronUp, Users, ExternalLink, X,
  Shield, Server, HardDrive, Cpu, Activity, Sliders, Palette
} from 'lucide-react';
import { SettingsNavGroup, SettingsTabId } from './types';

export function SettingsSidebar({
  groups,
  activeTab,
  onSelectTab,
  dirtyTabs,
  searchQuery,
  onSearchChange,
  mobileOpen,
  onCloseMobile,
  version,
}: {
  groups: SettingsNavGroup[];
  activeTab: SettingsTabId;
  onSelectTab: (tabId: SettingsTabId) => void;
  dirtyTabs: Set<SettingsTabId>;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  version?: number;
}) {
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});
  const desktopSidebarRef = useRef<HTMLElement>(null);

  // Restore previous scroll position and ensure active tab is locked in view
  useEffect(() => {
    if (!desktopSidebarRef.current) return;
    const saved = sessionStorage.getItem('settings_sidebar_scroll_top');
    if (saved) {
      desktopSidebarRef.current.scrollTop = Number(saved);
    }
  }, []);

  useEffect(() => {
    if (!desktopSidebarRef.current) return;
    const timer = setTimeout(() => {
      const activeEl = desktopSidebarRef.current?.querySelector<HTMLElement>('[data-active="true"]');
      if (activeEl) {
        activeEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    }, 60);
    return () => clearTimeout(timer);
  }, [activeTab]);

  const toggleGroup = (groupId: string) => {
    setCollapsedGroups((prev) => ({ ...prev, [groupId]: !prev[groupId] }));
  };

  const navContent = (
    <div className="space-y-4">
      {/* Search Bar */}
      <div className="relative">
        <Search className="w-4 h-4 text-slate-500 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="ابحث في الإعدادات... (Ctrl+K)"
          className="w-full rounded-xl bg-dark-950/70 border border-white/10 pr-9 pl-3.5 py-2.5 text-xs text-slate-100 placeholder:text-slate-500 outline-none focus:border-cyan-500/50 transition-colors"
        />
        {searchQuery && (
          <button
            type="button"
            onClick={() => onSearchChange('')}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Nav Groups */}
      <div className="space-y-3.5">
        {groups.map((group) => {
          const isCollapsed = collapsedGroups[group.id];
          const hasActiveChild = group.children.some((c) => c.id === activeTab);
          const GroupIcon = group.icon;

          return (
            <div key={group.id} className="space-y-1">
              <button
                type="button"
                onClick={() => toggleGroup(group.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-bold transition-all border shadow-xs my-1 select-none ${
                  hasActiveChild
                    ? 'bg-slate-800/95 dark:bg-slate-800/90 border-cyan-500/40 text-cyan-100 shadow-cyan-950/20'
                    : 'bg-slate-800/60 hover:bg-slate-800/80 dark:bg-slate-900/75 dark:hover:bg-slate-800/75 text-slate-200 hover:text-white border-slate-700/45 dark:border-white/10'
                } group`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div
                    className={`p-1 rounded-lg transition-colors ${
                      hasActiveChild
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                        : 'bg-white/5 text-slate-400 group-hover:text-cyan-400 group-hover:bg-white/10'
                    }`}
                  >
                    <GroupIcon className="w-3.5 h-3.5 shrink-0" />
                  </div>
                  <span className="truncate tracking-wide">{group.title}</span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400 border border-white/5">
                    {group.children.length}
                  </span>
                  {isCollapsed ? (
                    <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-200 transition-transform" />
                  ) : (
                    <ChevronUp className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-200 transition-transform" />
                  )}
                </div>
              </button>

              {!isCollapsed && (
                <div className="space-y-0.5 pr-2">
                  {group.children.map((item) => {
                    const isActive = activeTab === item.id;
                    const isDirty = dirtyTabs.has(item.id);

                    return (
                      <button
                        key={item.id}
                        type="button"
                        data-active={isActive ? 'true' : undefined}
                        onClick={() => {
                          if (desktopSidebarRef.current) {
                            sessionStorage.setItem('settings_sidebar_scroll_top', String(desktopSidebarRef.current.scrollTop));
                          }
                          onSelectTab(item.id);
                          onCloseMobile();
                        }}
                        className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                          isActive
                            ? 'bg-cyan-500/15 text-cyan-200 border border-cyan-500/30 font-bold shadow-sm shadow-cyan-500/10'
                            : 'text-slate-400 hover:bg-white/5 hover:text-white border border-transparent'
                        }`}
                      >
                        <span className="flex items-center gap-2">
                          <span
                            className={`w-1.5 h-1.5 rounded-full transition-colors ${
                              isActive
                                ? 'bg-cyan-400 shadow-[0_0_8px_rgba(0,229,255,0.6)]'
                                : isDirty
                                ? 'bg-amber-400'
                                : 'bg-slate-600'
                            }`}
                          />
                          {item.label}
                        </span>

                        <div className="flex items-center gap-1.5">
                          {isDirty && (
                            <span
                              className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"
                              title="توجد تعديلات غير محفوظة"
                            />
                          )}
                          {item.isRestartRequired && (
                            <span
                              className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/25"
                              title="يتطلب إعادة تشغيل"
                            >
                              إعادة تشغيل
                            </span>
                          )}
                          {item.badge && (
                            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-white/10 text-slate-300">
                              {item.badge}
                            </span>
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* External / Admin Links */}
      <div className="pt-3 border-t border-white/10 space-y-1">
        <Link
          href="/admin"
          className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-purple-400 hover:bg-purple-500/10 hover:text-purple-300 transition-colors"
        >
          <span className="flex items-center gap-2">
            <Users className="w-3.5 h-3.5" />
            إدارة المستخدمين المستقلة
          </span>
          <ExternalLink className="w-3 h-3 opacity-60" />
        </Link>
        <Link
          href="/help#platform-settings"
          className="w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-semibold text-cyan-400 hover:bg-cyan-500/10 hover:text-cyan-300 transition-colors"
        >
          <span className="flex items-center gap-2">
            <ExternalLink className="w-3.5 h-3.5" />
            مركز المساعدة ودليل الاستخدام
          </span>
        </Link>
      </div>

      {version && (
        <div className="text-[10px] text-slate-500 px-3 pt-2 text-center select-none">
          إصدار التكوين: v{version}
        </div>
      )}
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside
        ref={desktopSidebarRef}
        onScroll={(e) => {
          sessionStorage.setItem('settings_sidebar_scroll_top', String(e.currentTarget.scrollTop));
        }}
        className="hidden lg:block glass-panel p-3.5 max-h-[calc(100vh-6.5rem)] overflow-y-auto custom-sidebar-scrollbar lg:sticky lg:top-20 select-none"
      >
        {navContent}
      </aside>

      {/* Mobile Drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/75 backdrop-blur-sm"
            onClick={onCloseMobile}
          />
          <div className="relative w-4/5 max-w-sm bg-dark-900 border-l border-white/10 p-4 overflow-y-auto h-full z-10 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <h3 className="font-bold text-sm text-white">أقسام مركز الإعدادات</h3>
              <button
                type="button"
                onClick={onCloseMobile}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            {navContent}
          </div>
        </div>
      )}
    </>
  );
}
