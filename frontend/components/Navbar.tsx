'use client';

import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield,
  User as UserIcon,
  Users,
  LogOut,
  History,
  SlidersHorizontal,
  AlertTriangle,
  Cpu,
  Radar,
  BookOpen,
  Server,
  Network,
  Activity,
  Terminal,
  FileWarning,
  LayoutDashboard,
  ScrollText,
  PanelRightClose,
  PanelRightOpen,
  ChevronRight,
  ChevronLeft,
  Bell,
  CheckCheck,
  Search,
  FolderKanban,
  ShieldCheck,
  Award,
  Mail,
} from 'lucide-react';
import { User, PermissionCode, AppNotification } from '../lib/types';
import { fetchApi, getAuthStatus, getHistory, getNotifications, markNotificationRead, markAllNotificationsRead } from '../lib/api';
import { useTranslation } from '../lib/i18n';
import { HistoryModal } from './HistoryModal';
import { GlobalSearchModal } from './GlobalSearchModal';
import { EditionUpgradeModal } from './EditionUpgradeModal';

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  bgColor: string;
  borderColor: string;
  permission?: PermissionCode;
  badge?: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

export function Navbar({ onOpenHistory }: { onOpenHistory?: () => void }) {
  const { t } = useTranslation();
  const router = useRouter();
  const pathname = usePathname();

  const [user, setUser] = useState<User | null>(null);
  const [historyCount, setHistoryCount] = useState(0);
  const [brandTitle, setBrandTitle] = useState('بوابة التحليل الأمني');
  const [internalHistoryOpen, setInternalHistoryOpen] = useState(false);
  const [editionModalOpen, setEditionModalOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(true);
  const sidebarNavRef = useRef<HTMLDivElement>(null);

  // Global Search Modal State & Ctrl+K Listener
  const [searchModalOpen, setSearchModalOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchModalOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Live Notifications State
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [unreadNotifCount, setUnreadNotifCount] = useState<number>(0);
  const [notifDropdownOpen, setNotifDropdownOpen] = useState<boolean>(false);
  const notifRef = useRef<HTMLDivElement>(null);

  const fetchNotifs = () => {
    getNotifications({ limit: 8 })
      .then((res) => {
        setNotifications(res.notifications || []);
        setUnreadNotifCount(res.unread_count || 0);
      })
      .catch(() => {});
  };

  useEffect(() => {
    fetchNotifs();
    const interval = setInterval(fetchNotifs, 25000);
    return () => clearInterval(interval);
  }, []);

  // Live Licensing State
  const [licenseInfo, setLicenseInfo] = useState<{
    days_remaining: number;
    license_type: string;
    edition: string;
    is_valid: boolean;
    state: string;
  } | null>(null);

  useEffect(() => {
    const fetchLic = () => {
      fetch('/api/licensing/status')
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (data) setLicenseInfo(data);
        })
        .catch(() => {});
    };
    fetchLic();
    const interval = setInterval(fetchLic, 60000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setNotifDropdownOpen(false);
      }
    };
    window.addEventListener('mousedown', handleClickOutside);
    return () => window.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Restore and maintain sidebar scroll position to keep active link locked in view
  useEffect(() => {
    if (!sidebarNavRef.current) return;

    // 1. First restore previous scroll position from sessionStorage
    const savedScroll = sessionStorage.getItem('soc_sidebar_scroll_top');
    if (savedScroll !== null) {
      sidebarNavRef.current.scrollTop = Number(savedScroll);
    }

    // 2. Ensure the active item is in view
    const timer = setTimeout(() => {
      const activeEl = sidebarNavRef.current?.querySelector<HTMLElement>('[data-active="true"]');
      if (activeEl) {
        activeEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    }, 60);

    return () => clearTimeout(timer);
  }, [pathname, sidebarOpen]);

  // Initialize sidebar state from localStorage on client mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const querySidebar = urlParams.get('sidebar');
    let initialOpen: boolean;
    if (querySidebar === 'closed' || querySidebar === '0') {
      initialOpen = false;
      localStorage.setItem('platform-sidebar-open', 'false');
    } else if (querySidebar === 'open' || querySidebar === '1') {
      initialOpen = true;
      localStorage.setItem('platform-sidebar-open', 'true');
    } else {
      const saved = localStorage.getItem('platform-sidebar-open');
      initialOpen = saved !== null ? saved === 'true' : window.innerWidth >= 1280;
    }
    setSidebarOpen(initialOpen);
    if (initialOpen) {
      document.body.classList.add('sidebar-expanded');
    } else {
      document.body.classList.remove('sidebar-expanded');
    }

    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
        e.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.classList.remove('sidebar-expanded');
    };
  }, []);

  const toggleSidebar = () => {
    setSidebarOpen((prev) => {
      const next = !prev;
      localStorage.setItem('platform-sidebar-open', String(next));
      if (next) {
        document.body.classList.add('sidebar-expanded');
      } else {
        document.body.classList.remove('sidebar-expanded');
      }
      return next;
    });
  };

  const closeSidebarOnMobile = () => {
    if (typeof window !== 'undefined' && window.innerWidth < 1280) {
      setSidebarOpen(false);
      localStorage.setItem('platform-sidebar-open', 'false');
      document.body.classList.remove('sidebar-expanded');
    }
  };

  const handleGoBack = () => {
    if (typeof window !== 'undefined') {
      window.history.back();
    } else {
      router.back();
    }
  };

  const handleGoForward = () => {
    if (typeof window !== 'undefined') {
      window.history.forward();
    } else {
      router.forward();
    }
  };

  const refreshHistoryCount = () => {
    getHistory().then((h) => setHistoryCount(h.total || 0)).catch(() => {});
  };

  useEffect(() => {
    getAuthStatus().then((res) => {
      if (res.authenticated && res.user) {
        setUser(res.user);
        if (res.user.permissions?.includes('history.view')) {
          refreshHistoryCount();
        }
      }
    }).catch(() => {});

    const loadBrand = () =>
      fetchApi('/api/settings/public')
        .then((response) => setBrandTitle(response.appearance?.platform_title || 'بوابة التحليل الأمني'))
        .catch(() => {});

    loadBrand();
    window.addEventListener('platform-config-updated', loadBrand);
    return () => window.removeEventListener('platform-config-updated', loadBrand);
  }, []);

  const handleLogout = async () => {
    try {
      await fetchApi('/api/auth/logout', { method: 'POST' });
    } catch {}
    router.push('/login');
  };

  const handleOpenHistory = () => {
    refreshHistoryCount();
    if (onOpenHistory) {
      onOpenHistory();
    } else {
      setInternalHistoryOpen(true);
    }
  };

  const navigationGroups: NavGroup[] = [
    {
      title: 'المراقبة والتحقيق المباشر',
      items: [
        {
          name: 'الرئيسية (لوحة القيادة)',
          href: '/',
          icon: LayoutDashboard,
          color: 'text-primary',
          bgColor: 'bg-primary/10',
          borderColor: 'border-primary/25',
        },
        {
          name: 'إدارة الحوادث الأمنية',
          href: '/incidents',
          icon: AlertTriangle,
          color: 'text-red-400',
          bgColor: 'bg-red-500/10',
          borderColor: 'border-red-500/30',
          badge: 'P1-P4',
        },
        {
          name: 'قضايا التحقيق الأمني (SOC)',
          href: '/investigations',
          icon: FolderKanban,
          color: 'text-purple-400',
          bgColor: 'bg-purple-500/10',
          borderColor: 'border-purple-500/30',
          badge: 'Cases',
        },
        {
          name: 'سجلات الأحداث الموحدة',
          href: '/logs',
          icon: ScrollText,
          color: 'text-sky-400',
          bgColor: 'bg-sky-500/10',
          borderColor: 'border-sky-500/25',
          badge: 'Audit',
        },
        {
          name: 'الترابط وسلاسل الهجوم',
          href: '/correlation',
          icon: Network,
          color: 'text-purple-400',
          bgColor: 'bg-purple-500/10',
          borderColor: 'border-purple-500/30',
          badge: 'Graph',
        },
      ],
    },
    {
      title: 'وحدات التحليل الجنائي',
      items: [
        {
          name: 'FlowScope (تدفقات الشبكة)',
          href: '/flowscope',
          icon: Activity,
          color: 'text-cyan-400',
          bgColor: 'bg-cyan-500/10',
          borderColor: 'border-cyan-500/25',
          badge: 'NetFlow',
        },
        {
          name: 'LogScope (سجلات SIEM والأمان)',
          href: '/logscope',
          icon: Terminal,
          color: 'text-emerald-400',
          bgColor: 'bg-emerald-500/10',
          borderColor: 'border-emerald-500/25',
          badge: 'SIEM',
        },
        {
          name: 'ThreatScope (ملفات XDR والتجزئات)',
          href: '/threatscope',
          icon: FileWarning,
          color: 'text-pink-400',
          bgColor: 'bg-pink-500/10',
          borderColor: 'border-pink-500/25',
          badge: 'XDR',
        },
        {
          name: 'EndpointScope (مراقبة نقاط النهاية EDR)',
          href: '/endpointscope',
          icon: ShieldCheck,
          color: 'text-amber-400',
          bgColor: 'bg-amber-500/10',
          borderColor: 'border-amber-500/25',
          badge: 'EDR',
        },
        {
          name: 'MailScope (التحليل الجنائي للبريد والتصيد)',
          href: '/mailscope',
          icon: Mail,
          color: 'text-indigo-400',
          bgColor: 'bg-indigo-500/10',
          borderColor: 'border-indigo-500/25',
          badge: 'Anti-BEC',
        },
      ],
    },
    {
      title: 'الاستخبارات وهندسة الكشف',
      items: [
        {
          name: 'قواعد الكشف واستوديو Sigma',
          href: '/detections',
          icon: Cpu,
          color: 'text-amber-400',
          bgColor: 'bg-amber-500/10',
          borderColor: 'border-amber-500/30',
          badge: 'Sigma',
        },
        {
          name: 'استخبارات التهديدات (IOCs)',
          href: '/intel',
          icon: Radar,
          color: 'text-emerald-400',
          bgColor: 'bg-emerald-500/10',
          borderColor: 'border-emerald-500/30',
          badge: 'STIX 2.1',
        },
        {
          name: 'سجل وذكاء الأصول الأمنية',
          href: '/assets',
          icon: Server,
          color: 'text-blue-400',
          bgColor: 'bg-blue-500/10',
          borderColor: 'border-blue-500/30',
          badge: 'Assets',
        },
      ],
    },
    {
      title: 'العمليات والمراقبة',
      items: [
        {
          name: 'سجلات المنصة',
          href: '/operations/logs',
          icon: Terminal,
          color: 'text-amber-400',
          bgColor: 'bg-amber-500/10',
          borderColor: 'border-amber-500/30',
          badge: 'Platform',
          permission: 'system.status',
        },
        {
          name: 'صحة المنصة والمكونات',
          href: '/operations/health',
          icon: Activity,
          color: 'text-emerald-400',
          bgColor: 'bg-emerald-500/10',
          borderColor: 'border-emerald-500/30',
          badge: 'Health',
          permission: 'system.status',
        },
      ],
    },
    {
      title: 'الإدارة المركزية والحوكمة',
      items: [
        {
          name: 'مركز الإدارة والحوكمة',
          href: '/admin',
          icon: Shield,
          color: 'text-purple-400',
          bgColor: 'bg-purple-500/10',
          borderColor: 'border-purple-500/30',
          permission: 'users.manage',
          badge: 'Governance',
        },
        {
          name: 'ComplianceScope (إدارة الامتثال والضوابط)',
          href: '/compliance',
          icon: Award,
          color: 'text-emerald-400',
          bgColor: 'bg-emerald-500/10',
          borderColor: 'border-emerald-500/30',
          badge: 'NCA ECC',
        },
        {
          name: 'إعدادات المنصة والهوية',
          href: '/settings',
          icon: SlidersHorizontal,
          color: 'text-slate-300',
          bgColor: 'bg-white/5',
          borderColor: 'border-white/15',
          badge: 'Config',
        },
        {
          name: 'دليل الاستخدام ومركز المساعدة',
          href: '/help',
          icon: BookOpen,
          color: 'text-cyan-300',
          bgColor: 'bg-cyan-500/10',
          borderColor: 'border-cyan-500/30',
          badge: 'Guide',
        },
      ],
    },
  ];

  const isLinkActive = (href: string) => {
    if (href === '/') return pathname === '/';
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* ========================================================================= */}
      {/* 1. SLEEK FIXED TOPBAR (الشريط العلوي الثابت الممتد بكامل العرض)             */}
      {/* ========================================================================= */}
      <header className="platform-nav fixed top-0 inset-x-0 h-14 z-50 border-b border-white/10 bg-dark-900/90 backdrop-blur-md select-none">
        <div className="w-full px-3 sm:px-5 h-full flex items-center justify-between gap-3">
          {/* Right Section: Sidebar Toggle, Brand Mark, Live SOC Status */}
          <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
            {/* Exclusive Sidebar Toggle Button with Hover Shortcut Badge */}
            <div className="relative group/toggle shrink-0">
              <button
                type="button"
                onClick={toggleSidebar}
                className={`flex items-center gap-2 px-2.5 py-1.5 rounded-xl border transition-all duration-200 select-none shrink-0 ${
                  sidebarOpen
                    ? 'bg-primary/20 border-primary/40 text-primary shadow-sm shadow-primary/20'
                    : 'bg-white/5 border-white/15 text-slate-200 hover:bg-primary/10 hover:border-primary/40 hover:text-primary'
                }`}
                title={sidebarOpen ? 'إخفاء القائمة الجانبية (Ctrl+B)' : 'إظهار القائمة الجانبية (Ctrl+B)'}
                aria-label="تبديل القائمة الجانبية"
              >
                {sidebarOpen ? (
                  <PanelRightClose className="w-4 h-4 text-primary group-hover/toggle:scale-110 transition-transform" />
                ) : (
                  <PanelRightOpen className="w-4 h-4 text-slate-300 group-hover/toggle:text-primary group-hover/toggle:scale-110 transition-transform" />
                )}
                <span className="text-xs font-bold hidden sm:inline">
                  {sidebarOpen ? 'إخفاء القائمة' : 'القائمة الرئيسية'}
                </span>
              </button>

              {/* Hover-only Shortcut Tooltip Badge */}
              <div className="absolute top-full mt-2 right-0 pointer-events-none opacity-0 group-hover/toggle:opacity-100 -translate-y-1 group-hover/toggle:translate-y-0 transition-all duration-200 z-50">
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-dark-950/95 border border-primary/30 shadow-2xl backdrop-blur-md whitespace-nowrap text-[11px] text-slate-200">
                  <span className="text-slate-400">{sidebarOpen ? 'إخفاء' : 'إظهار'}</span>
                  <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/60 border border-white/15 text-primary font-bold shadow-inner">
                    Ctrl+B
                  </kbd>
                </div>
              </div>
            </div>

            {/* Brand Mark & Title */}
            <Link href="/" className="flex items-center gap-2.5 group select-none py-1">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/40 flex items-center justify-center text-primary shadow-md shadow-primary/10 group-hover:scale-105 transition-transform shrink-0">
                <Shield className="w-4 h-4 text-primary" />
              </div>
              <div className="flex flex-col justify-center">
                <span className="text-[9px] tracking-wider font-heading font-bold text-primary uppercase leading-tight whitespace-nowrap hidden sm:block">
                  Security Analysis Center
                </span>
                <span className="text-xs sm:text-sm font-bold text-white tracking-wide leading-tight whitespace-nowrap">
                  {brandTitle}
                </span>
              </div>
            </Link>

            {/* In-Platform Browser-Independent History Navigation (Back & Forward) */}
            <div
              className="flex items-center rounded-xl bg-white/5 border border-white/10 p-0.5 shrink-0"
              role="group"
              aria-label="أزرار التنقل داخل المنصة"
            >
              <button
                type="button"
                onClick={handleGoBack}
                className="flex items-center justify-center w-7 h-7 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 active:scale-95 transition-all"
                title="الرجوع للصفحة السابقة داخل المنصة (Back)"
                aria-label="الرجوع للصفحة السابقة"
              >
                <ChevronRight className="w-4 h-4 rtl:rotate-0 rotate-180" />
              </button>
              <div className="w-px h-3.5 bg-white/10" />
              <button
                type="button"
                onClick={handleGoForward}
                className="flex items-center justify-center w-7 h-7 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 active:scale-95 transition-all"
                title="التقدم للصفحة التالية داخل المنصة (Forward)"
                aria-label="التقدم للصفحة التالية"
              >
                <ChevronLeft className="w-4 h-4 rtl:rotate-0 rotate-180" />
              </button>
            </div>

            {/* Live Operational Indicator */}
            <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[11px] font-medium mr-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>SOC متصل</span>
            </div>

            {/* License & Edition Upgrade Modal Trigger */}
            {licenseInfo && (
              <button
                type="button"
                onClick={() => setEditionModalOpen(true)}
                className={`hidden xl:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold border transition-all ${
                  !licenseInfo.is_valid || licenseInfo.days_remaining <= 3
                    ? 'bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20 shadow-sm shadow-rose-500/10'
                    : licenseInfo.days_remaining <= 7
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-300 hover:bg-amber-500/20 shadow-sm shadow-amber-500/10'
                    : 'bg-gradient-to-r from-purple-500/15 to-primary/15 border-purple-500/30 text-purple-200 hover:border-purple-500/50 shadow-sm'
                }`}
                title="انقر لإدارة الباقات والترقية والامتثال"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-purple-400" />
                <span>
                  {licenseInfo.license_type === 'TRIAL'
                    ? `تجربة: ${licenseInfo.days_remaining} يوم متبقٍ`
                    : `طبعة ${licenseInfo.edition}`}
                </span>
                <span className="text-[9px] bg-purple-500/20 px-1 py-0.2 rounded font-mono uppercase tracking-wider text-purple-300">
                  ترقية
                </span>
              </button>
            )}
          </div>

          {/* Left Section: Quick History, Help, User Profile, and Logout */}
          <div className="flex items-center gap-2 shrink-0">
            {/* Global Search (Ctrl+K) Trigger */}
            <button
              type="button"
              onClick={() => setSearchModalOpen(true)}
              className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-300 hover:text-white transition-colors whitespace-nowrap shrink-0"
              title="البحث الشامل في المنصة (Ctrl+K)"
            >
              <Search className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="hidden md:inline">بحث سريع...</span>
              <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-mono bg-white/10 border border-white/15 text-slate-400">
                Ctrl+K
              </kbd>
            </button>

            {/* History Modal Trigger */}
            {user?.permissions?.includes('history.view') && (
              <button
                type="button"
                onClick={handleOpenHistory}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 transition-colors whitespace-nowrap shrink-0"
                title={t('navbar.history')}
              >
                <History className="w-3.5 h-3.5 text-primary shrink-0" />
                <span className="hidden sm:inline">{t('navbar.history')}</span>
                <span className="bg-primary/20 text-primary px-1.5 py-0.2 rounded-full text-[10px] font-bold font-mono">
                  {historyCount}
                </span>
              </button>
            )}

            {/* Quick Help Shortcut */}
            <Link
              href="/help"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/25 text-xs font-medium text-cyan-300 transition-colors shadow-sm shadow-cyan-500/10 whitespace-nowrap shrink-0"
              title="دليل الاستخدام ومركز المساعدة"
            >
              <BookOpen className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="hidden md:inline">دليل الاستخدام</span>
            </Link>

            {/* Notifications Bell Dropdown */}
            <div className="relative" ref={notifRef}>
              <button
                type="button"
                onClick={() => setNotifDropdownOpen(!notifDropdownOpen)}
                className="relative flex items-center justify-center p-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-colors shrink-0"
                title="الإشعارات والتنبيهات"
              >
                <Bell className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                {unreadNotifCount > 0 && (
                  <span className="absolute -top-1 -right-1 flex items-center justify-center min-w-[16px] h-4 px-1 rounded-full bg-rose-500 text-[10px] font-bold text-white shadow-sm font-mono animate-pulse">
                    {unreadNotifCount > 9 ? '9+' : unreadNotifCount}
                  </span>
                )}
              </button>

              {notifDropdownOpen && (
                <div className="absolute left-0 mt-2 w-80 sm:w-96 rounded-2xl bg-dark-900/95 border border-white/15 shadow-2xl backdrop-blur-xl z-50 overflow-hidden animate-fadeIn text-right">
                  <div className="p-3 border-b border-white/10 flex items-center justify-between bg-dark-950/60">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold font-heading text-white">التنبيهات الحية</span>
                      {unreadNotifCount > 0 && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          {unreadNotifCount} جديد
                        </span>
                      )}
                    </div>
                    {unreadNotifCount > 0 && (
                      <button
                        type="button"
                        onClick={async () => {
                          await markAllNotificationsRead();
                          fetchNotifs();
                        }}
                        className="text-[11px] text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-colors"
                      >
                        <CheckCheck className="w-3 h-3" />
                        <span>قراءة الكل</span>
                      </button>
                    )}
                  </div>

                  <div className="max-h-80 overflow-y-auto divide-y divide-white/5 scrollbar-thin">
                    {notifications.length === 0 ? (
                      <div className="p-6 text-center text-xs text-slate-400">
                        لا توجد إشعارات حالياً
                      </div>
                    ) : (
                      notifications.map((n) => (
                        <div
                          key={n.id}
                          className={`p-3 transition-colors text-xs space-y-1 ${
                            n.is_read ? 'bg-transparent opacity-75 hover:opacity-100 hover:bg-white/5' : 'bg-purple-500/5 hover:bg-purple-500/10'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div className="flex items-center gap-1.5 min-w-0">
                              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                n.severity === 'critical' ? 'bg-rose-400' :
                                n.severity === 'warning' ? 'bg-amber-400' :
                                n.severity === 'success' ? 'bg-emerald-400' : 'bg-blue-400'
                              }`} />
                              <span className="font-semibold text-slate-200 truncate">{n.title}</span>
                            </div>
                            <span className="text-[10px] text-slate-500 shrink-0 font-mono">
                              {new Date(n.created_at).toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit' })}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                            {n.message}
                          </p>
                          <div className="flex items-center justify-between pt-1">
                            {n.link ? (
                              <Link
                                href={n.link}
                                onClick={() => {
                                  if (!n.is_read) {
                                    markNotificationRead(n.id).then(fetchNotifs);
                                  }
                                  setNotifDropdownOpen(false);
                                }}
                                className="text-[10px] text-purple-400 hover:underline"
                              >
                                عرض التفاصيل ←
                              </Link>
                            ) : <span />}
                            {!n.is_read && (
                              <button
                                type="button"
                                onClick={async () => {
                                  await markNotificationRead(n.id);
                                  fetchNotifs();
                                }}
                                className="text-[10px] text-slate-400 hover:text-slate-200"
                              >
                                تحديد كمقروء
                              </button>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  <div className="p-2 border-t border-white/10 bg-dark-950/60 text-center">
                    <Link
                      href="/admin"
                      onClick={() => setNotifDropdownOpen(false)}
                      className="text-[11px] font-semibold text-purple-400 hover:text-purple-300 block py-1"
                    >
                      مركز الإشعارات الكامل ←
                    </Link>
                  </div>
                </div>
              )}
            </div>

            {/* Subtle Divider */}
            <div className="w-px h-5 bg-white/10 mx-0.5 shrink-0" />

            {/* User Profile Badge or Login */}
            {user ? (
              <>
                <Link
                  href="/account"
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-200 hover:text-white transition-colors whitespace-nowrap shrink-0 group"
                  title={`${user.display_name || user.username} — ${t('navbar.account')}`}
                >
                  <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0" />
                  <UserIcon className="w-3.5 h-3.5 text-blue-400 group-hover:text-blue-300 transition-colors shrink-0" />
                  <span className="max-w-[110px] truncate hidden sm:inline">
                    {user.display_name || user.username}
                  </span>
                </Link>

                {/* Logout Button */}
                <button
                  type="button"
                  onClick={handleLogout}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 text-rose-300 transition-colors whitespace-nowrap shrink-0"
                  title={t('navbar.logout')}
                >
                  <LogOut className="w-3.5 h-3.5 shrink-0" />
                  <span className="hidden sm:inline">{t('navbar.logout')}</span>
                </button>
              </>
            ) : (
              <Link
                href="/login"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-primary/15 hover:bg-primary/25 border border-primary/30 text-xs font-semibold text-primary transition-colors whitespace-nowrap shrink-0"
              >
                <UserIcon className="w-3.5 h-3.5 shrink-0" />
                <span>تسجيل الدخول</span>
              </Link>
            )}
          </div>
        </div>
      </header>

      {/* Topbar Height Spacer (Ensures page content begins cleanly below the fixed 56px header) */}
      <div className="h-14 shrink-0 pointer-events-none" aria-hidden="true" />

      {/* ========================================================================= */}
      {/* 2. EXCLUSIVE RIGHT-HAND SIDEBAR (الشريط الجانبي الأيمن الحصري والأنيق)        */}
      {/* ========================================================================= */}
      {/* Backdrop for Screens < 1280px (Tablet / Mobile) */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 top-14 bg-black/60 backdrop-blur-sm z-30 xl:hidden transition-opacity duration-300"
          onClick={toggleSidebar}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Panel: Placed at top-14 right-0 bottom-0, below the topbar */}
      <aside
        className={`fixed top-14 right-0 bottom-0 w-72 z-40 h-[calc(100vh-3.5rem)] flex flex-col platform-sidebar transition-transform duration-300 ease-in-out select-none ${
          sidebarOpen ? 'translate-x-0' : 'translate-x-full'
        }`}
        aria-label="القائمة الجانبية للمنصة"
      >
        {/* Compact SOC Menu Header with inline collapse */}
        <div className="h-12 px-4 border-b border-white/10 flex items-center justify-between gap-2 shrink-0 bg-dark-950/70">
          <div className="flex items-center gap-2 min-w-0">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse shrink-0" />
            <span className="text-[11px] font-heading font-bold text-primary uppercase tracking-wider truncate">
              مركز العمليات الأمنية
            </span>
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 text-slate-400 border border-white/10 shrink-0">
              SOC
            </span>
          </div>

          <button
            type="button"
            onClick={toggleSidebar}
            className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white transition-colors shrink-0"
            title="إخفاء القائمة الجانبية (Ctrl+B)"
            aria-label="إخفاء القائمة الجانبية"
          >
            <PanelRightClose className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Navigation Groups */}
        <div
          ref={sidebarNavRef}
          onScroll={(e) => {
            sessionStorage.setItem('soc_sidebar_scroll_top', String(e.currentTarget.scrollTop));
          }}
          className="flex-1 overflow-y-auto custom-sidebar-scrollbar px-3 py-3 space-y-4"
        >
          {navigationGroups.map((group, gIdx) => {
            // Filter items by user permissions if specified
            const visibleItems = group.items.filter((item) => {
              if (!item.permission) return true;
              return user?.permissions?.includes(item.permission);
            });

            if (visibleItems.length === 0) return null;

            return (
              <div key={gIdx} className="space-y-1.5 pt-1">
                <div className="mx-0.5 my-1.5 px-3 py-1.5 rounded-xl bg-slate-800/80 dark:bg-slate-800/80 border border-slate-700/60 dark:border-white/10 shadow-xs flex items-center justify-between gap-2 select-none">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-1.5 h-3.5 rounded-full bg-primary shrink-0 shadow-xs shadow-primary/40" />
                    <span className="text-[11px] font-extrabold text-slate-100 tracking-wide uppercase truncate">
                      {group.title}
                    </span>
                  </div>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/10 text-slate-300 border border-white/10 shrink-0 font-bold">
                    {visibleItems.length}
                  </span>
                </div>

                <div className="space-y-0.5">
                  {visibleItems.map((item, iIdx) => {
                    const active = isLinkActive(item.href);
                    const Icon = item.icon;

                    return (
                      <Link
                        key={iIdx}
                        href={item.href}
                        data-active={active ? 'true' : undefined}
                        onClick={() => {
                          if (sidebarNavRef.current) {
                            sessionStorage.setItem('soc_sidebar_scroll_top', String(sidebarNavRef.current.scrollTop));
                          }
                          closeSidebarOnMobile();
                        }}
                        className={`group relative flex items-center justify-between px-2.5 py-1.5 rounded-xl text-xs font-medium transition-all duration-200 ${
                          active
                            ? 'bg-gradient-to-l from-primary/20 to-primary/10 border border-primary/35 text-white shadow-sm shadow-primary/15 font-semibold'
                            : 'text-slate-300 hover:text-white hover:bg-white/5 border border-transparent hover:border-white/10'
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div
                            className={`w-6 h-6 rounded-lg flex items-center justify-center transition-transform group-hover:scale-110 ${
                              active
                                ? `${item.bgColor} ${item.borderColor} border ${item.color}`
                                : `${item.bgColor} border border-transparent ${item.color}`
                            }`}
                          >
                            <Icon className="w-3.5 h-3.5 shrink-0" />
                          </div>
                          <span className="truncate">{item.name}</span>
                        </div>

                        <div className="flex items-center gap-1.5 shrink-0">
                          {item.badge && (
                            <span
                              className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono border ${item.bgColor} ${item.color} ${item.borderColor}`}
                            >
                              {item.badge}
                            </span>
                          )}
                          {active && (
                            <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                          )}
                        </div>
                      </Link>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        {/* Sidebar Footer: User Card & Platform Info */}
        <div className="p-3 border-t border-white/10 bg-dark-950/60 shrink-0 space-y-2">
          {user ? (
            <div className="p-2 rounded-xl bg-white/5 border border-white/10 flex items-center justify-between gap-2">
              <Link
                href="/account"
                onClick={closeSidebarOnMobile}
                className="flex items-center gap-2 min-w-0 group"
                title="إدارة الحساب"
              >
                <div className="w-7 h-7 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform shrink-0">
                  <UserIcon className="w-3.5 h-3.5" />
                </div>
                <div className="flex flex-col min-w-0">
                  <span className="text-xs font-bold text-white truncate group-hover:text-primary transition-colors">
                    {user.display_name || user.username}
                  </span>
                  <span className="text-[9px] text-slate-400 truncate">
                    {user.permissions?.includes('users.manage') ? 'مسؤول النظام (Admin)' : 'محلل أمني (Analyst)'}
                  </span>
                </div>
              </Link>

              <button
                type="button"
                onClick={handleLogout}
                className="p-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 text-rose-300 transition-colors shrink-0"
                title="تسجيل الخروج"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              onClick={closeSidebarOnMobile}
              className="w-full flex items-center justify-center gap-2 py-2 rounded-xl bg-primary/20 hover:bg-primary/30 border border-primary/40 text-primary text-xs font-bold transition-colors"
            >
              <UserIcon className="w-4 h-4" />
              <span>تسجيل الدخول للمنصة</span>
            </Link>
          )}

          {/* Node Health Status */}
          <div className="flex items-center justify-between px-2 pt-0.5 text-[10px] text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-emerald-400 font-medium">العقدة جاهزة (100%)</span>
            </span>
            <span className="font-mono text-slate-500">v2.5 SOC</span>
          </div>
        </div>
      </aside>

      {/* History Modal */}
      <HistoryModal
        isOpen={internalHistoryOpen}
        onClose={() => setInternalHistoryOpen(false)}
      />

      {/* Global Cross-Entity Search Modal (Ctrl+K) */}
      <GlobalSearchModal
        isOpen={searchModalOpen}
        onClose={() => setSearchModalOpen(false)}
      />

      {/* Commercial Edition & License Upgrade Modal */}
      <EditionUpgradeModal
        isOpen={editionModalOpen}
        onClose={() => setEditionModalOpen(false)}
      />
    </>
  );
}
