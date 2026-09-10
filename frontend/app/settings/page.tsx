'use client';

import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Navbar } from '../../components/Navbar';
import {
  LayoutDashboard, Sliders, Palette, Users, ShieldCheck, Sparkles,
  Bot, ServerCog, HardDrive, Database, Plug, FileText, Activity,
  ToggleLeft, Network, Wrench, RefreshCw, CheckCircle2, XCircle,
  AlertTriangle, Search
} from 'lucide-react';
import { PlatformConfig } from '../../lib/types';
import { getPlatformConfig, savePlatformConfig } from '../../lib/api';
import { applyAppearance } from '../../components/ThemeSettings';
import { useTranslation } from '../../lib/i18n';

// Sub-components
import { SettingsTabId, SettingsNavGroup, SettingsSearchIndexItem } from './components/types';
import { SettingsSidebar } from './components/SettingsSidebar';
import { SettingsHeader } from './components/SettingsHeader';
import { UnsavedChangesBar } from './components/UnsavedChangesBar';
import { TabOverview } from './components/TabOverview';
import { TabGeneral } from './components/TabGeneral';
import { TabAppearance } from './components/TabAppearance';
import { TabUsers } from './components/TabUsers';
import { TabSecurity } from './components/TabSecurity';
import { TabAI } from './components/TabAI';
import { TabOllama } from './components/TabOllama';
import { TabAnalysis } from './components/TabAnalysis';
import { TabUploads } from './components/TabUploads';
import { TabSources } from './components/TabSources';
import { TabIntegrations } from './components/TabIntegrations';
import { TabReports } from './components/TabReports';
import { TabStorage } from './components/TabStorage';
import { TabLogging } from './components/TabLogging';
import { TabFeatures } from './components/TabFeatures';
import { TabNetwork } from './components/TabNetwork';
import { TabMaintenance } from './components/TabMaintenance';
import { TabGovernance } from './components/TabGovernance';

export default function SettingsPage() {
  const { t } = useTranslation();

  // Core State
  const [config, setConfig] = useState<PlatformConfig | null>(null);
  const [initialConfig, setInitialConfig] = useState<PlatformConfig | null>(null);
  const [defaults, setDefaults] = useState<PlatformConfig | null>(null);
  const [activeTab, setActiveTab] = useState<SettingsTabId>('overview');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string; isRestart?: boolean } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [mobileOpen, setMobileOpen] = useState(false);

  // Load configuration from API
  const loadConfigData = useCallback(async () => {
    setLoading(true);
    setMessage(null);
    try {
      const res = await getPlatformConfig();
      setConfig(res.config);
      setInitialConfig(JSON.parse(JSON.stringify(res.config)));
      setDefaults(res.defaults || null);
    } catch (err: any) {
      setMessage({
        ok: false,
        text: err.message || 'فشل تحميل إعدادات المنصة.',
      });
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadConfigData();
  }, [loadConfigData]);

  // Track Unsaved Changes
  const isDirty = useMemo(() => {
    if (!config || !initialConfig) return false;
    return JSON.stringify(config) !== JSON.stringify(initialConfig);
  }, [config, initialConfig]);

  // Identify which specific tabs have dirty changes
  const dirtyTabs = useMemo(() => {
    const set = new Set<SettingsTabId>();
    if (!config || !initialConfig) return set;

    const check = (key: keyof PlatformConfig, tabId: SettingsTabId) => {
      if (JSON.stringify(config[key]) !== JSON.stringify(initialConfig[key])) {
        set.add(tabId);
      }
    };

    check('general', 'general');
    if (JSON.stringify(config.time) !== JSON.stringify(initialConfig.time)) {
      set.add('general');
    }
    check('appearance', 'appearance');
    check('security', 'security');
    check('ai_providers', 'ai');
    check('ollama', 'ollama');
    check('analysis', 'analysis');
    check('uploads', 'uploads');
    check('source_systems', 'sources');
    check('providers', 'integrations');
    check('external_apis', 'integrations');
    check('reports', 'reports');
    check('storage', 'storage');
    check('logging', 'logging');
    check('features', 'features');
    check('network', 'network');
    check('governance' as any, 'governance');

    return set;
  }, [config, initialConfig]);

  // Browser beforeunload protection
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isDirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isDirty]);

  // Keyboard shortcut for search (Ctrl+K or Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[placeholder*="Ctrl+K"]') as HTMLInputElement;
        if (searchInput) searchInput.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Save changes to API
  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    setMessage(null);
    try {
      const res = await savePlatformConfig(config);
      setConfig(res.config);
      setInitialConfig(JSON.parse(JSON.stringify(res.config)));
      setMessage({
        ok: true,
        text: res.restart_required
          ? 'تم حفظ الإعدادات بنجاح. تنبيه: يتطلب تطبيق بعض التغييرات إعادة تشغيل المنصة.'
          : 'تم حفظ وتطبيق كافة إعدادات المنصة بنجاح.',
        isRestart: res.restart_required,
      });
      window.dispatchEvent(new Event('platform-config-updated'));
    } catch (err: any) {
      setMessage({
        ok: false,
        text: err.message || 'فشل حفظ الإعدادات. يرجى التحقق من صحة المدخلات.',
      });
    }
    setSaving(false);
  };

  // Reset current tab or all changes back to initialConfig
  const handleResetCurrentTab = () => {
    if (!initialConfig || !config) return;
    setConfig(JSON.parse(JSON.stringify(initialConfig)));
    if (initialConfig.appearance) {
      applyAppearance(initialConfig.appearance);
    }
    setMessage({ ok: true, text: 'تم التراجع عن التعديلات غير المحفوظة.' });
  };

  // Reset entire configuration to platform factory defaults
  const handleResetAllToDefaults = () => {
    if (!defaults || !config) return;
    const restored = { ...defaults, version: config.version };
    setConfig(restored);
    if (restored.appearance) {
      applyAppearance(restored.appearance);
    }
    setMessage({ ok: true, text: 'تمت استعادة الإعدادات الافتراضية للمنصة في النموذج. احرص على الضغط على حفظ لتأكيدها.' });
  };

  // Import configuration from file
  const handleImportConfig = async (imported: PlatformConfig) => {
    if (!config) return;
    const merged = { ...imported, version: config.version };
    setConfig(merged);
    if (merged.appearance) {
      applyAppearance(merged.appearance);
    }
    setMessage({ ok: true, text: 'تم تحميل ملف التكوين في النموذج بنجاح. اضغط على حفظ لاعتماده نهائيًا.' });
  };

  // Live preview helper for appearance tab
  const handlePreviewAppearance = (partial: Partial<PlatformConfig['appearance']>) => {
    if (!config) return;
    const updated = { ...config.appearance, ...partial };
    applyAppearance(updated);
  };

  // Navigation Groups Configuration
  const groups: SettingsNavGroup[] = useMemo(
    () => [
      {
        id: 'group_overview',
        title: 'الرئيسية',
        icon: LayoutDashboard,
        children: [
          {
            id: 'overview',
            label: 'نظرة عامة والخدمات',
            helpAnchor: 'platform-settings',
          },
        ],
      },
      {
        id: 'group_general',
        title: 'الإعدادات العامة',
        icon: Sliders,
        children: [
          {
            id: 'general',
            label: 'عام والمنطقة',
            helpAnchor: 'general-settings',
          },
          {
            id: 'appearance',
            label: 'المظهر والسمات',
            helpAnchor: 'appearance-settings',
          },
        ],
      },
      {
        id: 'group_identity',
        title: 'الهوية والوصول',
        icon: Users,
        children: [
          {
            id: 'users',
            label: 'المستخدمون والأدوار',
            badge: 'RBAC',
            helpAnchor: 'users-roles',
          },
          {
            id: 'security',
            label: 'الأمان والجلسات',
            isRestartRequired: true,
            helpAnchor: 'security-settings',
          },
        ],
      },
      {
        id: 'group_intelligence',
        title: 'الذكاء والتحليل',
        icon: Sparkles,
        children: [
          {
            id: 'ai',
            label: 'نماذج الذكاء الاصطناعي',
            badge: `${config?.ai_providers?.length || 0}`,
            helpAnchor: 'ai-providers',
          },
          {
            id: 'ollama',
            label: 'خادم Ollama المحلي',
            badge: config?.ollama?.enabled ? 'نشط' : 'معطل',
            helpAnchor: 'ollama-ai',
          },
          {
            id: 'analysis',
            label: 'محركات التحليل والخطورة',
            helpAnchor: 'analysis-engines',
          },
          {
            id: 'uploads',
            label: 'سياسات رفع الملفات',
            helpAnchor: 'upload-policies',
          },
        ],
      },
      {
        id: 'group_sources',
        title: 'المصادر والتكاملات',
        icon: Plug,
        children: [
          {
            id: 'integrations',
            label: 'مصادر السمعة الخارجية',
            badge: 'Threat Intel',
            helpAnchor: 'threat-intelligence',
          },
          {
            id: 'sources',
            label: 'الأنظمة المصدرية للبيئات',
            helpAnchor: 'source-systems',
          },
        ],
      },
      {
        id: 'group_data',
        title: 'البيانات والتقارير',
        icon: FileText,
        children: [
          {
            id: 'reports',
            label: 'التقارير وهوية الوثائق',
            helpAnchor: 'reports-export',
          },
          {
            id: 'storage',
            label: 'التخزين والاحتفاظ بالبيانات',
            helpAnchor: 'storage-retention',
          },
        ],
      },
      {
        id: 'group_system',
        title: 'النظام والتشغيل',
        icon: Network,
        children: [
          {
            id: 'logging',
            label: 'السجلات والتدقيق الأمني',
            helpAnchor: 'audit-logging',
          },
          {
            id: 'features',
            label: 'مفاتيح الميزات (Flags)',
            helpAnchor: 'feature-flags',
          },
          {
            id: 'network',
            label: 'الشبكة والمنافذ',
            isRestartRequired: true,
            helpAnchor: 'network-ports',
          },
          {
            id: 'governance',
            label: 'الحوكمة وسجل الإصدارات',
            badge: `v${config?.version || 1}`,
            helpAnchor: 'governance-settings',
          },
          {
            id: 'maintenance',
            label: 'النسخ الاحتياطي والصيانة',
            helpAnchor: 'backup-maintenance',
          },
        ],
      },
    ],
    [config]
  );

  // Search Index Dictionary
  const searchIndex: SettingsSearchIndexItem[] = useMemo(
    () => [
      { tabId: 'general', title: 'لغة المنصة', category: 'عام', keywords: ['لغة', 'عربي', 'انجليزي', 'language', 'ar', 'en'], description: 'تحديد لغة واجهة النظام واتجاه العرض' },
      { tabId: 'general', title: 'المنطقة الزمنية', category: 'عام', keywords: ['توقيت', 'منطقة زمنية', 'ساعة', 'timezone', 'asia', 'riyadh'], description: 'معيار توقيت طوابع الوقت الجنائية' },
      { tabId: 'general', title: 'توقيت ومزامنة المنصة (NTP / يدوي / المضيف)', category: 'عام', keywords: ['توقيت', 'مزامنة', 'ساعة', 'ntp', 'time', 'sync', 'clock', 'manual', 'host', 'pool.ntp.org'], description: 'ضبط مصدر توقيت المنصة (المضيف، يدوي، أو خادم NTP)' },
      { tabId: 'general', title: 'الصفحة الافتراضية', category: 'عام', keywords: ['صفحة', 'افتراضية', 'توجيه', 'dashboard', 'flowscope', 'threatscope', 'logscope'], description: 'الصفحة المفتوحة تلقائيًا بعد الدخول' },
      { tabId: 'general', title: 'كثافة عرض الجداول', category: 'عام', keywords: ['عناصر', 'صفحة', 'pagination', 'items_per_page'], description: 'عدد السجلات المعروضة في كل صفحة' },
      { tabId: 'appearance', title: 'سمات المظهر (Themes)', category: 'المظهر', keywords: ['ثيم', 'مظهر', 'داكن', 'فاتح', 'منتصف الليل', 'جرافيت', 'بحري', 'dark', 'light', 'midnight', 'graphite', 'navy'], description: 'السمات البصرية الخمس المصممة للمنصة' },
      { tabId: 'appearance', title: 'ألوان الهوية والعناوين', category: 'المظهر', keywords: ['ألوان', 'لون', 'أساسي', 'تمييز', 'عنوان', 'شعار', 'color', 'primary', 'accent'], description: 'تخصيص اللون الأساسي وعنوان المنصة' },
      { tabId: 'users', title: 'إدارة المستخدمين', category: 'الهوية', keywords: ['مستخدمين', 'حساب', 'محلل', 'مدير', 'users', 'rbac', 'admin', 'analyst'], description: 'إنشاء وتعديل وحذف حسابات المحللين' },
      { tabId: 'users', title: 'مصفوفة الصلاحيات', category: 'الهوية', keywords: ['صلاحيات', 'أدوار', 'مصفوفة', 'permissions', 'roles', 'presets'], description: 'تخصيص الصلاحيات الـ 21 وأدوار الوصول' },
      { tabId: 'security', title: 'مدة الجلسات', category: 'الأمان', keywords: ['جلسة', 'جلسات', 'ساعات', 'session', 'jwt', 'cookie'], description: 'مدة بقاء تسجيل الدخول قبل الخروج' },
      { tabId: 'security', title: 'سياسة قفل الحساب والتخمين', category: 'الأمان', keywords: ['قفل', 'محاولات', 'تخمين', 'lockout', 'rate limit', 'attempts'], description: 'الحد الأقصى لمحاولات الدخول الفاشلة ونافذة الحظر' },
      { tabId: 'security', title: 'كوكي مشفر HTTPS', category: 'الأمان', keywords: ['كوكي', 'https', 'ssl', 'secure cookie'], description: 'اشتراط اتصال HTTPS لنقل ملف تعريف الارتباط' },
      { tabId: 'ai', title: 'مزودو الذكاء الاصطناعي الخارجيون', category: 'الذكاء', keywords: ['ذكاء', 'openai', 'gpt', 'ai', 'providers', 'api key', 'llm'], description: 'ربط مزودي LLM متوافقين مع معيار OpenAI' },
      { tabId: 'ollama', title: 'خادم Ollama المحلي', category: 'الذكاء', keywords: ['ollama', 'محلي', 'gemma', 'llama', 'أولاما', 'on-premises'], description: 'الذكاء الاصطناعي المحلي المعزول عن الإنترنت' },
      { tabId: 'analysis', title: 'عتبات الخطورة (Risk Thresholds)', category: 'التحليل', keywords: ['خطورة', 'متوسط', 'مرتفع', 'حرج', 'عتبات', 'thresholds', 'risk', 'critical'], description: 'المستويات الفاصلة لتصنيف الحوادث والتهديدات' },
      { tabId: 'analysis', title: 'عمال الفحص المتوازي والكاش', category: 'التحليل', keywords: ['عمال', 'كاش', 'workers', 'cache', 'sqlite', 'ttl'], description: 'عدد خيوط الفحص وصلاحية ذاكرة التخزين المؤقت' },
      { tabId: 'uploads', title: 'الحد الأقصى لرفع الملفات', category: 'التحليل', keywords: ['رفع', 'حجم', 'ملفات', 'mb', 'upload', 'limits', 'flowscope', 'threatscope', 'logscope'], description: 'سقف أحجام الملفات لكل محرك تحليلي' },
      { tabId: 'uploads', title: 'حماية قنابل الضغط XLSX', category: 'التحليل', keywords: ['ضغط', 'excel', 'xlsx', 'zip bomb', 'ratio'], description: 'معايير الأمان لمنع هجمات قنابل الضغط' },
      { tabId: 'sources', title: 'الأنظمة المصدرية والبيئات', category: 'المصادر', keywords: ['بيئات', 'مصدر', 'flowmon', 'xdr', 'siem', 'manageengine', 'splunk', 'syslog'], description: 'مسميات مراكز تدفقات الشبكة والسجلات' },
      { tabId: 'integrations', title: 'VirusTotal وحوض المفاتيح', category: 'المصادر', keywords: ['virustotal', 'سمعة', 'مفاتيح', 'reputation', 'vt'], description: 'فحص سمعة العناوين وتدوير مفاتيح API' },
      { tabId: 'integrations', title: 'AbuseIPDB و MalwareBazaar و Shodan', category: 'المصادر', keywords: ['abuseipdb', 'malwarebazaar', 'shodan', 'سمعة', 'بصمات'], description: 'خدمات فحص سمعة العناوين والبصمات المدمجة' },
      { tabId: 'reports', title: 'هوية وتصنيف التقارير', category: 'التقارير', keywords: ['تقرير', 'تقارير', 'word', 'excel', 'pdf', 'classification', 'تصنيف'], description: 'ترويسة وتصنيف ومسمى محلل التقارير الرسمية' },
      { tabId: 'reports', title: 'محرك المعاينة والملخص التنفيذي', category: 'التقارير', keywords: ['معاينة', 'libreoffice', 'word', 'preview'], description: 'محرك تحويل المستندات وسقف النتائج والتوصيات' },
      { tabId: 'storage', title: 'سياسات الاحتفاظ بالبيانات', category: 'التخزين', keywords: ['احتفاظ', 'حذف', 'تنظيف', 'retention', 'days', 'storage'], description: 'مدة بقاء مهام التحليل وسجلات التدقيق' },
      { tabId: 'storage', title: 'استهلاك القرص الصلب', category: 'التخزين', keywords: ['قرص', 'مساحة', 'سعة', 'disk', 'usage', 'free'], description: 'المقاييس الفعلية للمساحة التخزينية لجذر المنصة' },
      { tabId: 'logging', title: 'مستويات التسجيل والتدقيق', category: 'النظام', keywords: ['سجل', 'تسجيل', 'تدقيق', 'debug', 'info', 'logging', 'audit'], description: 'دقة وعمق تسجيل العمليات في ملفات التدقيق' },
      { tabId: 'features', title: 'مفاتيح الميزات (Feature Flags)', category: 'النظام', keywords: ['ميزات', 'خصائص', 'flags', 'flowscope', 'threatscope', 'logscope', 'excel'], description: 'تفعيل أو تعطيل محركات ووظائف المنصة' },
      { tabId: 'network', title: 'منافذ الخدمات (Service Ports)', category: 'الشبكة', keywords: ['منفذ', 'منافذ', 'ports', '3000', '8081', '8082', 'gateway', 'python'], description: 'منافذ TCP للواجهة وبوابة API ومحرك التحليل' },
      { tabId: 'network', title: 'عنوان الاستماع والوكيل الموثوق', category: 'الشبكة', keywords: ['استماع', 'bind', 'ip', 'proxy', 'cors', 'origins'], description: 'عنوان الربط والمهلة الزمنية والأصول الموثوقة' },
      { tabId: 'maintenance', title: 'النسخ الاحتياطي وتصدير التكوين', category: 'الصيانة', keywords: ['تصدير', 'استيراد', 'نسخ احتياطي', 'backup', 'export', 'import', 'json'], description: 'تنزيل أو استيراد ملفات التكوين بأمان' },
      { tabId: 'maintenance', title: 'استعادة الإعدادات الافتراضية', category: 'الصيانة', keywords: ['استعادة', 'افتراضي', 'ضبط مصنع', 'reset', 'defaults'], description: 'إعادة ضبط المنصة على القيم القياسية المعتمدة' },
    ],
    []
  );

  // Search Results Filtering
  const searchResults = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return [];
    return searchIndex.filter(
      (item) =>
        item.title.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q) ||
        item.keywords.some((k) => k.toLowerCase().includes(q))
    );
  }, [searchQuery, searchIndex]);

  // Headers Lookup for Active Tab
  const activeHeaderInfo = useMemo(() => {
    for (const group of groups) {
      const child = group.children.find((c) => c.id === activeTab);
      if (child) {
        return {
          title: child.label,
          subtitle: group.title,
          icon: group.icon,
          isRestart: child.isRestartRequired,
          helpAnchor: child.helpAnchor,
        };
      }
    }
    return {
      title: 'مركز التحكم والإعدادات',
      subtitle: 'لوحة القيادة المركزية',
      icon: LayoutDashboard,
      isRestart: false,
      helpAnchor: 'platform-settings',
    };
  }, [groups, activeTab]);

  if (loading) {
    return (
      <div className="min-h-screen">
        <Navbar />
        <div className="h-[70vh] flex flex-col items-center justify-center text-slate-400 gap-3">
          <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
          <span className="text-sm font-bold">جارٍ تحميل مركز إدارة المنصة...</span>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="min-h-screen">
        <Navbar />
        <div className="max-w-xl mx-auto mt-20 glass-panel p-8 text-center text-rose-300 space-y-4">
          <XCircle className="w-12 h-12 text-rose-400 mx-auto" />
          <h2 className="text-lg font-bold text-white">تعذر جلب إعدادات المنصة</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            تأكد من تشغيل بوابة API ومحرك التحليل الخلفي وصلاحيات حسابك (users.manage).
          </p>
          <button
            type="button"
            onClick={loadConfigData}
            className="px-5 py-2.5 rounded-xl bg-cyan-500 text-slate-950 font-black text-xs inline-flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            إعادة المحاولة
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-7">
        {/* Top Breadcrumb & Quick Actions Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <div className="text-[11px] text-cyan-400 font-black tracking-wider flex items-center gap-2 mb-1">
              <Sliders className="w-3.5 h-3.5" />
              CENTRALIZED PLATFORM ADMINISTRATION
            </div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
              مركز التحكم وإعدادات المنصة
            </h1>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Mobile Toggle Button */}
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="lg:hidden px-3.5 py-2 rounded-xl border border-white/10 bg-white/5 text-xs font-bold text-white flex items-center gap-2"
            >
              <Sliders className="w-4 h-4 text-cyan-400" />
              الأقسام
            </button>

            {isDirty && (
              <span className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/15 border border-amber-500/30 text-amber-300">
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                توجد تعديلات غير محفوظة
              </span>
            )}
          </div>
        </div>

        {/* Global Feedback Banner */}
        {message && (
          <div
            className={`mb-6 rounded-2xl border p-4 flex items-start gap-3 text-xs leading-relaxed animate-fade-in ${
              message.ok
                ? message.isRestart
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-200'
            }`}
          >
            {message.ok ? (
              message.isRestart ? (
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              )
            ) : (
              <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1 font-semibold">{message.text}</div>
            <button
              type="button"
              onClick={() => setMessage(null)}
              className="p-1 rounded-lg text-slate-400 hover:text-white"
            >
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Search Results Dropdown Overlay */}
        {searchQuery && searchResults.length > 0 && (
          <div className="mb-6 rounded-2xl border border-cyan-500/30 bg-dark-900/95 p-4 backdrop-blur-md space-y-3 shadow-xl">
            <div className="flex items-center justify-between text-xs text-slate-400 border-b border-white/5 pb-2">
              <span className="font-bold text-cyan-300">
                نتائج البحث عن «{searchQuery}» ({searchResults.length} مطابقة):
              </span>
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="text-slate-400 hover:text-white"
              >
                إغلاق
              </button>
            </div>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-72 overflow-y-auto">
              {searchResults.map((r, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => {
                    setActiveTab(r.tabId);
                    setSearchQuery('');
                  }}
                  className="text-right p-3 rounded-xl border border-white/10 bg-white/[0.02] hover:bg-cyan-500/10 hover:border-cyan-500/30 transition-all space-y-1 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-white group-hover:text-cyan-300 transition-colors">
                      {r.title}
                    </span>
                    <span className="text-[10px] font-semibold px-2 py-0.5 rounded-md bg-white/10 text-slate-300">
                      {r.category}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed truncate">{r.description}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Main Settings Grid Layout */}
        <div className="grid lg:grid-cols-[280px_1fr] gap-6 items-start">
          {/* Categorized Sidebar */}
          <SettingsSidebar
            groups={groups}
            activeTab={activeTab}
            onSelectTab={(tabId) => {
              setActiveTab(tabId);
            }}
            dirtyTabs={dirtyTabs}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            mobileOpen={mobileOpen}
            onCloseMobile={() => setMobileOpen(false)}
            version={config.version}
          />

          {/* Active Settings Panel */}
          <section className="glass-panel p-5 sm:p-7 min-h-[700px] relative">
            {/* Unified Header */}
            {activeTab !== 'overview' && (
              <SettingsHeader
                title={activeHeaderInfo.title}
                subtitle={activeHeaderInfo.subtitle}
                icon={activeHeaderInfo.icon}
                isRestartRequired={activeHeaderInfo.isRestart}
                helpAnchor={activeHeaderInfo.helpAnchor}
                onSave={handleSave}
                onReset={handleResetCurrentTab}
                onReload={loadConfigData}
                saving={saving}
                isDirty={isDirty}
              />
            )}

            {/* Tab Views */}
            {activeTab === 'overview' && (
              <TabOverview config={config} onNavigate={(tab) => setActiveTab(tab)} />
            )}

            {activeTab === 'general' && (
              <TabGeneral
                config={config}
                onChange={(general) => setConfig({ ...config, general: { ...config.general, ...general } })}
                onTimeChange={(time) =>
                  setConfig({
                    ...config,
                    time: {
                      source: 'host',
                      manual_time: '',
                      ntp_server: 'pool.ntp.org',
                      ntp_port: 123,
                      ntp_sync_interval_seconds: 3600,
                      auto_sync: true,
                      ...(config.time || {}),
                      ...time,
                    },
                  })
                }
              />
            )}

            {activeTab === 'appearance' && (
              <TabAppearance
                config={config}
                onChange={(appearance) => setConfig({ ...config, appearance: { ...config.appearance, ...appearance } })}
                onPreview={handlePreviewAppearance}
              />
            )}

            {activeTab === 'users' && <TabUsers />}

            {activeTab === 'security' && (
              <TabSecurity
                config={config}
                onChange={(security) => setConfig({ ...config, security: { ...config.security, ...security } })}
              />
            )}

            {activeTab === 'ai' && (
              <TabAI
                config={config}
                onChange={(ai) => setConfig({ ...config, ...ai })}
              />
            )}

            {activeTab === 'ollama' && (
              <TabOllama
                config={config}
                onChange={(ollama) => setConfig({ ...config, ollama: { ...config.ollama, ...ollama } })}
              />
            )}

            {activeTab === 'analysis' && (
              <TabAnalysis
                config={config}
                onChange={(analysis) => setConfig({ ...config, analysis: { ...config.analysis, ...analysis } })}
              />
            )}

            {activeTab === 'uploads' && (
              <TabUploads
                config={config}
                onChange={(uploads) => setConfig({ ...config, uploads: { ...config.uploads, ...uploads } })}
              />
            )}

            {activeTab === 'sources' && (
              <TabSources
                config={config}
                onChange={(sources) => setConfig({ ...config, ...sources })}
              />
            )}

            {activeTab === 'integrations' && (
              <TabIntegrations
                config={config}
                onChange={(integrations) => setConfig({ ...config, ...integrations })}
              />
            )}

            {activeTab === 'reports' && (
              <TabReports
                config={config}
                onChange={(reports) => setConfig({ ...config, reports: { ...config.reports, ...reports } })}
              />
            )}

            {activeTab === 'storage' && (
              <TabStorage
                config={config}
                onChange={(storage) => setConfig({ ...config, storage: { ...config.storage, ...storage } })}
              />
            )}

            {activeTab === 'logging' && (
              <TabLogging
                config={config}
                onChange={(logging) => setConfig({ ...config, logging: { ...config.logging, ...logging } })}
              />
            )}

            {activeTab === 'features' && (
              <TabFeatures
                config={config}
                onChange={(features) => setConfig({ ...config, features: { ...config.features, ...features } })}
              />
            )}

            {activeTab === 'network' && (
              <TabNetwork
                config={config}
                onChange={(network) => setConfig({ ...config, network: { ...config.network, ...network } })}
              />
            )}

            {activeTab === 'governance' && (
              <TabGovernance
                config={config}
                onChange={setConfig}
                onReload={loadConfigData}
              />
            )}

            {activeTab === 'maintenance' && (
              <TabMaintenance
                config={config}
                defaults={defaults}
                onImportConfig={handleImportConfig}
                onResetAll={handleResetAllToDefaults}
                onResetSection={handleResetCurrentTab}
              />
            )}
          </section>
        </div>

        {/* Floating Unsaved Changes Bar */}
        <UnsavedChangesBar
          isDirty={isDirty}
          saving={saving}
          dirtyCount={dirtyTabs.size}
          onSave={handleSave}
          onReset={handleResetCurrentTab}
        />
      </main>
    </div>
  );
}
