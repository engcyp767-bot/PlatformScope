'use client';

import React, { useEffect, useState, useMemo, useRef } from 'react';
import {
  BookOpen, Search, X, ChevronRight, ChevronLeft, ArrowRight, ArrowLeft,
  ExternalLink, Copy, Check, Info, AlertTriangle, AlertCircle, CheckCircle2,
  FileText, Shield, Terminal, Hash, Menu, Compass, Sparkles, Layers, Cpu,
  Radar, Activity, RefreshCw
} from 'lucide-react';
import { Navbar } from '../../components/Navbar';
import { getHelpGuide } from '../../lib/api';
import {
  parseMarkdownGuide, searchDocumentation, DocSection, MarkdownBlock, SearchResult
} from '../../lib/markdown';

export default function HelpCenterPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rawGuide, setRawGuide] = useState<string>('');
  const [lastModified, setLastModified] = useState<string>('');
  const [activeSectionId, setActiveSectionId] = useState<string>('quick-start');
  const [searchQuery, setSearchQuery] = useState('');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const tocNavRef = useRef<HTMLElement>(null);

  // Restore and maintain TOC sidebar scroll position to keep active section locked in view
  useEffect(() => {
    const saved = sessionStorage.getItem('help_toc_scroll_top');
    if (saved && tocNavRef.current) {
      tocNavRef.current.scrollTop = Number(saved);
    }
  }, []);

  useEffect(() => {
    if (!tocNavRef.current || !activeSectionId) return;
    const timer = setTimeout(() => {
      const activeBtn = tocNavRef.current?.querySelector<HTMLElement>('[data-active="true"]');
      if (activeBtn) {
        activeBtn.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    }, 60);
    return () => clearTimeout(timer);
  }, [activeSectionId]);

  // Load guide from single source of truth via Gateway API
  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    getHelpGuide()
      .then((data) => {
        if (!isMounted) return;
        setRawGuide(data.content || '');
        setLastModified(data.lastModified ? new Date(data.lastModified).toLocaleDateString('ar-EG', { dateStyle: 'long' }) : '');
        setLoading(false);
      })
      .catch((err) => {
        if (!isMounted) return;
        setError(err.message || 'تعذر تحميل دليل الاستخدام.');
        setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  // Parse markdown into sections and table of contents
  const { sections, tableOfContents } = useMemo(() => {
    if (!rawGuide) return { sections: [], tableOfContents: [] };
    return parseMarkdownGuide(rawGuide);
  }, [rawGuide]);

  // Handle URL hash on initial load or hashchange
  useEffect(() => {
    if (sections.length === 0) return;

    const handleHash = () => {
      const hash = window.location.hash.replace(/^#/, '');
      if (hash) {
        const found = sections.find((s) => s.id === hash);
        if (found) {
          setActiveSectionId(found.id);
          const el = document.getElementById(found.id);
          if (el) {
            el.scrollIntoView({ behavior: 'auto' });
          }
        }
      } else if (sections.length > 0) {
        setActiveSectionId(sections[0].id);
      }
    };

    handleHash();
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, [sections]);

  // Search results
  const searchResults: SearchResult[] = useMemo(() => {
    if (!searchQuery.trim()) return [];
    return searchDocumentation(searchQuery, sections);
  }, [searchQuery, sections]);

  // Current active section object and index
  const activeIndex = sections.findIndex((s) => s.id === activeSectionId);
  const activeSection = sections[activeIndex] || sections[0] || null;
  const prevSection = activeIndex > 0 ? sections[activeIndex - 1] : null;
  const nextSection = activeIndex < sections.length - 1 ? sections[activeIndex + 1] : null;

  // Jump to specific section
  const handleSelectSection = (id: string) => {
    setActiveSectionId(id);
    window.location.hash = id;
    setMobileMenuOpen(false);
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'auto' });
    }
  };

  // Copy anchor link
  const handleCopyLink = (id: string) => {
    const url = `${window.location.origin}/help#${id}`;
    navigator.clipboard.writeText(url);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Quick Start Domain Cards definitions
  const quickCards = [
    { id: 'quick-start', title: 'البدء السريع', desc: 'إعداد الحساب، تسجيل الدخول الأول، وتغيير كلمة المرور', icon: Compass, color: 'from-blue-500/20 to-cyan-500/20 text-cyan-400 border-cyan-500/30' },
    { id: 'flowscope', title: 'تحليل FlowScope', desc: 'تحليل حركة الشبكة وملفات PCAP و NetFlow واكتشاف الشذوذ', icon: Activity, color: 'from-blue-600/20 to-indigo-600/20 text-blue-400 border-blue-500/30' },
    { id: 'logscope', title: 'تحليل LogScope', desc: 'تحليل سجلات الأمان ونموذج الأحداث الموحد CanonicalEvent', icon: FileText, color: 'from-purple-500/20 to-pink-500/20 text-purple-400 border-purple-500/30' },
    { id: 'threatscope', title: 'تحليل ThreatScope', desc: 'تحليل تنبيهات XDR وشجرة العمليات وفحص التجزئات', icon: Shield, color: 'from-amber-500/20 to-orange-500/20 text-amber-400 border-amber-500/30' },
    { id: 'incident-management', title: 'إدارة الحوادث', desc: 'دورة حياة الحوادث الأمنية، خزانة الأدلة وتصنيف الأولويات P1-P4', icon: AlertTriangle, color: 'from-red-500/20 to-rose-500/20 text-red-400 border-red-500/30' },
    { id: 'detection-engineering', title: 'هندسة قواعد الكشف', desc: 'تأليف واختبار قواعد الكشف والمحاكي التراجعي ومقاييس الأداء', icon: Cpu, color: 'from-emerald-500/20 to-teal-500/20 text-emerald-400 border-emerald-500/30' },
    { id: 'sigma-studio', title: 'استوديو قواعد Sigma', desc: 'فحص التوافق الدلالي ثلاثي المستويات ومستودع القواعد العالمي', icon: Layers, color: 'from-cyan-500/20 to-blue-500/20 text-cyan-300 border-cyan-500/30' },
    { id: 'threat-intelligence', title: 'استخبارات التهديدات', desc: 'مؤشرات الاختراق IOCs، بروتوكول TLP وتكامل حزم STIX 2.1', icon: Radar, color: 'from-teal-500/20 to-emerald-500/20 text-teal-400 border-teal-500/30' },
    { id: 'ai-advisor', title: 'المستشار الذكي (AI)', desc: 'التحليل الاسترشادي المحلي عبر Ollama وقواعد العمل المستقلة', icon: Sparkles, color: 'from-violet-500/20 to-purple-500/20 text-violet-400 border-violet-500/30' },
    { id: 'reporting', title: 'التقارير والمعاينة', desc: 'تصدير Word و Excel المتدفق ومعاينة PDF المدمجة المباشرة', icon: FileText, color: 'from-slate-500/20 to-zinc-500/20 text-slate-300 border-slate-500/30' },
  ];

  return (
    <div className="min-h-screen flex flex-col font-sans selection:bg-primary/30 selection:text-white" dir="rtl">
      <Navbar />

      {/* Hero Header & Search Section */}
      <section className="relative border-b border-[var(--border)] bg-gradient-to-b from-primary/5 via-transparent to-transparent backdrop-blur-md py-10 px-4 sm:px-6 lg:px-8">
        <div className="max-w-6xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-primary text-xs font-semibold mb-4">
            <BookOpen className="w-3.5 h-3.5" />
            <span>مركز التوثيق والدعم التشغيلي الموحد</span>
          </div>

          <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight mb-3 font-heading">
            دليل الاستخدام ومركز المساعدة
          </h1>
          <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto mb-6">
            دليل عملي تفصيلي لفرق مراكز العمليات الأمنية (SOC) ومحللي الحوادث الرقمية (DFIR) وهندسة الكشف.
            المحتوى متزامن لحظياً ومباشرة مع النظام البرمجي للمنصة.
          </p>

          {/* Search Box */}
          <div className="max-w-2xl mx-auto relative">
            <div className="relative flex items-center">
              <Search className="w-5 h-5 text-slate-400 absolute right-4 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="ابحث في دليل الاستخدام (مثال: Sigma، الحوادث، تقرير PDF، STIX، FlowScope، IOC)..."
                className="w-full pl-10 pr-12 py-3.5 rounded-xl bg-dark-950/80 border border-white/15 focus:border-primary focus:ring-2 focus:ring-primary/20 text-white placeholder-slate-500 text-sm shadow-xl transition-all outline-none"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute left-3 p-1 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
                  title="مسح البحث"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>

            {/* Instant Search Results Dropdown / Panel */}
            {searchQuery.trim() && (
              <div className="absolute top-full right-0 left-0 mt-2 bg-dark-900/95 border border-white/15 rounded-xl shadow-2xl backdrop-blur-xl z-50 max-h-96 overflow-y-auto p-2 text-right">
                <div className="px-3 py-2 text-xs font-semibold text-slate-400 border-b border-white/5 flex items-center justify-between">
                  <span>نتائج البحث ({searchResults.length})</span>
                  <span>اضغط على النتيجة للانتقال المباشر</span>
                </div>
                {searchResults.length === 0 ? (
                  <div className="p-6 text-center text-sm text-slate-500">
                    لا توجد نتائج تطابق &quot;{searchQuery}&quot;. جرب كلمة بحث أخرى مثل &quot;FlowScope&quot; أو &quot;Sigma&quot;.
                  </div>
                ) : (
                  <div className="divide-y divide-white/5">
                    {searchResults.map((res) => (
                      <button
                        key={res.sectionId}
                        onClick={() => {
                          handleSelectSection(res.sectionId);
                          setSearchQuery('');
                        }}
                        className="w-full text-right p-3 rounded-lg hover:bg-white/5 transition-colors group flex flex-col gap-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-bold text-primary group-hover:text-cyan-300 transition-colors">
                            {res.sectionTitle}
                          </span>
                          <span className="text-[10px] text-slate-500 bg-white/5 px-2 py-0.5 rounded font-mono">
                            #{res.sectionId}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                          {res.matchedText}
                        </p>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {lastModified && (
            <div className="mt-3 text-[11px] text-slate-500">
              آخر تحديث للدليل المعتمد: {lastModified}
            </div>
          )}
        </div>
      </section>

      {/* Main Content Layout */}
      <div className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col lg:flex-row gap-8">
        {/* Sidebar: Table of Contents */}
        <aside className="lg:w-80 shrink-0">
          {/* Mobile TOC Toggle Button */}
          <div className="lg:hidden mb-4">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="w-full flex items-center justify-between px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-sm font-semibold text-slate-200"
            >
              <div className="flex items-center gap-2">
                <Menu className="w-4 h-4 text-primary" />
                <span>فهرس دليل الاستخدام ({sections.length} قسم)</span>
              </div>
              <ChevronRight className={`w-4 h-4 transition-transform ${mobileMenuOpen ? 'rotate-90' : ''}`} />
            </button>
          </div>

          {/* Sticky Sidebar Container */}
          <div className={`sticky top-20 rounded-2xl glass-panel p-4 shadow-xl backdrop-blur-md ${mobileMenuOpen ? 'block' : 'hidden lg:block'}`}>
            <div className="flex items-center justify-between pb-3 border-b border-white/10 mb-3">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-primary" />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  أقسام الدليل المعتمد
                </span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/20 text-primary font-bold">
                {sections.length}
              </span>
            </div>

            <nav
              ref={tocNavRef}
              onScroll={(e) => {
                sessionStorage.setItem('help_toc_scroll_top', String(e.currentTarget.scrollTop));
              }}
              className="max-h-[calc(100vh-220px)] overflow-y-auto space-y-1 pr-1 pl-1 text-sm custom-scrollbar"
            >
              {tableOfContents.map((item) => {
                const isActive = activeSectionId === item.id;
                const isMainSection = item.level === 2;
                return (
                  <button
                    key={item.id}
                    data-active={isActive ? 'true' : undefined}
                    onClick={() => {
                      if (tocNavRef.current) {
                        sessionStorage.setItem('help_toc_scroll_top', String(tocNavRef.current.scrollTop));
                      }
                      handleSelectSection(item.id);
                    }}
                    className={`w-full text-right flex items-center justify-between gap-2 px-3 py-2 rounded-xl text-xs transition-all select-none ${
                      isActive
                        ? 'bg-primary/25 text-primary border border-primary/40 font-extrabold shadow-sm'
                        : isMainSection
                        ? 'bg-slate-800/65 dark:bg-slate-800/50 border border-slate-700/50 dark:border-white/10 text-slate-200 font-bold hover:bg-slate-800/85 hover:text-white my-1'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-white/5 border border-transparent mr-2.5 text-[11px]'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      {isMainSection && (
                        <span className={`w-1.5 h-3 rounded-full shrink-0 ${isActive ? 'bg-primary' : 'bg-slate-500/70'}`} />
                      )}
                      <span className="truncate">{item.title}</span>
                    </div>
                    {isActive && <div className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />}
                  </button>
                );
              })}
            </nav>
          </div>
        </aside>

        {/* Content Area */}
        <main className="flex-1 min-w-0">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-24 gap-4">
              <RefreshCw className="w-8 h-8 text-primary animate-spin" />
              <p className="text-sm text-slate-400 font-medium">جاري قراءة وتحليل دليل الاستخدام الموحد...</p>
            </div>
          ) : error ? (
            <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-8 text-center">
              <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-3" />
              <h3 className="text-lg font-bold text-white mb-2">تعذر قراءة دليل الاستخدام</h3>
              <p className="text-sm text-red-300 mb-4">{error}</p>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-xs font-semibold text-red-200"
              >
                إعادة المحاولة
              </button>
            </div>
          ) : (
            <div className="space-y-8">
              {/* Quick Jump Cards (Shown at the top of the active view) */}
              <div className="rounded-2xl glass-panel p-5 backdrop-blur-sm">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                    <Compass className="w-4 h-4 text-primary" />
                    <span>الانتقال السريع إلى المجالات الأمنية</span>
                  </h2>
                  <span className="text-[11px] text-slate-500">اختر مجالاً للاطلاع على إرشاداته وتشغيله</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
                  {quickCards.map((card) => {
                    const Icon = card.icon;
                    const isCardActive = activeSectionId === card.id;
                    return (
                      <button
                        key={card.id}
                        onClick={() => handleSelectSection(card.id)}
                        className={`text-right p-3 rounded-xl border bg-gradient-to-br transition-all hover:scale-[1.02] flex flex-col gap-1.5 ${card.color} ${
                          isCardActive ? 'ring-2 ring-primary shadow-lg' : 'opacity-90 hover:opacity-100'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <Icon className="w-4 h-4" />
                          <ChevronLeft className="w-3.5 h-3.5 opacity-60" />
                        </div>
                        <span className="text-xs font-bold text-white leading-tight">
                          {card.title}
                        </span>
                        <span className="text-[10px] text-slate-300 line-clamp-2 leading-tight">
                          {card.desc}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Active Section Content Container */}
              {activeSection ? (
                <article id={activeSection.id} className="rounded-2xl glass-panel p-6 sm:p-8 backdrop-blur-md shadow-2xl">
                  {/* Section Header */}
                  <div className="pb-6 border-b border-white/10 mb-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <div className="inline-flex items-center gap-1.5 text-xs text-primary font-mono mb-1">
                        <Hash className="w-3.5 h-3.5" />
                        <span>قسم #{activeSection.id}</span>
                      </div>
                      <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight font-heading">
                        {activeSection.title}
                      </h2>
                    </div>

                    <button
                      onClick={() => handleCopyLink(activeSection.id)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-300 hover:text-white transition-colors shrink-0"
                      title="نسخ رابط مباشر لهذا القسم"
                    >
                      {copiedId === activeSection.id ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">تم نسخ الرابط!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-slate-400" />
                          <span>نسخ الرابط</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Render Structured Blocks */}
                  <div className="space-y-6 text-slate-300 leading-relaxed">
                    {activeSection.rawBlocks.map((block, idx) => (
                      <RenderBlock key={idx} block={block} onAnchorClick={handleSelectSection} />
                    ))}
                  </div>

                  {/* Previous / Next Navigation Buttons */}
                  <div className="mt-12 pt-6 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
                    {prevSection ? (
                      <button
                        onClick={() => handleSelectSection(prevSection.id)}
                        className="w-full sm:w-auto flex items-center gap-2.5 px-4 py-3 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-slate-200 hover:text-white transition-all group"
                      >
                        <ArrowRight className="w-4 h-4 text-primary group-hover:-translate-x-1 transition-transform" />
                        <div className="text-right">
                          <span className="block text-[10px] text-slate-400 uppercase font-mono">القسم السابق</span>
                          <span className="font-bold">{prevSection.title}</span>
                        </div>
                      </button>
                    ) : (
                      <div className="hidden sm:block" />
                    )}

                    {nextSection ? (
                      <button
                        onClick={() => handleSelectSection(nextSection.id)}
                        className="w-full sm:w-auto flex items-center justify-between sm:justify-start gap-2.5 px-4 py-3 rounded-xl bg-primary/10 hover:bg-primary/20 border border-primary/30 text-xs font-semibold text-primary hover:text-white transition-all group"
                      >
                        <div className="text-left sm:text-right">
                          <span className="block text-[10px] text-primary/70 uppercase font-mono">القسم التالي</span>
                          <span className="font-bold">{nextSection.title}</span>
                        </div>
                        <ArrowLeft className="w-4 h-4 text-primary group-hover:translate-x-1 transition-transform" />
                      </button>
                    ) : (
                      <div className="hidden sm:block" />
                    )}
                  </div>
                </article>
              ) : null}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

// Markdown Block Renderer Component
function RenderBlock({ block, onAnchorClick }: { block: MarkdownBlock; onAnchorClick: (id: string) => void }) {
  const [copiedCode, setCopiedCode] = useState(false);

  switch (block.type) {
    case 'heading': {
      if (block.level === 2) return null; // Already shown in section header
      const HeadingTag = block.level === 3 ? 'h3' : 'h4';
      return (
        <div className="pt-4 border-t border-[var(--border)] first:border-0 first:pt-0">
          <HeadingTag className={`font-bold tracking-wide ${block.level === 3 ? 'text-lg sm:text-xl text-primary' : 'text-base text-[var(--text-main)]'}`}>
            {block.text}
          </HeadingTag>
        </div>
      );
    }

    case 'paragraph': {
      return <p className="text-sm sm:text-base text-[var(--text-soft)] leading-relaxed">{block.text}</p>;
    }

    case 'alert': {
      const variants = {
        note: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400 dark:text-blue-300', icon: Info, title: 'ملاحظة تشغيلية (Note)' },
        tip: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400 dark:text-emerald-300', icon: CheckCircle2, title: 'نصيحة أمنية (Security Tip)' },
        important: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400 dark:text-amber-300', icon: AlertTriangle, title: 'إجراء هام وإلزامي (Important)' },
        warning: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400 dark:text-orange-300', icon: AlertTriangle, title: 'تحذير (Warning)' },
        caution: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400 dark:text-red-300', icon: AlertCircle, title: 'تنبيه عالي الخطورة (Caution)' },
      };
      const v = variants[block.variant] || variants.note;
      const Icon = v.icon;

      return (
        <div className={`rounded-xl border p-4 sm:p-5 ${v.bg} ${v.border} flex items-start gap-3.5 my-4`}>
          <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${v.text}`} />
          <div className="flex-1 min-w-0">
            <h4 className={`text-xs font-bold uppercase tracking-wider mb-1 ${v.text}`}>
              {v.title}
            </h4>
            <p className="text-xs sm:text-sm text-[var(--text-main)] leading-relaxed whitespace-pre-line">
              {block.text}
            </p>
          </div>
        </div>
      );
    }

    case 'code': {
      const handleCopy = () => {
        navigator.clipboard.writeText(block.code);
        setCopiedCode(true);
        setTimeout(() => setCopiedCode(false), 2000);
      };

      return (
        <div className="rounded-xl border border-[var(--border)] bg-[#0a0f1d] overflow-hidden my-4 shadow-lg text-left" dir="ltr">
          <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/10 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-primary" />
              <span>{block.language || 'code'}</span>
            </div>
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
            >
              {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedCode ? 'تم النسخ' : 'Copy'}</span>
            </button>
          </div>
          <pre className="p-4 text-xs sm:text-sm font-mono text-emerald-400 overflow-x-auto selection:bg-emerald-500/30">
            <code>{block.code}</code>
          </pre>
        </div>
      );
    }

    case 'table': {
      return (
        <div className="overflow-x-auto my-4 rounded-xl border border-[var(--border)] bg-[var(--bg-panel)]">
          <table className="w-full text-right text-xs sm:text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] bg-white/5 text-[var(--text-main)] font-bold">
                {block.headers.map((h, i) => (
                  <th key={i} className="py-3 px-4">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {block.rows.map((row, rowIdx) => (
                <tr key={rowIdx} className="hover:bg-white/5 transition-colors">
                  {row.map((cell, cellIdx) => (
                    <td key={cellIdx} className="py-2.5 px-4 text-[var(--text-soft)]">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }

    case 'list': {
      if (block.ordered) {
        return (
          <ol className="list-decimal list-inside space-y-2 text-sm sm:text-base text-[var(--text-soft)] pr-2">
            {block.items.map((item, idx) => (
              <li key={idx} className="leading-relaxed">
                {item}
              </li>
            ))}
          </ol>
        );
      }
      return (
        <ul className="space-y-2 text-sm sm:text-base text-[var(--text-soft)]">
          {block.items.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2.5 leading-relaxed">
              <span className="w-1.5 h-1.5 rounded-full bg-primary mt-2 shrink-0" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      );
    }

    case 'divider': {
      return <hr className="border-[var(--border)] my-6" />;
    }

    default:
      return null;
  }
}
