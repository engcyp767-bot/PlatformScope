'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Search,
  X,
  AlertTriangle,
  Server,
  Shield,
  Target,
  ListTodo,
  ExternalLink,
  ArrowRight,
  CornerDownLeft,
  Loader2,
} from 'lucide-react';
import { GlobalSearchResultItem, GlobalSearchResponse } from '../lib/types';
import { globalSearch } from '../lib/api';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type EntityFilter = 'all' | 'incidents' | 'assets' | 'rules' | 'iocs' | 'tasks';

export function GlobalSearchModal({ isOpen, onClose }: GlobalSearchModalProps) {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<EntityFilter>('all');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<GlobalSearchResponse['results']>({
    incidents: [],
    assets: [],
    rules: [],
    iocs: [],
    tasks: [],
  });
  const [totalMatches, setTotalMatches] = useState(0);
  const [selectedIndex, setSelectedIndex] = useState(0);

  // Focus on input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
    } else {
      setQuery('');
      setResults({ incidents: [], assets: [], rules: [], iocs: [], tasks: [] });
      setTotalMatches(0);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  // Debounced Search
  useEffect(() => {
    if (!isOpen) return;
    const trimmed = query.trim();
    if (trimmed.length < 2) {
      setResults({ incidents: [], assets: [], rules: [], iocs: [], tasks: [] });
      setTotalMatches(0);
      setSelectedIndex(0);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const entities = activeFilter === 'all' ? undefined : [activeFilter];
        const res = await globalSearch(trimmed, entities, 6);
        setResults(res.results);
        setTotalMatches(res.total_matches);
        setSelectedIndex(0);
      } catch {
        // silent fail
      } finally {
        setLoading(false);
      }
    }, 180);

    return () => clearTimeout(timer);
  }, [query, activeFilter, isOpen]);

  // Flattened list for keyboard navigation
  const flattenedResults: GlobalSearchResultItem[] = React.useMemo(() => {
    const list: GlobalSearchResultItem[] = [];
    if (activeFilter === 'all' || activeFilter === 'incidents') list.push(...results.incidents);
    if (activeFilter === 'all' || activeFilter === 'assets') list.push(...results.assets);
    if (activeFilter === 'all' || activeFilter === 'rules') list.push(...results.rules);
    if (activeFilter === 'all' || activeFilter === 'iocs') list.push(...results.iocs);
    if (activeFilter === 'all' || activeFilter === 'tasks') list.push(...results.tasks);
    return list;
  }, [results, activeFilter]);

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => (flattenedResults.length === 0 ? 0 : (prev + 1) % flattenedResults.length));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => (flattenedResults.length === 0 ? 0 : (prev - 1 + flattenedResults.length) % flattenedResults.length));
      } else if (e.key === 'Enter') {
        if (flattenedResults.length > 0 && selectedIndex < flattenedResults.length) {
          e.preventDefault();
          const target = flattenedResults[selectedIndex];
          onClose();
          router.push(target.url);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, flattenedResults, selectedIndex, onClose, router]);

  if (!isOpen) return null;

  const getEntityIcon = (type: GlobalSearchResultItem['entity_type']) => {
    switch (type) {
      case 'incident':
        return <AlertTriangle className="w-4 h-4 text-rose-400" />;
      case 'asset':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'rule':
        return <Shield className="w-4 h-4 text-purple-400" />;
      case 'ioc':
        return <Target className="w-4 h-4 text-amber-400" />;
      case 'task':
        return <ListTodo className="w-4 h-4 text-emerald-400" />;
    }
  };

  const getBadgeClass = (color: string) => {
    switch (color) {
      case 'rose':
        return 'bg-rose-500/10 text-rose-300 border-rose-500/25';
      case 'amber':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/25';
      case 'emerald':
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25';
      case 'purple':
        return 'bg-purple-500/10 text-purple-300 border-purple-500/25';
      case 'cyan':
        return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/25';
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/25';
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-16 sm:pt-24 p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div
        className="w-full max-w-2xl bg-dark-900/95 border border-white/15 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[80vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="p-4 border-b border-white/10 flex items-center gap-3 bg-white/[0.02]">
          <Search className="w-5 h-5 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="البحث الشامل في المنصة (الحوادث، الأصول، قواعد الكشف، مؤشرات IOC، المهام)..."
            className="flex-1 bg-transparent text-sm text-white placeholder-slate-400 focus:outline-none"
          />
          {loading && <Loader2 className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />}
          {query && !loading && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="p-1 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="hidden sm:inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-white/5 border border-white/10 text-slate-400">
            ESC
          </kbd>
        </div>

        {/* Filter Pills */}
        <div className="px-4 py-2 border-b border-white/5 bg-white/[0.01] flex items-center gap-2 overflow-x-auto text-xs">
          {[
            { id: 'all', label: 'الكل' },
            { id: 'incidents', label: 'الحوادث' },
            { id: 'assets', label: 'الأصول' },
            { id: 'rules', label: 'قواعد الكشف' },
            { id: 'iocs', label: 'مؤشرات التهديد' },
            { id: 'tasks', label: 'المهام' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveFilter(tab.id as EntityFilter)}
              className={`px-3 py-1 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${
                activeFilter === tab.id
                  ? 'bg-cyan-500 text-slate-950 shadow-sm shadow-cyan-500/20'
                  : 'bg-white/5 text-slate-400 hover:bg-white/10 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {query.trim().length < 2 ? (
            <div className="p-8 text-center space-y-2">
              <Search className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-xs text-slate-400">
                اكتب حرفين على الأقل للبحث السريع عبر كافة مكونات المنصة.
              </p>
              <div className="flex items-center justify-center gap-4 text-[11px] text-slate-500 pt-2">
                <span>استخدم <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">↑</kbd> <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">↓</kbd> للتنقل</span>
                <span><kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">Enter</kbd> للفتح المباشر</span>
              </div>
            </div>
          ) : flattenedResults.length === 0 && !loading ? (
            <div className="p-8 text-center space-y-1">
              <p className="text-xs text-slate-400">لم يتم العثور على أي نتائج تطابق "{query}".</p>
              <p className="text-[11px] text-slate-500">جرب البحث بكلمات مختلفة أو إزالة الفلاتر.</p>
            </div>
          ) : (
            flattenedResults.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={`${item.entity_type}-${item.id}`}
                  onClick={() => {
                    onClose();
                    router.push(item.url);
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`p-3 rounded-xl cursor-pointer transition-all flex items-center justify-between gap-3 border ${
                    isSelected
                      ? 'bg-cyan-500/10 border-cyan-500/30 text-white'
                      : 'border-transparent hover:bg-white/[0.03] text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="p-2 rounded-lg bg-white/5 border border-white/10 shrink-0">
                      {getEntityIcon(item.entity_type)}
                    </div>
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-xs truncate max-w-sm">{item.title}</span>
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold border ${getBadgeClass(item.badge_color)}`}>
                          {item.badge}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 truncate">{item.subtitle}</p>
                      {item.snippet && (
                        <p className="text-[10px] text-slate-500 truncate max-w-md">{item.snippet}</p>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {isSelected && (
                      <span className="hidden sm:flex items-center gap-1 text-[10px] font-mono text-cyan-400 bg-cyan-500/15 px-2 py-0.5 rounded border border-cyan-500/25">
                        <span>فتح</span>
                        <CornerDownLeft className="w-3 h-3" />
                      </span>
                    )}
                    <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-2.5 border-t border-white/10 bg-white/[0.02] flex items-center justify-between text-[11px] text-slate-400 px-4">
          <span>تم العثور على {totalMatches} نتيجة</span>
          <div className="flex items-center gap-3 text-[10px]">
            <span>التنقل: <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">↑↓</kbd></span>
            <span>الفتح: <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">↵</kbd></span>
            <span>الإغلاق: <kbd className="px-1.5 py-0.5 rounded bg-white/5 border border-white/10">ESC</kbd></span>
          </div>
        </div>
      </div>
    </div>
  );
}
