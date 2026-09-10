'use client';

import React, { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import {
  Radar, Plus, Search, Filter, Download, UploadCloud, RefreshCw,
  Globe, Link2, Hash, Key, ShieldAlert, CheckCircle2, AlertTriangle,
  Flame, Copy, Check, ChevronLeft, ChevronRight, Eye, Sparkles, ExternalLink, BookOpen
} from 'lucide-react';
import { getIOCs, getIOCSummary, toggleIOC } from '../../lib/api';
import { IOCItem, IOCSummary, IOCFilterOptions, IOCType } from '../../lib/types';
import { QuickLookupModal } from '../../components/intel/QuickLookupModal';
import { AddIOCModal } from '../../components/intel/AddIOCModal';
import { IOCDrawer } from '../../components/intel/IOCDrawer';
import { Navbar } from '../../components/Navbar';

export default function ThreatIntelPage() {
  const [iocs, setIocs] = useState<IOCItem[]>([]);
  const [summary, setSummary] = useState<IOCSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  // Filters
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedThreatType, setSelectedThreatType] = useState<string>('all');
  const [selectedTlp, setSelectedTlp] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const limit = 20;

  // Modals & Drawer
  const [lookupModalOpen, setLookupModalOpen] = useState(false);
  const [addModalOpen, setAddModalOpen] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState<IOCItem | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [iocsRes, sumRes] = await Promise.all([
        getIOCs({
          type: selectedType !== 'all' ? selectedType : undefined,
          severity: selectedSeverity !== 'all' ? selectedSeverity : undefined,
          threat_type: selectedThreatType !== 'all' ? selectedThreatType : undefined,
          tlp: selectedTlp !== 'all' ? selectedTlp : undefined,
          search: searchQuery.trim() || undefined,
          page,
          limit,
        }),
        getIOCSummary(),
      ]);

      setIocs(iocsRes.iocs || []);
      setTotal(iocsRes.total || 0);
      setSummary(sumRes);
    } catch (err) {
      console.error('Failed to load threat intelligence data', err);
    } finally {
      setLoading(false);
    }
  }, [selectedType, selectedSeverity, selectedThreatType, selectedTlp, searchQuery, page]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const copyToClipboard = (val: string, id: string) => {
    navigator.clipboard.writeText(val);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleToggle = async (ioc: IOCItem, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const updated = await toggleIOC(ioc.id, !ioc.is_active);
      setIocs((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
      if (selectedIOC?.id === updated.id) {
        setSelectedIOC(updated);
      }
    } catch (err) {
      console.error('Toggle failed', err);
    }
  };

  const getTypeIcon = (type: IOCType) => {
    switch (type) {
      case 'ip':
        return <Globe className="w-4 h-4 text-blue-400" />;
      case 'domain':
        return <Globe className="w-4 h-4 text-cyan-400" />;
      case 'url':
        return <Link2 className="w-4 h-4 text-indigo-400" />;
      case 'hash_md5':
      case 'hash_sha1':
      case 'hash_sha256':
        return <Hash className="w-4 h-4 text-emerald-400" />;
      case 'certificate':
        return <Key className="w-4 h-4 text-purple-400" />;
      default:
        return <Flame className="w-4 h-4 text-slate-400" />;
    }
  };

  const getTlpBadge = (tlp: string) => {
    switch (tlp) {
      case 'red':
        return <span className="px-2 py-0.5 rounded bg-red-600/30 text-red-300 font-mono font-bold text-[10px] border border-red-500/40">TLP:RED</span>;
      case 'amber':
        return <span className="px-2 py-0.5 rounded bg-amber-500/30 text-amber-300 font-mono font-bold text-[10px] border border-amber-500/40">TLP:AMBER</span>;
      case 'green':
        return <span className="px-2 py-0.5 rounded bg-emerald-500/30 text-emerald-300 font-mono font-bold text-[10px] border border-emerald-500/40">TLP:GREEN</span>;
      default:
        return <span className="px-2 py-0.5 rounded bg-slate-500/30 text-slate-300 font-mono font-bold text-[10px] border border-slate-500/40">TLP:WHITE</span>;
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="min-h-screen bg-[#070b13] text-slate-100 flex flex-col" dir="rtl">
      <Navbar />

      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Top Banner & Actions */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-4 border-b border-white/10">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/10">
              <Radar className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold text-white tracking-wide flex items-center gap-2">
                <span>استخبارات التهديدات وقاعدة المؤشرات المركزية</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  Threat Intel O(1)
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                قاعدة بيانات مركزية لمؤشرات الاختراق (IOCs) مع مطابقة فورية عالية السرعة وربط أوتوماتيكي مع سجلات وحوادث SOC
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <Link
            href="/help#threat-intelligence"
            className="px-3.5 py-2 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-xs font-semibold text-emerald-300 flex items-center gap-1.5 transition-colors shadow-sm"
            title="فتح دليل استخبارات التهديدات ومؤشرات الاختراق"
          >
            <BookOpen className="w-4 h-4 text-emerald-400" />
            <span>دليل المؤشرات وIOC</span>
          </Link>

          <button
            type="button"
            onClick={() => setLookupModalOpen(true)}
            className="px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Search className="w-4 h-4 text-emerald-400" />
            <span>فحص سريع فوري</span>
          </button>

          <div className="relative group">
            <button
              type="button"
              className="px-3.5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <Download className="w-4 h-4 text-cyan-400" />
              <span>تصدير الحزمة</span>
            </button>
            <div className="absolute left-0 mt-1 w-44 rounded-xl bg-dark-900 border border-white/10 shadow-2xl py-1 hidden group-hover:block z-30">
              <a
                href="/api/intel/export?format=json"
                download="threat_intel.json"
                className="block px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:bg-white/5"
              >
                تصدير JSON المهيكل
              </a>
              <a
                href="/api/intel/export?format=csv"
                download="threat_intel.csv"
                className="block px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:bg-white/5"
              >
                تصدير جدول CSV
              </a>
              <a
                href="/api/intel/export?format=stix"
                download="threat_intel_stix.json"
                className="block px-3 py-1.5 text-xs text-emerald-400 hover:text-emerald-300 hover:bg-white/5 font-semibold"
              >
                تصدير STIX 2.1 Bundle
              </a>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setAddModalOpen(true)}
            className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-emerald-600/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>إضافة / استيراد مؤشرات</span>
          </button>

          <button
            type="button"
            onClick={loadData}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-400 hover:text-white transition-colors"
            title="تحديث البيانات"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-lg space-y-1 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-semibold">إجمالي مؤشرات التهديد</span>
            <span className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Globe className="w-4 h-4" />
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {summary?.total_iocs || 0}
          </div>
          <div className="text-[11px] text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" />
            <span>{summary?.active_iocs || 0} مؤشر نشط في الذاكرة</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-lg space-y-1 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-semibold">إجمالي مطابقات الرصد (Hits)</span>
            <span className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {summary?.total_hits || 0}
          </div>
          <div className="text-[11px] text-slate-400">
            تطابقات حية مع تدفقات LogScope
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-lg space-y-1 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-semibold">توزيع الخطورة المرتفعة</span>
            <span className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center text-orange-400">
              <Flame className="w-4 h-4" />
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-orange-400">
            {(summary?.by_severity?.critical || 0) + (summary?.by_severity?.high || 0)}
          </div>
          <div className="text-[11px] text-slate-400 flex items-center gap-2">
            <span>حرجة: {summary?.by_severity?.critical || 0}</span>
            <span>|</span>
            <span>مرتفعة: {summary?.by_severity?.high || 0}</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 shadow-lg space-y-1 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400 font-semibold">تنوع الفئات المعرفية</span>
            <span className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <Sparkles className="w-4 h-4" />
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-purple-300">
            {Object.keys(summary?.by_type || {}).length} أنواع
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            IP: {summary?.by_type?.ip || 0} | Dom: {summary?.by_type?.domain || 0} | Hash: {(summary?.by_type?.hash_sha256 || 0) + (summary?.by_type?.hash_md5 || 0)}
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-dark-900/60 border border-white/10 space-y-3">
        {/* Type selector pills */}
        <div className="flex flex-wrap gap-2 pb-2 border-b border-white/5">
          {[
            { id: 'all', label: 'كافة المؤشرات' },
            { id: 'ip', label: 'عناوين IP' },
            { id: 'domain', label: 'النطاقات (Domains)' },
            { id: 'url', label: 'الروابط (URLs)' },
            { id: 'hash', label: 'تجزئات الملفات (Hashes)' },
            { id: 'certificate', label: 'الشهادات الرقمية' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setSelectedType(tab.id);
                setPage(1);
              }}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all ${
                selectedType === tab.id
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm shadow-emerald-500/10'
                  : 'bg-white/5 text-slate-400 hover:text-white border border-transparent'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Dropdown filters and search */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="lg:col-span-2 relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder="البحث بالقيمة، الوصف، الوسوم، الفاعل الجنائي..."
              className="w-full pl-4 pr-9 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
            />
            <Search className="w-4 h-4 text-slate-500 absolute right-3 top-2.5" />
          </div>

          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
            >
              <option value="all">كافة مستويات الخطورة</option>
              <option value="critical">Critical (حرج)</option>
              <option value="high">High (مرتفع)</option>
              <option value="medium">Medium (متوسط)</option>
              <option value="low">Low (منخفض)</option>
            </select>
          </div>

          <div>
            <select
              value={selectedThreatType}
              onChange={(e) => {
                setSelectedThreatType(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
            >
              <option value="all">كافة تصنيفات التهديد</option>
              <option value="c2">Command & Control</option>
              <option value="malware">Malware</option>
              <option value="phishing">Phishing</option>
              <option value="ransomware">Ransomware</option>
              <option value="scanner">Scanner</option>
              <option value="exploit">Exploit</option>
              <option value="apt">APT</option>
            </select>
          </div>

          <div>
            <select
              value={selectedTlp}
              onChange={(e) => {
                setSelectedTlp(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
            >
              <option value="all">كافة مستويات TLP</option>
              <option value="red">TLP:RED</option>
              <option value="amber">TLP:AMBER</option>
              <option value="green">TLP:GREEN</option>
              <option value="white">TLP:WHITE</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main IOC Table */}
      <div className="rounded-2xl bg-dark-900/60 border border-white/10 shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-right border-collapse text-xs">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02] text-slate-400 uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">نوع المؤشر</th>
                <th className="py-3 px-4">القيمة المعيارية</th>
                <th className="py-3 px-4">تصنيف التهديد</th>
                <th className="py-3 px-4">الخطورة</th>
                <th className="py-3 px-4">الموثوقية</th>
                <th className="py-3 px-4">مستوى TLP</th>
                <th className="py-3 px-4">الفاعل / المصدر</th>
                <th className="py-3 px-4 text-center">مرات الرصد</th>
                <th className="py-3 px-4 text-center">الحالة</th>
                <th className="py-3 px-4 text-center">الإجراءات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {loading ? (
                Array.from({ length: 5 }).map((_, idx) => (
                  <tr key={idx} className="animate-pulse">
                    <td colSpan={10} className="py-4 px-4">
                      <div className="h-4 bg-white/5 rounded-lg w-full"></div>
                    </td>
                  </tr>
                ))
              ) : iocs.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-400">
                    <div className="max-w-md mx-auto space-y-2">
                      <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto" />
                      <div className="text-sm font-semibold text-white">لا توجد مؤشرات مطابقة لمعايير البحث</div>
                      <p className="text-xs text-slate-500">
                        جرّب تعديل الفلاتر المحددة أو اضغط على «إضافة / استيراد مؤشرات» لتسجيل مؤشرات جديدة.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                iocs.map((ioc) => (
                  <tr
                    key={ioc.id}
                    onClick={() => setSelectedIOC(ioc)}
                    className="hover:bg-white/[0.03] transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-md bg-white/5 flex items-center justify-center">
                          {getTypeIcon(ioc.type)}
                        </div>
                        <span className="font-mono text-[11px] text-slate-300 uppercase">
                          {ioc.type.replace('hash_', '')}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2 max-w-xs md:max-w-sm">
                        <span className="font-mono text-xs font-semibold text-white truncate" dir="ltr">
                          {ioc.value}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(ioc.value, ioc.id);
                          }}
                          className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-white transition-opacity"
                          title="نسخ"
                        >
                          {copiedId === ioc.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 font-semibold text-[11px] uppercase">
                        {ioc.threat_type}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          ioc.severity === 'critical'
                            ? 'bg-red-600 text-white'
                            : ioc.severity === 'high'
                            ? 'bg-orange-500 text-white'
                            : ioc.severity === 'medium'
                            ? 'bg-amber-500 text-black'
                            : 'bg-blue-600 text-white'
                        }`}
                      >
                        {ioc.severity}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-emerald-400 text-xs">{ioc.confidence}%</span>
                        <div className="w-12 h-1.5 rounded-full bg-white/10 overflow-hidden">
                          <div
                            className="h-full bg-emerald-500 rounded-full"
                            style={{ width: `${ioc.confidence}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4">{getTlpBadge(ioc.tlp)}</td>

                    <td className="py-3 px-4">
                      <div className="text-xs">
                        <div className="font-semibold text-purple-300 truncate max-w-[120px]">
                          {ioc.related_threat_actor || '-'}
                        </div>
                        <div className="text-[10px] text-slate-500 truncate max-w-[120px]">
                          {ioc.source}
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-center">
                      <span
                        className={`px-2 py-0.5 rounded-full font-mono text-xs font-bold ${
                          ioc.hit_count > 0
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : 'bg-white/5 text-slate-400'
                        }`}
                      >
                        {ioc.hit_count}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-center">
                      <button
                        type="button"
                        onClick={(e) => handleToggle(ioc, e)}
                        className={`w-7 h-4 rounded-full transition-colors relative inline-flex items-center ${
                          ioc.is_active ? 'bg-emerald-500' : 'bg-slate-700'
                        }`}
                      >
                        <span
                          className={`w-3 h-3 rounded-full bg-white transition-transform ${
                            ioc.is_active ? 'translate-x-0.5' : '-translate-x-3.5'
                          }`}
                        />
                      </button>
                    </td>

                    <td className="py-3 px-4 text-center">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIOC(ioc);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-emerald-400 hover:text-emerald-300 text-xs font-semibold flex items-center gap-1 mx-auto"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>تفاصيل</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-4 border-t border-white/10 bg-white/[0.01] flex items-center justify-between text-xs text-slate-400">
          <div>
            عرض <strong className="text-white font-mono">{iocs.length}</strong> من إجمالي{' '}
            <strong className="text-white font-mono">{total}</strong> مؤشر مسجل
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
            <span className="font-mono px-2">
              الصفحة {page} من {totalPages}
            </span>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 text-white transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </main>

      {/* Modals & Drawer */}
      <QuickLookupModal
        isOpen={lookupModalOpen}
        onClose={() => setLookupModalOpen(false)}
        onSelectIOC={(ioc) => setSelectedIOC(ioc)}
      />

      <AddIOCModal
        isOpen={addModalOpen}
        onClose={() => setAddModalOpen(false)}
        onSuccess={loadData}
      />

      <IOCDrawer
        ioc={selectedIOC}
        onClose={() => setSelectedIOC(null)}
        onUpdated={loadData}
      />
    </div>
  );
}
