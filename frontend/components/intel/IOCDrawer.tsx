'use client';

import React, { useEffect, useState } from 'react';
import {
  X, Shield, ShieldAlert, Globe, Link2, Hash, Key, Copy, Check,
  Clock, Tag, UserX, AlertTriangle, Trash2, Power, History, ExternalLink, Loader2
} from 'lucide-react';
import { getIOCHits, toggleIOC, deleteIOC } from '../../lib/api';
import { IOCItem, IOCHitItem } from '../../lib/types';

interface IOCDrawerProps {
  ioc: IOCItem | null;
  onClose: () => void;
  onUpdated: () => void;
}

export function IOCDrawer({ ioc, onClose, onUpdated }: IOCDrawerProps) {
  const [copied, setCopied] = useState(false);
  const [hits, setHits] = useState<IOCHitItem[]>([]);
  const [loadingHits, setLoadingHits] = useState(false);
  const [toggling, setToggling] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [activeTab, setActiveTab] = useState<'details' | 'hits'>('details');

  useEffect(() => {
    if (ioc?.id) {
      setLoadingHits(true);
      getIOCHits(ioc.id)
        .then((res) => setHits(res.hits || []))
        .catch(() => setHits([]))
        .finally(() => setLoadingHits(false));
    }
  }, [ioc?.id]);

  if (!ioc) return null;

  const copyValue = () => {
    navigator.clipboard.writeText(ioc.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleToggleActive = async () => {
    setToggling(true);
    try {
      await toggleIOC(ioc.id, !ioc.is_active);
      onUpdated();
    } catch (err) {
      console.error('Failed to toggle IOC active state', err);
    } finally {
      setToggling(false);
    }
  };

  const handleDelete = async () => {
    if (!confirmDelete) {
      setConfirmDelete(true);
      return;
    }
    setDeleting(true);
    try {
      await deleteIOC(ioc.id);
      onUpdated();
      onClose();
    } catch (err) {
      console.error('Failed to delete IOC', err);
    } finally {
      setDeleting(false);
    }
  };

  const getTypeIcon = () => {
    switch (ioc.type) {
      case 'ip':
        return <Globe className="w-5 h-5 text-blue-400" />;
      case 'domain':
        return <Globe className="w-5 h-5 text-cyan-400" />;
      case 'url':
        return <Link2 className="w-5 h-5 text-indigo-400" />;
      case 'hash_md5':
      case 'hash_sha1':
      case 'hash_sha256':
        return <Hash className="w-5 h-5 text-emerald-400" />;
      case 'certificate':
        return <Key className="w-5 h-5 text-purple-400" />;
      default:
        return <Shield className="w-5 h-5 text-slate-400" />;
    }
  };

  const getTlpBadge = () => {
    switch (ioc.tlp) {
      case 'red':
        return <span className="px-2 py-0.5 rounded bg-red-600/30 text-red-300 font-mono font-bold text-xs border border-red-500/40">TLP:RED</span>;
      case 'amber':
        return <span className="px-2 py-0.5 rounded bg-amber-500/30 text-amber-300 font-mono font-bold text-xs border border-amber-500/40">TLP:AMBER</span>;
      case 'green':
        return <span className="px-2 py-0.5 rounded bg-emerald-500/30 text-emerald-300 font-mono font-bold text-xs border border-emerald-500/40">TLP:GREEN</span>;
      default:
        return <span className="px-2 py-0.5 rounded bg-slate-500/30 text-slate-300 font-mono font-bold text-xs border border-slate-500/40">TLP:WHITE</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm animate-fadeIn" dir="rtl">
      <div className="absolute inset-y-0 left-0 max-w-full flex pl-0 sm:pl-10">
        <div className="w-screen max-w-2xl bg-dark-900/98 border-r border-white/10 shadow-2xl flex flex-col">
          {/* Header */}
          <div className="p-6 border-b border-white/10 bg-white/[0.02]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center">
                  {getTypeIcon()}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-white/10 text-slate-300">
                      {ioc.type}
                    </span>
                    {getTlpBadge()}
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${
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
                  </div>
                  <h3 className="text-sm font-mono font-bold text-white mt-1.5 break-all select-all flex items-center gap-2" dir="ltr">
                    <span>{ioc.value}</span>
                    <button
                      type="button"
                      onClick={copyValue}
                      className="text-slate-400 hover:text-white p-1 rounded transition-colors"
                      title="نسخ القيمة"
                    >
                      {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </h3>
                </div>
              </div>

              <button
                type="button"
                onClick={onClose}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick action bar */}
            <div className="mt-4 pt-3 border-t border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleToggleActive}
                  disabled={toggling}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    ioc.is_active
                      ? 'bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30'
                      : 'bg-slate-500/20 text-slate-400 hover:bg-slate-500/30'
                  }`}
                >
                  <Power className="w-3.5 h-3.5" />
                  <span>{ioc.is_active ? 'نشط في الكاش الفوري' : 'معطل مؤقتاً'}</span>
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleDelete}
                  disabled={deleting}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    confirmDelete
                      ? 'bg-red-600 text-white animate-pulse'
                      : 'bg-white/5 hover:bg-red-500/20 text-slate-400 hover:text-red-400'
                  }`}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>{confirmDelete ? 'تأكيد الحذف النهائي؟' : 'حذف المؤشر'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex border-b border-white/10 bg-white/[0.01] px-6">
            <button
              type="button"
              onClick={() => setActiveTab('details')}
              className={`pb-3 pt-3 px-4 text-xs font-semibold border-b-2 transition-colors ${
                activeTab === 'details'
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              البيانات الجنائية والمعايير
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('hits')}
              className={`pb-3 pt-3 px-4 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
                activeTab === 'hits'
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-slate-400 hover:text-white'
              }`}
            >
              <History className="w-4 h-4" />
              <span>سجل المطابقات والرصد ({ioc.hit_count})</span>
            </button>
          </div>

          {/* Drawer Body */}
          <div className="p-6 flex-1 overflow-y-auto space-y-6">
            {activeTab === 'details' ? (
              <>
                {/* Confidence Bar */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-semibold text-slate-300">درجة موثوقية الاستخبارات (Confidence):</span>
                    <span className="font-bold text-emerald-400 font-mono">{ioc.confidence}%</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-white/10 overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-emerald-500 to-cyan-400 rounded-full"
                      style={{ width: `${ioc.confidence}%` }}
                    />
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-[11px] text-slate-400">تصنيف التهديد:</div>
                    <div className="text-sm font-semibold text-white mt-1 uppercase">
                      {ioc.threat_type}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-[11px] text-slate-400">الفاعل / العصابة:</div>
                    <div className="text-sm font-semibold text-purple-300 mt-1">
                      {ioc.related_threat_actor || 'غير محدد'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-[11px] text-slate-400">المصدر الموثوق:</div>
                    <div className="text-xs font-semibold text-slate-200 mt-1">
                      {ioc.source}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-white/[0.02] border border-white/10">
                    <div className="text-[11px] text-slate-400">تاريخ أول / آخر رصد:</div>
                    <div className="text-xs font-mono text-slate-300 mt-1">
                      {ioc.first_seen ? ioc.first_seen.split('T')[0] : 'N/A'}
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/10 space-y-3">
                  <h4 className="text-xs font-bold text-white flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    <span>مصفوفة هجوم MITRE ATT&CK v14.1:</span>
                  </h4>
                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-slate-400">التكتيكات (Tactics):</span>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {ioc.mitre_attack?.tactics && ioc.mitre_attack.tactics.length > 0 ? (
                          ioc.mitre_attack.tactics.map((t, idx) => (
                            <span key={idx} className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 text-[11px]">
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 text-[11px]">لا توجد تكتيكات مسجلة</span>
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-slate-400">التقنيات (Techniques):</span>
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {ioc.mitre_attack?.techniques && ioc.mitre_attack.techniques.length > 0 ? (
                          ioc.mitre_attack.techniques.map((te, idx) => (
                            <span key={idx} className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono text-[11px]">
                              {te}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 text-[11px]">لا توجد تقنيات مسجلة</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Tags */}
                {ioc.tags && ioc.tags.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                      <Tag className="w-3.5 h-3.5 text-slate-400" />
                      <span>الوسوم الجنائية (Tags):</span>
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {ioc.tags.map((tg, idx) => (
                        <span key={idx} className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-xs text-slate-300 font-mono">
                          #{tg}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Description */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 mb-2">الوصف والسياق الجنائي:</h4>
                  <div className="p-3.5 rounded-xl bg-black/40 border border-white/10 text-xs text-slate-300 leading-relaxed">
                    {ioc.description || 'لا يوجد وصف جنائي مسجل لهذا المؤشر.'}
                  </div>
                </div>
              </>
            ) : (
              /* Hits History Tab */
              <div className="space-y-4">
                <div className="flex items-center justify-between text-xs text-slate-300">
                  <span>إجمالي مطابقات الكشف: <strong className="text-white font-mono">{ioc.hit_count}</strong></span>
                  {ioc.last_hit_at && (
                    <span className="text-slate-400">آخر مطابقة: {new Date(ioc.last_hit_at).toLocaleString('ar-SA')}</span>
                  )}
                </div>

                {loadingHits ? (
                  <div className="flex items-center justify-center p-8">
                    <Loader2 className="w-6 h-6 text-emerald-400 animate-spin" />
                  </div>
                ) : hits.length === 0 ? (
                  <div className="p-8 text-center rounded-xl bg-white/[0.02] border border-white/10 text-xs text-slate-400">
                    لم يتم تسجيل أي رصد مطابق لهذا المؤشر في جلسات التحليل حتى الآن.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {hits.map((h) => (
                      <div key={h.id} className="p-3.5 rounded-xl bg-white/[0.02] border border-white/10 space-y-2">
                        <div className="flex items-center justify-between text-xs">
                          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono uppercase font-bold">
                            {h.source_app}
                          </span>
                          <span className="text-slate-400 font-mono">
                            {new Date(h.hit_timestamp).toLocaleString('ar-SA')}
                          </span>
                        </div>
                        {h.event_data && Object.keys(h.event_data).length > 0 && (
                          <pre className="p-2 rounded bg-black/50 text-[11px] font-mono text-slate-300 overflow-x-auto" dir="ltr">
                            {JSON.stringify(h.event_data, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
