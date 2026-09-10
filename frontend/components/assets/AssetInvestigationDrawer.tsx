'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  X, Server, Shield, AlertTriangle, Activity, Terminal, CheckCircle2,
  Copy, Check, ExternalLink, ShieldAlert, Lock, Unlock, Cpu, Globe,
  Clock, HardDrive, User, Building, Radio
} from 'lucide-react';
import { Asset, AssetContainmentAction } from '../../lib/types';
import { createAssetContainment, confirmAssetContainment, revokeAssetContainment } from '../../lib/api';

interface AssetInvestigationDrawerProps {
  asset: Asset | null;
  onClose: () => void;
  onRefresh: () => void;
  defaultTab?: 'overview' | 'mesh' | 'timeline' | 'containment';
}

export function AssetInvestigationDrawer({
  asset,
  onClose,
  onRefresh,
  defaultTab = 'overview'
}: AssetInvestigationDrawerProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'mesh' | 'timeline' | 'containment'>(defaultTab);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [containmentLoading, setContainmentLoading] = useState(false);
  const [selectedProvider, setSelectedProvider] = useState('fortinet_firewall');
  const [selectedActionType, setSelectedActionType] = useState('network_isolation');
  const [containmentError, setContainmentError] = useState<string | null>(null);

  if (!asset) return null;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleCreateContainment = async () => {
    setContainmentLoading(true);
    setContainmentError(null);
    try {
      await createAssetContainment(asset.id, selectedActionType, selectedProvider);
      onRefresh();
    } catch (err: any) {
      setContainmentError(err.message || 'فشل إنشاء خطة العزل');
    } finally {
      setContainmentLoading(false);
    }
  };

  const handleConfirmContainment = async (actionId: string) => {
    setContainmentLoading(true);
    setContainmentError(null);
    try {
      await confirmAssetContainment(actionId);
      onRefresh();
    } catch (err: any) {
      setContainmentError(err.message || 'فشل تأكيد العزل');
    } finally {
      setContainmentLoading(false);
    }
  };

  const handleRevokeContainment = async (actionId: string) => {
    setContainmentLoading(true);
    setContainmentError(null);
    try {
      await revokeAssetContainment(actionId);
      onRefresh();
    } catch (err: any) {
      setContainmentError(err.message || 'فشل إلغاء العزل');
    } finally {
      setContainmentLoading(false);
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (score >= 60) return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    if (score >= 40) return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
  };

  const getCriticalityBadge = (crit: string) => {
    const map: Record<string, { label: string; cls: string }> = {
      mission_critical: { label: 'حرج للغاية (Mission Critical)', cls: 'bg-purple-500/10 text-purple-400 border-purple-500/30' },
      high: { label: 'عالي (High)', cls: 'bg-red-500/10 text-red-400 border-red-500/30' },
      medium: { label: 'متوسط (Medium)', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
      low: { label: 'منخفض (Low)', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    };
    return map[crit] || { label: crit, cls: 'bg-white/5 text-slate-400 border-white/10' };
  };

  const getStatusBadge = (status: string) => {
    const map: Record<string, { label: string; cls: string }> = {
      active: { label: 'نشط (Active)', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
      isolated: { label: 'معزول أمنياً (Isolated)', cls: 'bg-red-500/15 text-red-400 border-red-500/40 animate-pulse' },
      unknown: { label: 'غير مصنف (Unknown)', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
      maintenance: { label: 'صيانة (Maintenance)', cls: 'bg-blue-500/10 text-blue-400 border-blue-500/30' },
      decommissioned: { label: 'خارج الخدمة (Decommissioned)', cls: 'bg-slate-500/10 text-slate-400 border-slate-500/30' },
    };
    return map[status] || { label: status, cls: 'bg-white/5 text-slate-400 border-white/10' };
  };

  const latestAction = asset.containment_actions && asset.containment_actions.length > 0 ? asset.containment_actions[0] : null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="w-full max-w-3xl bg-dark-900 border-l border-white/10 h-full flex flex-col shadow-2xl overflow-hidden animate-slide-in">
        {/* Header */}
        <div className="p-5 border-b border-white/10 bg-dark-800/60 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="w-11 h-11 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary shrink-0">
              <Server className="w-6 h-6" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-lg font-bold text-white font-mono tracking-tight truncate">{asset.hostname}</h2>
                <span className={`text-[11px] px-2 py-0.5 rounded-full border font-semibold ${getStatusBadge(asset.status).cls}`}>
                  {getStatusBadge(asset.status).label}
                </span>
                <span className={`text-[11px] px-2 py-0.5 rounded-full border font-semibold ${getCriticalityBadge(asset.criticality).cls}`}>
                  {getCriticalityBadge(asset.criticality).label}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                {asset.id} • {asset.primary_ip} {asset.mac_address ? `• ${asset.mac_address}` : ''}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {/* Dynamic Risk Meter */}
            <div className={`px-3 py-1.5 rounded-xl border flex items-center gap-2 ${getRiskColor(asset.risk_score)}`}>
              <Activity className="w-4 h-4" />
              <div className="text-left">
                <span className="text-[10px] block uppercase leading-none font-bold opacity-80">Risk Score</span>
                <span className="text-base font-bold leading-tight font-mono">{asset.risk_score}</span>
                <span className="text-[10px] opacity-70">/100</span>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
              title="إغلاق"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 px-5 pt-3 border-b border-white/10 bg-dark-800/30 overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveTab('overview')}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-primary text-primary bg-primary/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>نظرة عامة والهوية</span>
          </button>

          <button
            onClick={() => setActiveTab('mesh')}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
              activeTab === 'mesh'
                ? 'border-primary text-primary bg-primary/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>شبكة العلاقات SOC Mesh ({asset.related_incidents?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('timeline')}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
              activeTab === 'timeline'
                ? 'border-primary text-primary bg-primary/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>الخط الزمني للأصل ({asset.timeline?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('containment')}
            className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap ${
              activeTab === 'containment'
                ? 'border-red-500 text-red-400 bg-red-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>خطة العزل والاحتواء</span>
            {asset.status === 'isolated' && (
              <span className="w-2 h-2 rounded-full bg-red-400 animate-ping" />
            )}
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-5 animate-fade-in">
              {/* Identity & Technical Specs */}
              <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <HardDrive className="w-4 h-4 text-primary" />
                  الهوية الفنية ومواصفات النظام
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3.5 text-xs">
                  <div>
                    <span className="text-slate-500 block">اسم المضيف الموحد</span>
                    <span className="font-mono font-bold text-white">{asset.normalized_hostname}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">عنوان الـ IP الرئيسي</span>
                    <span className="font-mono text-primary font-semibold">{asset.primary_ip}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">عنوان الماك (MAC)</span>
                    <span className="font-mono text-slate-300">{asset.mac_address || 'غير محدد'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">نظام التشغيل</span>
                    <span className="text-slate-200">{asset.os}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">نوع الأصل</span>
                    <span className="capitalize text-slate-200">{asset.asset_type.replace('_', ' ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">البيئة</span>
                    <span className="capitalize text-slate-200">{asset.environment}</span>
                  </div>
                </div>

                {asset.ip_addresses && asset.ip_addresses.length > 1 && (
                  <div className="mt-3 pt-3 border-t border-white/5">
                    <span className="text-slate-500 text-[11px] block mb-1">عناوين IP المرتبطة تاريخياً:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {asset.ip_addresses.map((ip) => (
                        <span key={ip} className="px-2 py-0.5 rounded bg-dark-900 border border-white/10 font-mono text-[11px] text-slate-300">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Ownership & Department */}
              <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Building className="w-4 h-4 text-primary" />
                  السياق المؤسسي والملكية
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3.5 text-xs">
                  <div>
                    <span className="text-slate-500 block">القسم التابع له</span>
                    <span className="font-semibold text-white">{asset.department}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">المالك / المسؤول</span>
                    <span className="text-slate-300">{asset.owner}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">تاريخ أول رصد</span>
                    <span className="text-slate-400 font-mono text-[11px]">{asset.first_seen.slice(0, 19).replace('T', ' ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">آخر نشاط ملاحظ</span>
                    <span className="text-slate-400 font-mono text-[11px]">{asset.last_seen.slice(0, 19).replace('T', ' ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">موثوقية الاكتشاف</span>
                    <div className="flex items-center gap-2 mt-0.5">
                      <div className="w-16 h-2 bg-dark-900 rounded-full overflow-hidden border border-white/10">
                        <div className="h-full bg-primary rounded-full" style={{ width: `${asset.confidence_score}%` }} />
                      </div>
                      <span className="font-mono font-bold text-primary text-[11px]">{asset.confidence_score}%</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Discovery Sources */}
              {asset.discovery_sources && asset.discovery_sources.length > 0 && (
                <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4">
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                    <Radio className="w-4 h-4 text-primary" />
                    مصادر الاكتشاف المرصودة (Discovery Sources)
                  </h3>
                  <div className="space-y-2 mt-3">
                    {asset.discovery_sources.map((src, i) => (
                      <div key={i} className="flex items-center justify-between text-xs p-2.5 rounded-lg bg-dark-900/60 border border-white/5">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-emerald-400" />
                          <span className="font-semibold text-white capitalize">{src.source.replace('_', ' ')}</span>
                        </div>
                        <div className="flex items-center gap-4 text-slate-400 text-[11px]">
                          <span>المرات: <strong className="text-slate-200">{src.count}</strong></span>
                          <span>آخر ظهور: <span className="font-mono">{src.last_seen.slice(0, 16).replace('T', ' ')}</span></span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SOC MESH */}
          {activeTab === 'mesh' && (
            <div className="space-y-5 animate-fade-in">
              {/* Linked Incidents */}
              <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    الحوادث الأمنية المرتبطة بالأصل ({asset.related_incidents?.length || 0})
                  </h3>
                </div>

                {(!asset.related_incidents || asset.related_incidents.length === 0) ? (
                  <div className="text-center py-6 text-slate-500 text-xs">
                    لا توجد حوادث أمنية نشطة مسجلة على هذا الأصل حالياً.
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {asset.related_incidents.map((inc) => (
                      <div key={inc.id} className="p-3 rounded-lg bg-dark-900/80 border border-white/10 flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-red-400">{inc.id}</span>
                            <span className="text-xs font-semibold text-white truncate">{inc.title}</span>
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-400">
                            <span>الحالة: <strong className="text-slate-200 capitalize">{inc.status}</strong></span>
                            <span>الأولوية: <strong className="text-red-300">{inc.priority}</strong></span>
                            <span>التوقيت: <span className="font-mono">{inc.created_at?.slice(0, 16).replace('T', ' ')}</span></span>
                          </div>
                        </div>
                        <Link
                          href={`/incidents?id=${inc.id}`}
                          className="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-medium flex items-center gap-1 shrink-0 transition-colors"
                        >
                          <span>فتح الحادث</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Matched IOCs */}
              <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-amber-400" />
                  مؤشرات التهديد المطابقة (Threat Intel IOCs)
                </h3>

                {(!asset.matched_iocs || asset.matched_iocs.length === 0) ? (
                  <div className="text-center py-6 text-slate-500 text-xs">
                    لم يتم رصد أي مؤشرات اختراق (IOCs) مطابقة لقاعدة الاستخبارات على هذا الأصل.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {asset.matched_iocs.map((ioc, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-dark-900/60 border border-amber-500/20 flex items-center justify-between gap-2 text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-mono text-[10px] uppercase font-bold">
                            {ioc.threat_type}
                          </span>
                          <span className="font-mono text-slate-200 truncate">{ioc.value}</span>
                        </div>
                        <span className="text-slate-400 text-[11px] shrink-0">
                          الثقة: <strong className="text-amber-400">{ioc.confidence}%</strong>
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: TIMELINE */}
          {activeTab === 'timeline' && (
            <div className="space-y-4 animate-fade-in">
              {(!asset.timeline || asset.timeline.length === 0) ? (
                <div className="text-center py-8 text-slate-500 text-xs">
                  لا توجد أحداث مسجلة في الخط الزمني لهذا الأصل حتى الآن.
                </div>
              ) : (
                <div className="relative border-r border-white/10 pr-4 space-y-4 mr-2">
                  {asset.timeline.map((ev) => (
                    <div key={ev.id} className="relative group">
                      {/* Timeline Dot */}
                      <span className={`absolute -right-[21px] top-1.5 w-2.5 h-2.5 rounded-full ring-4 ring-dark-900 ${
                        ev.severity === 'critical' ? 'bg-red-500 ring-red-500/20' :
                        ev.severity === 'high' ? 'bg-orange-500 ring-orange-500/20' :
                        ev.severity === 'medium' ? 'bg-amber-500 ring-amber-500/20' : 'bg-primary ring-primary/20'
                      }`} />

                      <div className="bg-dark-800/50 border border-white/10 rounded-xl p-3 text-xs">
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span className="font-bold text-white">{ev.title}</span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            {ev.timestamp?.slice(0, 19).replace('T', ' ')}
                          </span>
                        </div>
                        {ev.description && (
                          <p className="text-slate-400 text-[11px] leading-relaxed">{ev.description}</p>
                        )}
                        <div className="mt-1.5 flex items-center gap-2 text-[10px] text-slate-500">
                          <span>المسؤول: <strong className="text-slate-400">{ev.actor}</strong></span>
                          <span>•</span>
                          <span className="uppercase font-mono">{ev.event_type}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: CONTAINMENT */}
          {activeTab === 'containment' && (
            <div className="space-y-5 animate-fade-in">
              {/* Containment Status Banner */}
              {asset.status === 'isolated' ? (
                <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className="w-9 h-9 rounded-lg bg-red-500/20 flex items-center justify-center text-red-400 shrink-0">
                      <Lock className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-white">الأصل معزول أمنياً عن الشبكة</h4>
                      <p className="text-xs text-red-300/80 mt-0.5">
                        تم تفعيل خطة العزل الأمني لهذا الجهاز للحد من التحرك العرضي (Lateral Movement) وانتشار الهجمات.
                      </p>
                    </div>
                  </div>
                  {latestAction && (
                    <button
                      onClick={() => handleRevokeContainment(latestAction.id)}
                      disabled={containmentLoading}
                      className="px-3.5 py-1.5 rounded-lg bg-red-500 hover:bg-red-600 text-white text-xs font-semibold shrink-0 transition-colors flex items-center gap-1.5"
                    >
                      <Unlock className="w-3.5 h-3.5" />
                      <span>فك العزل الأمني</span>
                    </button>
                  )}
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                  <p className="text-xs text-emerald-300">
                    الأصل متصل بالشبكة بشكل طبيعي. يمكنك توليد خطة عزل فوري (Containment Playbook) عند الاشتباه في اختراقه.
                  </p>
                </div>
              )}

              {containmentError && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
                  {containmentError}
                </div>
              )}

              {/* Create New Containment Action Form */}
              {asset.status !== 'isolated' && (
                <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4 space-y-4">
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-primary" />
                    توليد خطة احتواء وعزل جديدة (Action Framework)
                  </h4>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">نوع الإجراء المطلوب</label>
                      <select
                        value={selectedActionType}
                        onChange={(e) => setSelectedActionType(e.target.value)}
                        className="w-full bg-dark-900 border border-white/10 rounded-lg p-2 text-white text-xs focus:border-primary outline-none"
                      >
                        <option value="network_isolation">عزل شبكي كامل (Full Network Isolation)</option>
                        <option value="firewall_block">حظر في جدار الحماية (Firewall Perimeter Block)</option>
                        <option value="edr_containment">احتواء عبر وكيل EDR (EDR Host Quarantine)</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 mb-1">نظام / مزود العزل المستهدف</label>
                      <select
                        value={selectedProvider}
                        onChange={(e) => setSelectedProvider(e.target.value)}
                        className="w-full bg-dark-900 border border-white/10 rounded-lg p-2 text-white text-xs focus:border-primary outline-none"
                      >
                        <option value="fortinet_firewall">Fortinet FortiGate Firewall</option>
                        <option value="sentinel_one">SentinelOne Singularity API</option>
                        <option value="endpoint_central">ManageEngine Endpoint Central</option>
                        <option value="manual_playbook">كتيب الأوامر المباشر (CLI Manual Playbook)</option>
                      </select>
                    </div>
                  </div>

                  <button
                    onClick={handleCreateContainment}
                    disabled={containmentLoading}
                    className="px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white text-xs font-semibold flex items-center gap-2 transition-colors"
                  >
                    <Lock className="w-4 h-4" />
                    <span>توليد خطة العزل وإصدار الأوامر</span>
                  </button>
                </div>
              )}

              {/* Display Generated Playbook Commands */}
              {latestAction && latestAction.playbook_commands && (
                <div className="bg-dark-800/40 border border-white/10 rounded-xl p-4 space-y-3.5">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-primary" />
                      كتيب الأوامر الجاهزة للتنفيذ الميداني (Playbook Commands)
                    </h4>
                    <span className="text-[11px] px-2 py-0.5 rounded bg-dark-900 border border-white/10 text-slate-400 font-mono">
                      {latestAction.id}
                    </span>
                  </div>

                  {/* Windows Netsh */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>أمر Windows Firewall (PowerShell/CMD):</span>
                      <button
                        onClick={() => copyToClipboard(latestAction.playbook_commands.windows_netsh || '', 'win')}
                        className="hover:text-white flex items-center gap-1 text-primary"
                      >
                        {copiedKey === 'win' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>نسخ</span>
                      </button>
                    </div>
                    <pre className="p-2.5 rounded-lg bg-black/60 border border-white/5 font-mono text-[11px] text-slate-300 overflow-x-auto text-left ltr">
                      {latestAction.playbook_commands.windows_netsh}
                    </pre>
                  </div>

                  {/* Fortinet Firewall */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>أمر FortiGate Firewall CLI:</span>
                      <button
                        onClick={() => copyToClipboard(latestAction.playbook_commands.fortinet_cli || '', 'forti')}
                        className="hover:text-white flex items-center gap-1 text-primary"
                      >
                        {copiedKey === 'forti' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>نسخ</span>
                      </button>
                    </div>
                    <pre className="p-2.5 rounded-lg bg-black/60 border border-white/5 font-mono text-[11px] text-slate-300 overflow-x-auto text-left ltr">
                      {latestAction.playbook_commands.fortinet_cli}
                    </pre>
                  </div>

                  {/* Linux iptables */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>أمر Linux iptables:</span>
                      <button
                        onClick={() => copyToClipboard(latestAction.playbook_commands.linux_iptables || '', 'linux')}
                        className="hover:text-white flex items-center gap-1 text-primary"
                      >
                        {copiedKey === 'linux' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>نسخ</span>
                      </button>
                    </div>
                    <pre className="p-2.5 rounded-lg bg-black/60 border border-white/5 font-mono text-[11px] text-slate-300 overflow-x-auto text-left ltr">
                      {latestAction.playbook_commands.linux_iptables}
                    </pre>
                  </div>

                  {latestAction.status === 'pending_approval' && (
                    <div className="pt-2 flex items-center gap-2.5">
                      <button
                        onClick={() => handleConfirmContainment(latestAction.id)}
                        disabled={containmentLoading}
                        className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                      >
                        <Check className="w-4 h-4" />
                        <span>تأكيد واعتماد العزل في السجل</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
