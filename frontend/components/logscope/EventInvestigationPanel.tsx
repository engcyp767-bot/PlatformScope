'use client';

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Sparkles,
  Network,
  Terminal,
  Crosshair,
  HelpCircle,
  TrendingUp,
  TrendingDown,
  CheckCircle,
  ExternalLink,
  User,
  Target,
  Laptop,
  Globe,
  AlertTriangle,
  ShieldCheck,
} from 'lucide-react';
import { RiskBadge } from '../RiskBadge';

interface EventInvestigationPanelProps {
  record: any | null;
  enrichmentResults?: Record<string, any>;
  onClose: () => void;
  onSelectIncident?: (incidentId: string) => void;
  onFilterEntity?: (type: 'user' | 'ip' | 'device', value: string) => void;
}

export function EventInvestigationPanel({
  record,
  enrichmentResults,
  onClose,
  onSelectIncident,
  onFilterEntity,
}: EventInvestigationPanelProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'forensics' | 'mitre' | 'raw'>('overview');

  if (!record) return null;

  const riskExpl = record.risk_explanation || {};
  const hasExpl = Boolean(riskExpl.reasons_for_increase?.length || riskExpl.reasons_for_decrease?.length);

  const srcIntel = record.src_ip ? enrichmentResults?.[record.src_ip] : null;
  const dstIntel = record.destination ? enrichmentResults?.[record.destination] : null;

  const renderBadge = (intel: any) => {
    if (!intel) return null;
    if (intel.reason) {
      return (
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30">
          داخلي
        </span>
      );
    }
    const vt = intel.virustotal;
    const abuse = intel.abuseipdb;
    if (vt?.malicious > 0) {
      return (
        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
          VT: {vt.malicious} كشف
        </span>
      );
    }
    if (abuse?.score > 0) {
      return (
        <span
          className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
            abuse.score >= 50 ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
          } border`}
        >
          Abuse: {abuse.score}%
        </span>
      );
    }
    if (vt?.verdict === 'benign' || (abuse && abuse.score === 0)) {
      return (
        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
          سليم
        </span>
      );
    }
    return null;
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md p-2 sm:p-4 grid place-items-center animate-in fade-in duration-200">
      <div
        className="glass-panel w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col border-emerald-500/30 shadow-2xl rounded-2xl bg-dark-950"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-white/10 flex items-center justify-between gap-4 bg-gradient-to-r from-emerald-950/40 via-dark-900 to-dark-900">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-extrabold text-white text-base">
                  التحقيق الجنائي في الحدث الأمني
                </h3>
                {record.event_id && (
                  <span className="px-2 py-0.5 rounded bg-white/10 font-mono text-xs text-slate-300 font-bold">
                    Event ID: {record.event_id}
                  </span>
                )}
                <RiskBadge score={record.risk_score} level={record.severity} />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {record.report_family || 'SIEM Log'} · توقيت الحدث: {record.event_time || '—'}
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Sub Navigation */}
        <div className="border-b border-white/10 px-5 bg-dark-900/50 flex items-center gap-2 overflow-x-auto scrollbar-none">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all ${
              activeTab === 'overview'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            نظرة عامة والاتصال
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('forensics')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'forensics'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>تفسير الخطورة والموثوقية</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('mitre')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'mitre'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK ({record.mitre_techniques?.length || 0})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'raw'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>الحقول الأصلية (Raw Fields)</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-200 text-xs">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-5">
              {/* Linked Incident Banner if linked */}
              {record.incident_id && (
                <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-500/30 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span className="font-bold text-white">
                      هذا الحدث جزء من حادثة أمنية مترابطة:
                    </span>
                    <span className="font-mono text-rose-300 font-bold">{record.incident_id}</span>
                  </div>
                  {onSelectIncident && (
                    <button
                      type="button"
                      onClick={() => onSelectIncident(record.incident_id)}
                      className="flex items-center gap-1 text-xs font-bold text-rose-400 hover:text-rose-300"
                    >
                      <span>فتح تفاصيل الحادثة</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              )}

              {/* Forensic Description */}
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/20 p-4 space-y-2">
                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                  <Sparkles className="w-4 h-4" />
                  <span>الشرح والتوصيف الجنائي للحدث:</span>
                </div>
                <p className="text-sm leading-relaxed text-emerald-100 font-medium bg-black/25 p-3 rounded-xl border border-white/5" dir="auto">
                  {record.description_ar || record.description || 'حدث أمني مسجل'}
                </p>
                {record.description && record.description !== record.description_ar && (
                  <p className="text-[11px] text-slate-400 font-mono" dir="ltr">
                    Original: {record.description}
                  </p>
                )}
              </div>

              {/* Network and Identity Connection Details */}
              <div className="rounded-2xl border border-cyan-500/20 bg-cyan-950/15 p-5 space-y-4">
                <div className="flex items-center gap-2 border-b border-cyan-500/15 pb-2 text-cyan-400 font-bold">
                  <Network className="w-4 h-4" />
                  <span>بيانات الاتصال والشبكة والكيانات</span>
                </div>

                <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-3">
                  <div className="bg-black/30 border border-white/10 rounded-xl p-3">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">المصدر (Source IP & Port)</div>
                    <div className="flex items-center justify-between gap-1 flex-wrap">
                      <button
                        type="button"
                        onClick={() => record.src_ip && onFilterEntity?.('ip', record.src_ip)}
                        className="text-xs font-bold text-white font-mono hover:text-cyan-300 transition-colors"
                      >
                        {record.src_ip || '—'}
                        {record.src_port ? ` : ${record.src_port}` : ''}
                      </button>
                      {renderBadge(srcIntel)}
                    </div>
                  </div>

                  <div className="bg-black/30 border border-white/10 rounded-xl p-3">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">الوجهة (Destination)</div>
                    <div className="flex items-center justify-between gap-1 flex-wrap">
                      <button
                        type="button"
                        onClick={() => record.destination && onFilterEntity?.('ip', record.destination)}
                        className="text-xs font-bold text-amber-300 font-mono hover:text-amber-200 transition-colors"
                      >
                        {record.destination || '—'}
                        {record.dst_port ? ` : ${record.dst_port}` : ''}
                      </button>
                      {renderBadge(dstIntel)}
                    </div>
                  </div>

                  <div className="bg-black/30 border border-white/10 rounded-xl p-3">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">البروتوكول والخدمة</div>
                    <div className="text-xs font-bold text-cyan-300 font-mono">
                      {record.protocol || '—'}
                      {record.service_name ? ` · ${record.service_name}` : ''}
                    </div>
                  </div>

                  <div className="bg-black/30 border border-white/10 rounded-xl p-3">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">المستخدم / الحساب</div>
                    <button
                      type="button"
                      onClick={() => record.user_account && onFilterEntity?.('user', record.user_account)}
                      className="text-xs font-bold text-emerald-300 hover:underline"
                    >
                      {record.user_account || '—'}
                    </button>
                  </div>

                  <div className="bg-black/30 border border-white/10 rounded-xl p-3">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">الجهاز / النظام المصدري</div>
                    <button
                      type="button"
                      onClick={() => record.device && onFilterEntity?.('device', record.device)}
                      className="text-xs font-bold text-slate-200 font-mono hover:underline"
                    >
                      {record.device || '—'}
                    </button>
                  </div>

                  <div className="bg-black/30 border border-white/10 rounded-xl p-3">
                    <div className="text-[10px] text-slate-400 font-bold mb-1">الإجراء الأمني المتخذ</div>
                    <div className="text-xs font-bold text-rose-300">
                      {record.action_ar || record.action || '—'}
                    </div>
                  </div>
                </div>

                {/* Event Associated Threat Intelligence Cards */}
                {(srcIntel || dstIntel) && (
                  <div className="space-y-3 pt-3 border-t border-cyan-500/15">
                    <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs">
                      <Globe className="w-4 h-4" />
                      <span>استخبارات وسمعة العناوين المرتبطة بالحدث (Threat Intelligence)</span>
                    </div>

                    <div className="grid sm:grid-cols-2 gap-3">
                      {/* Source IP Intel */}
                      {record.src_ip && srcIntel && (
                        <div className="p-3 rounded-xl bg-black/40 border border-white/10 space-y-2">
                          <div className="flex items-center justify-between border-b border-white/5 pb-1.5">
                            <span className="font-mono text-cyan-300 font-bold text-xs" dir="ltr">
                              {record.src_ip} <span className="font-sans text-[10px] text-slate-400">(المصدر)</span>
                            </span>
                            {renderBadge(srcIntel)}
                          </div>
                          {srcIntel.reason ? (
                            <div className="text-[11px] text-slate-400 font-sans">
                              {srcIntel.reason} (نطاق داخلي مستثنى من الاستعلام الخارجي)
                            </div>
                          ) : (
                            <div className="space-y-1.5 text-[11px] text-slate-300">
                              {/* 1. VirusTotal */}
                              {srcIntel.virustotal ? (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                  <span className="text-slate-400 font-bold">VirusTotal:</span>
                                  <span className="font-mono font-bold text-white">
                                    {srcIntel.virustotal.malicious ?? 0} ضار / {srcIntel.virustotal.suspicious ?? 0} مشبوه
                                  </span>
                                </div>
                              ) : (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                  <span className="text-slate-500">VirusTotal:</span>
                                  <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                </div>
                              )}

                              {/* 2. Shodan InternetDB */}
                              {srcIntel.shodan ? (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                  <span className="text-slate-400 font-bold">Shodan:</span>
                                  {srcIntel.shodan.ports?.length > 0 ? (
                                    <span className="font-mono text-cyan-300 font-bold text-[10px]">
                                      {srcIntel.shodan.ports.slice(0, 5).join(', ')} (مفتوحة)
                                      {srcIntel.shodan.vulns?.length > 0 ? ` · ${srcIntel.shodan.vulns.length} ثغرة` : ''}
                                    </span>
                                  ) : (
                                    <span className="text-emerald-400 text-[10px] font-sans">
                                      سليم (لا توجد منافذ أو ثغرات مكشوفة)
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                  <span className="text-slate-500">Shodan:</span>
                                  <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                </div>
                              )}

                              {/* 3. AbuseIPDB */}
                              {srcIntel.abuseipdb ? (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                  <span className="text-slate-400 font-bold">AbuseIPDB:</span>
                                  <span className="font-mono font-bold text-white">
                                    {srcIntel.abuseipdb.score ?? 0}% ثقة ({srcIntel.abuseipdb.total_reports ?? 0} بلاغ)
                                  </span>
                                </div>
                              ) : (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                  <span className="text-slate-500">AbuseIPDB:</span>
                                  <span className="text-slate-400 text-[10px] font-sans">غير مفعّل في المنصة (يتطلب مفتاح API)</span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Destination IP Intel */}
                      {record.destination && dstIntel && (
                        <div className="p-3 rounded-xl bg-black/40 border border-white/10 space-y-2">
                          <div className="flex items-center justify-between border-b border-white/5 pb-1.5">
                            <span className="font-mono text-amber-300 font-bold text-xs" dir="ltr">
                              {record.destination} <span className="font-sans text-[10px] text-slate-400">(الوجهة)</span>
                            </span>
                            {renderBadge(dstIntel)}
                          </div>
                          {dstIntel.reason ? (
                            <div className="text-[11px] text-slate-400 font-sans">
                              {dstIntel.reason} (نطاق داخلي مستثنى من الاستعلام الخارجي)
                            </div>
                          ) : (
                            <div className="space-y-1.5 text-[11px] text-slate-300">
                              {/* 1. VirusTotal */}
                              {dstIntel.virustotal ? (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                  <span className="text-slate-400 font-bold">VirusTotal:</span>
                                  <span className="font-mono font-bold text-white">
                                    {dstIntel.virustotal.malicious ?? 0} ضار / {dstIntel.virustotal.suspicious ?? 0} مشبوه
                                  </span>
                                </div>
                              ) : (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                  <span className="text-slate-500">VirusTotal:</span>
                                  <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                </div>
                              )}

                              {/* 2. Shodan InternetDB */}
                              {dstIntel.shodan ? (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                  <span className="text-slate-400 font-bold">Shodan:</span>
                                  {dstIntel.shodan.ports?.length > 0 ? (
                                    <span className="font-mono text-amber-300 font-bold text-[10px]">
                                      {dstIntel.shodan.ports.slice(0, 5).join(', ')} (مفتوحة)
                                      {dstIntel.shodan.vulns?.length > 0 ? ` · ${dstIntel.shodan.vulns.length} ثغرة` : ''}
                                    </span>
                                  ) : (
                                    <span className="text-emerald-400 text-[10px] font-sans">
                                      سليم (لا توجد منافذ أو ثغرات مكشوفة)
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                  <span className="text-slate-500">Shodan:</span>
                                  <span className="text-slate-400 text-[10px] font-sans">غير متاح</span>
                                </div>
                              )}

                              {/* 3. AbuseIPDB */}
                              {dstIntel.abuseipdb ? (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded">
                                  <span className="text-slate-400 font-bold">AbuseIPDB:</span>
                                  <span className="font-mono font-bold text-white">
                                    {dstIntel.abuseipdb.score ?? 0}% ثقة ({dstIntel.abuseipdb.total_reports ?? 0} بلاغ)
                                  </span>
                                </div>
                              ) : (
                                <div className="flex justify-between items-center bg-white/5 p-1.5 rounded opacity-60">
                                  <span className="text-slate-500">AbuseIPDB:</span>
                                  <span className="text-slate-400 text-[10px] font-sans">غير مفعّل في المنصة (يتطلب مفتاح API)</span>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: FORENSICS & RISK EXPLAINABILITY */}
          {activeTab === 'forensics' && (
            <div className="space-y-5">
              <div className="grid sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">الدرجة الأساسية (Base Score)</div>
                  <div className="text-base font-bold text-slate-200 font-mono">
                    {riskExpl.base_score ?? record.base_risk_score ?? record.risk_score} / 100
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">نسبة الموثوقية (Confidence Score)</div>
                  <div className="text-base font-bold text-cyan-400 font-mono">
                    {record.confidence_score ?? 50}%
                  </div>
                </div>
              </div>

              {/* Reasons for Increase */}
              <div className="rounded-2xl border border-rose-500/20 bg-rose-950/15 p-4 space-y-2.5">
                <div className="flex items-center gap-2 text-rose-400 font-bold">
                  <TrendingUp className="w-4 h-4" />
                  <span>عوامل رفع درجة الخطورة:</span>
                </div>
                {riskExpl.reasons_for_increase?.length ? (
                  <ul className="space-y-1.5">
                    {riskExpl.reasons_for_increase.map((r: string, idx: number) => (
                      <li key={idx} className="p-2.5 rounded-lg bg-black/30 border border-rose-500/20 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-slate-400">لا توجد عوامل تصعيد إضافية مسجلة للحدث.</p>
                )}
              </div>

              {/* Reasons for Decrease */}
              {riskExpl.reasons_for_decrease?.length > 0 && (
                <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/15 p-4 space-y-2.5">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold">
                    <TrendingDown className="w-4 h-4" />
                    <span>عوامل خفض الخطورة (إحباط الهجوم):</span>
                  </div>
                  <ul className="space-y-1.5">
                    {riskExpl.reasons_for_decrease.map((r: string, idx: number) => (
                      <li key={idx} className="p-2.5 rounded-lg bg-black/30 border border-emerald-500/20 flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                        <span>{r}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Confidence Factors */}
              {riskExpl.confidence_factors?.length > 0 && (
                <div className="rounded-2xl border border-cyan-500/20 bg-cyan-950/15 p-4 space-y-2.5">
                  <div className="flex items-center gap-2 text-cyan-400 font-bold">
                    <Sparkles className="w-4 h-4" />
                    <span>مبررات موثوقية الكشف الجنائي:</span>
                  </div>
                  <ul className="space-y-1.5">
                    {riskExpl.confidence_factors.map((f: string, idx: number) => (
                      <li key={idx} className="p-2.5 rounded-lg bg-black/30 border border-cyan-500/20 flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-cyan-400 mt-0.5 shrink-0" />
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: MITRE ATT&CK */}
          {activeTab === 'mitre' && (
            <div className="space-y-4">
              <div className="text-slate-400">التكتيكات والتقنيات المطابقة لهذا الحدث:</div>
              <div className="space-y-2">
                {record.mitre_techniques?.map((tech: string, idx: number) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-black/30 border border-white/10 flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono font-bold">
                        {tech}
                      </span>
                      <span className="font-bold text-white">{record.threat_family || 'تهديد سيبراني'}</span>
                    </div>
                    <span className="text-[11px] text-slate-400 font-medium">
                      {record.mitre_tactics?.[idx] || record.mitre_tactics?.[0] || 'Tactic'}
                    </span>
                  </div>
                ))}

                {!record.mitre_techniques?.length && (
                  <div className="p-8 text-center text-slate-400 text-xs">
                    لم تسجل تقنيات MITRE محددة لهذا الحدث.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: RAW FIELDS */}
          {activeTab === 'raw' && (
            <div className="space-y-3">
              <div className="grid sm:grid-cols-2 gap-2.5">
                {Object.entries(record.raw_fields || {}).map(([key, value]) => (
                  <div key={key} className="rounded-xl border border-white/10 bg-black/30 p-3 min-w-0">
                    <div className="text-[11px] font-bold text-emerald-400 mb-1 break-words">{key}</div>
                    <div className="text-xs text-slate-200 whitespace-pre-wrap break-words font-mono" dir="auto">
                      {String(value)}
                    </div>
                  </div>
                ))}
                {!Object.keys(record.raw_fields || {}).length && (
                  <p className="text-xs text-slate-400">لا توجد حقول أصلية مفصلة مسجلة.</p>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 bg-dark-900 flex items-center justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 text-xs font-bold transition-colors"
          >
            إغلاق
          </button>
        </div>
      </div>
    </div>
  );
}
