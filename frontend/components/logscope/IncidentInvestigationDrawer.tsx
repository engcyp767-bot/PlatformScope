'use client';

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Clock,
  Sparkles,
  TrendingUp,
  TrendingDown,
  Crosshair,
  ListFilter,
  CheckCircle,
  FileCode2,
  HelpCircle,
  User,
  Target,
  Laptop,
  Terminal,
  ArrowLeft,
  ChevronRight,
} from 'lucide-react';
import { IncidentData, translateConclusion } from './IncidentCard';
import { RiskBadge } from '../RiskBadge';

interface IncidentInvestigationDrawerProps {
  incident: IncidentData | null;
  onClose: () => void;
  onFilterByIncidentEvents: (incidentId: string) => void;
  onFilterEntity?: (type: 'user' | 'ip' | 'device', value: string) => void;
  onSelectEventRecord?: (record: any) => void;
}

export function IncidentInvestigationDrawer({
  incident,
  onClose,
  onFilterByIncidentEvents,
  onFilterEntity,
  onSelectEventRecord,
}: IncidentInvestigationDrawerProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'explainability' | 'mitre' | 'recommendations' | 'evidence'>('overview');

  if (!incident) return null;

  const conclusion = translateConclusion(incident.conclusion_level);
  const timeline = incident.timeline_events || [];

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md p-2 sm:p-4 lg:p-6 grid place-items-center animate-in fade-in duration-200">
      <div
        className="glass-panel w-full max-w-6xl max-h-[92vh] overflow-hidden flex flex-col border-emerald-500/30 shadow-2xl rounded-2xl bg-dark-950"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header */}
        <div className="p-5 border-b border-white/10 flex items-center justify-between gap-4 bg-gradient-to-r from-emerald-950/40 via-dark-900 to-dark-900">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-rose-500/10 border border-rose-500/25 text-rose-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-bold">
                  {incident.incident_id}
                </span>
                <span className={`px-2 py-0.5 rounded text-xs font-bold border ${conclusion.color}`}>
                  {conclusion.label}
                </span>
                <RiskBadge score={incident.risk_score} level={incident.severity} />
              </div>
              <h3 className="font-extrabold text-white text-base mt-1.5 leading-snug" dir="auto">
                {incident.title_ar}
              </h3>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                onFilterByIncidentEvents(incident.incident_id);
                onClose();
              }}
              className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-bold transition-all"
            >
              <ListFilter className="w-3.5 h-3.5" />
              <span>تصفية أحداث الحادثة</span>
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-colors"
              title="إغلاق نافذة التحقيق"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Sub Navigation Bar */}
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
            نظرة عامة وسياق التحقيق
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('timeline')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'timeline'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>المخطط الزمني ({timeline.length || incident.event_count})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('explainability')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'explainability'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>لماذا هذه الخطورة؟ (Risk Explainability)</span>
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
            <span>تكتيكات وتقنيات MITRE ({incident.mitre_techniques?.length || 0})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('recommendations')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'recommendations'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <CheckCircle className="w-3.5 h-3.5" />
            <span>إجراءات وتوصيات SOC</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('evidence')}
            className={`px-3 py-2.5 text-xs font-bold border-b-2 transition-all flex items-center gap-1.5 ${
              activeTab === 'evidence'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>الأدلة المادية (Evidence)</span>
          </button>
        </div>

        {/* Drawer Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-slate-200">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Executive Summary Card */}
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/20 p-5 space-y-3">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                  <Sparkles className="w-4 h-4" />
                  <span>التوصيف الجنائي للحادثة</span>
                </div>
                <p className="text-sm leading-relaxed text-emerald-100/90 font-medium" dir="auto">
                  {incident.description_ar}
                </p>
              </div>

              {/* Grid Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">مستوى الخطورة المحسوب</div>
                  <div className="text-lg font-black text-rose-400 font-mono">{incident.risk_score} / 100</div>
                  <div className="text-[10px] text-slate-500 font-medium">{incident.severity}</div>
                </div>

                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">نسبة الثقة والموثوقية</div>
                  <div className="text-lg font-black text-cyan-400 font-mono">{incident.confidence_score}%</div>
                  <div className="text-[10px] text-slate-500 font-medium">مستقلة عن درجة الخطورة</div>
                </div>

                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">إجمالي الأحداث المساهمة</div>
                  <div className="text-lg font-black text-emerald-400 font-mono">{incident.event_count}</div>
                  <div className="text-[10px] text-slate-500 font-medium">أحداث مرتبطة زمنياً</div>
                </div>

                <div className="p-3.5 rounded-xl bg-black/30 border border-white/10 space-y-1">
                  <div className="text-[10px] text-slate-400 font-bold">النتيجة والاستنتاج الجنائي</div>
                  <div className="text-sm font-bold text-white pt-1">{conclusion.label}</div>
                  <div className="text-[10px] text-slate-500 font-mono">{incident.conclusion_level}</div>
                </div>
              </div>

              {/* Entities & Artifacts */}
              <div className="rounded-2xl border border-white/10 bg-black/20 p-5 space-y-4">
                <h4 className="text-xs font-extrabold text-white tracking-wide uppercase">
                  الأصول والكيانات المرتبطة بالحادثة
                </h4>

                <div className="grid sm:grid-cols-3 gap-4">
                  {/* Users */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-emerald-400" />
                      <span>الحسابات المستهدفة ({incident.usernames?.length || 0})</span>
                    </div>
                    <div className="space-y-1">
                      {incident.usernames?.map((u, i) => (
                        <button
                          key={i}
                          type="button"
                          onClick={() => onFilterEntity?.('user', u)}
                          className="w-full text-right p-2 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 text-xs font-bold text-emerald-300 transition-colors"
                        >
                          {u}
                        </button>
                      ))}
                      {!incident.usernames?.length && <div className="text-xs text-slate-500">—</div>}
                    </div>
                  </div>

                  {/* Attacking IPs */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                      <Target className="w-3.5 h-3.5 text-cyan-400" />
                      <span>عناوين المصدر / الهجوم ({incident.source_ips?.length || 0})</span>
                    </div>
                    <div className="space-y-1">
                      {incident.source_ips?.map((ip, i) => (
                        <button
                          key={i}
                          type="button"
                          onClick={() => onFilterEntity?.('ip', ip)}
                          className="w-full text-right p-2 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 text-xs font-mono font-bold text-cyan-300 transition-colors"
                        >
                          {ip}
                        </button>
                      ))}
                      {!incident.source_ips?.length && <div className="text-xs text-slate-500">—</div>}
                    </div>
                  </div>

                  {/* Devices */}
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-slate-400 flex items-center gap-1.5">
                      <Laptop className="w-3.5 h-3.5 text-purple-400" />
                      <span>الأجهزة والخوادم ({incident.devices?.length || 0})</span>
                    </div>
                    <div className="space-y-1">
                      {incident.devices?.map((dev, i) => (
                        <button
                          key={i}
                          type="button"
                          onClick={() => onFilterEntity?.('device', dev)}
                          className="w-full text-right p-2 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 text-xs font-mono font-bold text-purple-300 transition-colors"
                        >
                          {dev}
                        </button>
                      ))}
                      {!incident.devices?.length && <div className="text-xs text-slate-500">—</div>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: INTERACTIVE TIMELINE */}
          {activeTab === 'timeline' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>التسلسل الزمني للتحركات المكونة للحادثة بالترتيب الزمني:</span>
                <span className="font-mono">{timeline.length} حدث مسجل في السلسلة</span>
              </div>

              <div className="relative border-r border-emerald-500/30 mr-4 pr-6 space-y-6">
                {timeline.map((item, idx) => {
                  const isLast = idx === timeline.length - 1;
                  const isSuccess = item.status === 'SUCCESS' || item.action === 'Privilege Activity';

                  return (
                    <div key={idx} className="relative group">
                      {/* Node Indicator Dot */}
                      <div
                        className={`absolute -right-[31px] top-1.5 w-4 h-4 rounded-full border-2 ${
                          isSuccess
                            ? 'bg-rose-500 border-rose-300 shadow-[0_0_10px_rgba(244,63,94,0.8)]'
                            : 'bg-emerald-500 border-dark-950'
                        }`}
                      />

                      <div
                        onClick={() => onSelectEventRecord?.(item)}
                        className={`p-4 rounded-xl border transition-all cursor-pointer ${
                          isSuccess
                            ? 'bg-rose-950/20 border-rose-500/30 hover:border-rose-500/60'
                            : 'bg-dark-900/60 border-white/10 hover:border-emerald-500/40'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3 flex-wrap">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-white/5 border border-white/10 text-emerald-400">
                              {item.event_id ? `ID: ${item.event_id}` : `خطوة #${idx + 1}`}
                            </span>
                            {item.status && (
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  isSuccess
                                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                    : 'bg-slate-500/20 text-slate-300'
                                }`}
                              >
                                {item.status}
                              </span>
                            )}
                          </div>
                          <span className="text-xs font-mono text-slate-400">{item.time || '—'}</span>
                        </div>

                        <div className="grid sm:grid-cols-2 gap-2 mt-3 text-xs">
                          {item.user && (
                            <div>
                              <span className="text-slate-500">المستخدم:</span>{' '}
                              <span className="font-bold text-emerald-300">{item.user}</span>
                            </div>
                          )}
                          {item.src && (
                            <div>
                              <span className="text-slate-500">عنوان المصدر:</span>{' '}
                              <span className="font-mono font-bold text-cyan-300">{item.src}</span>
                            </div>
                          )}
                          {item.action && (
                            <div className="sm:col-span-2">
                              <span className="text-slate-500">نوع الإجراء:</span>{' '}
                              <span className="font-bold text-rose-300">{item.action}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}

                {timeline.length === 0 && (
                  <div className="p-8 text-center text-slate-400 text-xs">
                    لم يتم تسجيل تفاصيل المخطط الزمني بصورة مسبقة لهذا الحدث.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: RISK EXPLAINABILITY */}
          {activeTab === 'explainability' && (
            <div className="space-y-6">
              <div className="p-4 rounded-xl bg-dark-900/60 border border-white/10 flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/25 text-emerald-400">
                  <HelpCircle className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-white">
                    تفسير درجة الخطورة والموثوقية (Explainable Risk & Decoupled Confidence)
                  </h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    يوضح النظام العوامل الدقيقة المحسوبة التي أدت لرفع درجة الخطورة أو خفضها واستقلالية الثقة
                  </p>
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-5">
                {/* Factors Increasing Risk */}
                <div className="rounded-2xl border border-rose-500/20 bg-rose-950/15 p-5 space-y-3">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-xs">
                    <TrendingUp className="w-4 h-4" />
                    <span>عوامل رفعت درجة الخطورة (Risk Increase Factors):</span>
                  </div>
                  <ul className="space-y-2 text-xs">
                    <li className="flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-rose-500/20">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                      <span>سلسلة هجمات تخمين كلمات مرور مترابطة زمنياً (Brute-Force Attack Chain).</span>
                    </li>
                    {incident.conclusion_level === 'confirmed' || incident.conclusion_level === 'likely_successful' ? (
                      <li className="flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-rose-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                        <span>نجاح تسجيل دخول الحساب بعد محاولات فاشلة متتالية (Account Takeover Compromise).</span>
                      </li>
                    ) : null}
                    {incident.risk_score >= 85 && (
                      <li className="flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-rose-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                        <span>تأثير الحساب المستهدف وامتيازات الإدارة في النطاق (High Privilege Asset).</span>
                      </li>
                    )}
                  </ul>
                </div>

                {/* Factors for Confidence */}
                <div className="rounded-2xl border border-cyan-500/20 bg-cyan-950/15 p-5 space-y-3">
                  <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs">
                    <Sparkles className="w-4 h-4" />
                    <span>عوامل موثوقية الكشف الجنائي (Decoupled Confidence):</span>
                  </div>
                  <ul className="space-y-2 text-xs">
                    <li className="flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-cyan-500/20">
                      <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <span>اكتمال حقول المصدر والوجهة والحساب المصاب في السجلات.</span>
                    </li>
                    <li className="flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-cyan-500/20">
                      <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <span>توثيق تسلسل أدلة متعدد الخطوات مدعوم بسجلات تدقيق متتالية.</span>
                    </li>
                    <li className="flex items-start gap-2 bg-black/30 p-2.5 rounded-xl border border-cyan-500/20">
                      <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <span>تطابق بصمات قواعد كشف SIEM المعتمدة بنسبة عالية.</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: MITRE ATT&CK */}
          {activeTab === 'mitre' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>التقنيات والتكتيكات الموثقة للحادثة طبقاً لإطار MITRE ATT&CK:</span>
              </div>

              <div className="grid gap-3">
                {incident.mitre_techniques?.map((tech, idx) => (
                  <div key={idx} className="p-4 rounded-xl border border-white/10 bg-dark-900/60 space-y-2">
                    <div className="flex items-center justify-between gap-3 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className="px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs font-bold">
                          {tech}
                        </span>
                        <span className="text-sm font-bold text-white">
                          {tech.includes('-') ? tech.split('-')[1].trim() : tech}
                        </span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-white/5 text-[11px] text-slate-400 font-medium">
                        تكتيك: {incident.mitre_tactics?.[idx] || incident.mitre_tactics?.[0] || 'Credential Access'}
                      </span>
                    </div>
                  </div>
                ))}

                {!incident.mitre_techniques?.length && (
                  <div className="p-8 text-center text-slate-400 text-xs">
                    لم يتم تسجيل تقنيات MITRE محددة لهذه الحادثة.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 5: SOC RECOMMENDATIONS */}
          {activeTab === 'recommendations' && (
            <div className="space-y-4">
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/20 p-5 space-y-3">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                  <CheckCircle className="w-4 h-4" />
                  <span>توصيات الاستجابة للحوادث (Incident Response Playbook)</span>
                </div>
                <p className="text-xs text-slate-300">
                  خطوات عملية موصى بها لفريق مركز العمليات الأمنية (SOC) لاحتواء الحادثة فوراً:
                </p>

                <ul className="space-y-2 pt-2">
                  {incident.recommendations && incident.recommendations.length > 0 ? (
                    incident.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2.5 p-3 rounded-xl bg-black/30 border border-white/5 text-xs text-white">
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <span className="leading-relaxed">{rec}</span>
                      </li>
                    ))
                  ) : (
                    <>
                      <li className="flex items-start gap-2.5 p-3 rounded-xl bg-black/30 border border-white/5 text-xs text-white">
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <span>إعادة تعيين كلمة المرور فوراً وتفعيل المصادقة متعددة العوامل (MFA) للحسابات المستهدفة.</span>
                      </li>
                      <li className="flex items-start gap-2.5 p-3 rounded-xl bg-black/30 border border-white/5 text-xs text-white">
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <span>عزل عناوين IP المهاجمة في جدار الحماية الخارجي وWAF.</span>
                      </li>
                      <li className="flex items-start gap-2.5 p-3 rounded-xl bg-black/30 border border-white/5 text-xs text-white">
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <span>مراجعة سجلات الأجهزة الطرفية للتأكد من عدم تثبيت برمجيات أو خدمات غير مصرح بها.</span>
                      </li>
                    </>
                  )}
                </ul>
              </div>
            </div>
          )}

          {/* TAB 6: RAW EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="rounded-2xl border border-white/10 bg-black/30 p-5 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between text-slate-400">
                  <span>الأدلة الجنائية الخام المقيدة:</span>
                  <span>Incident Schema 2026</span>
                </div>
                <pre className="p-4 rounded-xl bg-black/60 border border-white/10 overflow-x-auto text-emerald-300 leading-relaxed max-h-96">
                  {JSON.stringify(incident, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-white/10 bg-dark-900 flex items-center justify-between">
          <button
            type="button"
            onClick={() => {
              onFilterByIncidentEvents(incident.incident_id);
              onClose();
            }}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-dark-950 font-bold text-xs transition-all shadow-lg hover:shadow-emerald-500/20"
          >
            <ListFilter className="w-4 h-4" />
            <span>عرض وتصفية جميع أحداث هذه الحادثة في الجدول</span>
          </button>

          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-slate-200 text-xs font-bold transition-colors"
          >
            إغلاق نافذة التحقيق
          </button>
        </div>
      </div>
    </div>
  );
}
