'use client';

import React, { useState, useEffect } from 'react';
import {
  Sparkles, Bot, Zap, ShieldAlert, CheckCircle2, AlertTriangle,
  Copy, Check, PlusCircle, RefreshCw, Layers, ShieldCheck, ArrowLeft,
  ChevronRight, ArrowUpRight, HelpCircle
} from 'lucide-react';
import { Incident, CopilotInvestigationResult, CopilotStatus, User as UserType } from '../../lib/types';
import { queryCopilot, getCopilotStatus, applyCopilotNote } from '../../lib/api';

interface CopilotTabProps {
  incident: Incident;
  currentUser: UserType | null;
  onNoteAdded?: () => void;
}

export function CopilotTab({ incident, currentUser, onNoteAdded }: CopilotTabProps) {
  const [status, setStatus] = useState<CopilotStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [investigating, setInvestigating] = useState(false);
  const [activeIntent, setActiveIntent] = useState<'explain_severity' | 'attack_sequence' | 'recommended_actions' | 'custom_query'>('explain_severity');
  const [customQuery, setCustomQuery] = useState('');
  const [result, setResult] = useState<CopilotInvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [copying, setCopying] = useState(false);
  const [savingNote, setSavingNote] = useState(false);
  const [noteSaved, setNoteSaved] = useState(false);

  // Check if user has permission
  const canQuery = currentUser?.permissions?.includes('copilot.query') || currentUser?.permissions?.includes('incidents.manage');
  const canAddNotes = currentUser?.permissions?.includes('incidents.manage');

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    setLoadingStatus(true);
    try {
      const s = await getCopilotStatus();
      setStatus(s);
    } catch (err) {
      console.error('Failed to load copilot status:', err);
    } finally {
      setLoadingStatus(false);
    }
  };

  const handleRunInvestigation = async (intent: 'explain_severity' | 'attack_sequence' | 'recommended_actions' | 'custom_query', queryText?: string) => {
    if (!canQuery) {
      alert('ليس لديك صلاحية استخدام المساعد الأمني الذكي (copilot.query).');
      return;
    }
    setInvestigating(true);
    setActiveIntent(intent);
    setError(null);
    setNoteSaved(false);

    try {
      const res = await queryCopilot(incident.id, intent, queryText || (intent === 'custom_query' ? customQuery : undefined));
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'فشل تشغيل تحقيق المساعد الذكي');
    } finally {
      setInvestigating(false);
    }
  };

  const handleCopyAnalysis = () => {
    if (!result) return;
    const text = `${result.investigation_title_ar}\n\n${result.summary_ar}\n\n${result.detailed_analysis_ar}\n\n---\n${result.disclaimer_ar}`;
    navigator.clipboard.writeText(text);
    setCopying(true);
    setTimeout(() => setCopying(false), 2000);
  };

  const handleSaveToIncidentNotes = async () => {
    if (!result || !canAddNotes) return;
    setSavingNote(true);
    try {
      const noteContent = `${result.investigation_title_ar}\n\n${result.summary_ar}\n\nالتوصيات المقترحة:\n` +
        result.recommended_actions.map(a => `- [${a.phase}] ${a.action_ar}`).join('\n');
      await applyCopilotNote(incident.id, noteContent);
      setNoteSaved(true);
      onNoteAdded?.();
      setTimeout(() => setNoteSaved(false), 3000);
    } catch (err: any) {
      alert(err.message || 'فشل حفظ التوصيات في ملاحظات الحادث');
    } finally {
      setSavingNote(false);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner: Engine Status & Readiness */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-purple-950/40 via-dark-900 to-primary-950/20 border border-purple-500/20 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Sparkles className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
                <span>المساعد الأمني الذكي (AI Security Copilot)</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 font-mono">
                  DFIR Copilot
                </span>
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              تحقيق جنائي فوري باللغة الطبيعية مقيد بالأدلة الرقمية وتكتيكات MITRE ATT&CK.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-dark-950/80 border border-white/10 text-xs font-mono">
            <div className={`w-2 h-2 rounded-full ${status?.ollama_available ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'}`} />
            <span className="text-slate-300 text-[11px]">
              {status?.active_model || (loadingStatus ? 'جاري الفحص...' : 'Deterministic Fallback')}
            </span>
          </div>

          <button
            onClick={loadStatus}
            disabled={loadingStatus}
            title="تحديث حالة محرك الذكاء الاصطناعي"
            className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingStatus ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Quick Prompt Cards (Single Click) */}
      <div>
        <label className="text-xs font-bold text-slate-300 block mb-2.5 flex items-center gap-1.5">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span>استفسارات التحقيق السريعة بنقرة واحدة (Quick Investigation Prompts):</span>
        </label>
        
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button
            onClick={() => handleRunInvestigation('explain_severity')}
            disabled={investigating}
            className={`p-3.5 rounded-xl border text-right transition-all flex flex-col justify-between gap-2 group ${
              activeIntent === 'explain_severity' && result
                ? 'bg-red-500/15 border-red-500/50 shadow-md shadow-red-500/10'
                : 'bg-dark-900/60 border-white/10 hover:border-red-500/40 hover:bg-red-500/5'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white group-hover:text-red-300 transition-colors">
                لماذا اعتبر هذا الحادث خطيراً؟
              </span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              تفكيك درجات الخطورة وعوامل التأثير وحساسية الأصول المتضررة.
            </p>
          </button>

          <button
            onClick={() => handleRunInvestigation('attack_sequence')}
            disabled={investigating}
            className={`p-3.5 rounded-xl border text-right transition-all flex flex-col justify-between gap-2 group ${
              activeIntent === 'attack_sequence' && result
                ? 'bg-blue-500/15 border-blue-500/50 shadow-md shadow-blue-500/10'
                : 'bg-dark-900/60 border-white/10 hover:border-blue-500/40 hover:bg-blue-500/5'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white group-hover:text-blue-300 transition-colors">
                ما هو تسلسل مراحل الهجوم؟
              </span>
              <Layers className="w-4 h-4 text-blue-400" />
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              إعادة بناء سلسلة القتل الجنائية (Kill Chain) ومطابقة تقنيات MITRE.
            </p>
          </button>

          <button
            onClick={() => handleRunInvestigation('recommended_actions')}
            disabled={investigating}
            className={`p-3.5 rounded-xl border text-right transition-all flex flex-col justify-between gap-2 group ${
              activeIntent === 'recommended_actions' && result
                ? 'bg-emerald-500/15 border-emerald-500/50 shadow-md shadow-emerald-500/10'
                : 'bg-dark-900/60 border-white/10 hover:border-emerald-500/40 hover:bg-emerald-500/5'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white group-hover:text-emerald-300 transition-colors">
                ما هي الإجراءات المقترحة؟
              </span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <p className="text-[11px] text-slate-400 line-clamp-2">
              خطة الاستجابة التكتيكية: العزل الفوري، الاستئصال، وكتيب NIST.
            </p>
          </button>
        </div>
      </div>

      {/* Freeform Query Box */}
      <div className="p-3.5 rounded-xl bg-dark-900/40 border border-white/10 space-y-2">
        <label className="text-xs font-bold text-slate-300 flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <Bot className="w-3.5 h-3.5 text-primary" />
            <span>أو اطرح سؤالاً حراً بلغة طبيعية على المساعد:</span>
          </span>
          <span className="text-[11px] text-slate-400">عربي / English</span>
        </label>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (customQuery.trim()) {
              handleRunInvestigation('custom_query', customQuery.trim());
            }
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={customQuery}
            onChange={(e) => setCustomQuery(e.target.value)}
            placeholder="مثال: هل تم رصد أي اتصال بخوادم C2 خارجية أو محاولات تنقل أفقي؟"
            className="flex-1 bg-dark-950 border border-white/15 rounded-lg px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-primary"
          />
          <button
            type="submit"
            disabled={investigating || !customQuery.trim()}
            className="px-4 py-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 text-dark-950 font-bold text-xs flex items-center gap-1.5 transition-colors"
          >
            {investigating ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5" />
            )}
            <span>تحقيق</span>
          </button>
        </form>
      </div>

      {/* Loading indicator */}
      {investigating && (
        <div className="p-8 rounded-xl bg-dark-900/80 border border-purple-500/30 flex flex-col items-center justify-center gap-3 text-center animate-pulse">
          <div className="w-9 h-9 rounded-full border-2 border-primary border-t-transparent animate-spin" />
          <div className="space-y-1">
            <p className="text-sm font-bold text-white">المساعد الأمني الذكي يقوم بتحليل الحادث...</p>
            <p className="text-xs text-slate-400">فحص الأدلة الجنائية، مطابقة مؤشرات التهديد واستخراج سياق الهجوم.</p>
          </div>
        </div>
      )}

      {/* Error display */}
      {error && !investigating && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0 text-red-400" />
          <p>{error}</p>
        </div>
      )}

      {/* Investigation Results Card */}
      {result && !investigating && (
        <div className="rounded-xl bg-dark-900 border border-purple-500/30 overflow-hidden shadow-2xl space-y-0">
          
          {/* Result Header */}
          <div className="p-4 border-b border-white/10 bg-gradient-to-r from-purple-950/40 via-dark-900 to-dark-900 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  {result.intent}
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  نسبة الموثوقية: {result.confidence}%
                </span>
              </div>
              <h4 className="text-base font-extrabold text-white">
                {result.investigation_title_ar}
              </h4>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyAnalysis}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-xs text-slate-300 hover:text-white transition-colors"
                title="نسخ التحليل كاملاً إلى الحافظة"
              >
                {copying ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copying ? 'تم النسخ' : 'نسخ'}</span>
              </button>

              {canAddNotes && (
                <button
                  onClick={handleSaveToIncidentNotes}
                  disabled={savingNote || noteSaved}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-bold transition-all ${
                    noteSaved
                      ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                      : 'bg-primary/20 hover:bg-primary/30 border-primary/40 text-primary'
                  }`}
                  title="إدراج هذا التحليل في ملاحظات الحادث الرسمية"
                >
                  {noteSaved ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>تم الحفظ في الملاحظات</span>
                    </>
                  ) : (
                    <>
                      <PlusCircle className="w-3.5 h-3.5" />
                      <span>{savingNote ? 'جاري الحفظ...' : 'إدراج في ملاحظات الحادث'}</span>
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          <div className="p-6 space-y-6 text-slate-200">
            
            {/* Executive Summary */}
            <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/30 text-xs leading-relaxed text-purple-100 space-y-1">
              <div className="text-[11px] font-bold uppercase tracking-wider text-purple-300">
                الملخص التحليلي التنفيذي:
              </div>
              <p>{result.summary_ar}</p>
            </div>

            {/* Attack Stages (if present) */}
            {result.attack_stages && result.attack_stages.length > 0 && (
              <div className="space-y-3">
                <h5 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-blue-400" />
                  <span>مراحل تسلسل الهجوم (Kill Chain Progression):</span>
                </h5>

                <div className="space-y-2">
                  {result.attack_stages.map((stage) => (
                    <div
                      key={stage.step_number}
                      className="p-3 rounded-lg bg-dark-950 border border-white/10 flex items-start gap-3"
                    >
                      <div className="w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/40 flex items-center justify-center font-bold text-xs shrink-0">
                        {stage.step_number}
                      </div>
                      <div className="space-y-1 flex-1 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white">{stage.stage_name}</span>
                          <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-white/5 text-blue-300 border border-white/10">
                            {stage.tactic} - {stage.technique}
                          </span>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{stage.description_ar}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed Analysis */}
            <div className="space-y-2">
              <h5 className="text-xs font-bold text-slate-300">التحليل الجنائي المفصل:</h5>
              <div className="p-4 rounded-xl bg-dark-950 border border-white/10 text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-line">
                {result.detailed_analysis_ar}
              </div>
            </div>

            {/* Grounded Facts List */}
            {result.grounded_facts && result.grounded_facts.length > 0 && (
              <div className="space-y-2">
                <h5 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>الحقائق المثبتة في الحادث (Grounded Evidence):</span>
                </h5>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {result.grounded_facts.map((fact, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-dark-950 border border-white/5 text-xs text-slate-300 flex items-start gap-2"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                      <span>{fact}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Actions */}
            {result.recommended_actions && result.recommended_actions.length > 0 && (
              <div className="space-y-3">
                <h5 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-primary" />
                  <span>خطة الاستجابة والإجراءات المقترحة:</span>
                </h5>
                
                <div className="space-y-2">
                  {result.recommended_actions.map((act, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-dark-950 border border-white/10 flex items-start justify-between gap-3 text-xs"
                    >
                      <div className="flex items-start gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          act.priority === 'immediate' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          act.priority === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                        }`}>
                          {act.priority === 'immediate' ? 'فوري' : act.priority === 'high' ? 'أولوية قصوى' : 'مجدول'}
                        </span>
                        <span className="text-slate-200">{act.action_ar}</span>
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono shrink-0 uppercase bg-white/5 px-2 py-0.5 rounded">
                        {act.phase}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Engine & Attribution Footer */}
            <div className="pt-4 border-t border-white/10 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-[11px] text-slate-400">
              <div>
                المحرك المستخدم: <span className="text-slate-200 font-mono font-bold">{result.engine_used}</span>
              </div>
              <div className="text-slate-500">
                تاريخ التوليد: {new Date(result.generated_at).toLocaleString('ar-EG')}
              </div>
            </div>

            {/* Official Ethical & Forensic Disclaimer */}
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[11px] text-amber-300/90 leading-relaxed flex items-start gap-2">
              <HelpCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>{result.disclaimer_ar}</span>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
