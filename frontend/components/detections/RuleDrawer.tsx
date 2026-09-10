'use client';

import React, { useState, useEffect } from 'react';
import {
  X,
  Shield,
  Activity,
  CheckCircle2,
  XCircle,
  Play,
  History,
  AlertTriangle,
  Code,
  Tag,
  Clock,
  User,
  Sliders,
  Sparkles,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import { DetectionRule, RuleTestResult } from '../../lib/types';
import {
  toggleDetectionRule,
  updateDetectionLifecycle,
  runDetectionRuleTests,
  testDetectionRuleSimulator,
} from '../../lib/api';

interface RuleDrawerProps {
  rule: DetectionRule | null;
  onClose: () => void;
  onRuleUpdated: (updated: DetectionRule) => void;
  userPermissions?: string[];
}

export function RuleDrawer({ rule, onClose, onRuleUpdated, userPermissions = [] }: RuleDrawerProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'condition' | 'simulator' | 'history'>('overview');
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [testingRunning, setTestingRunning] = useState(false);

  // Simulator live test state
  const [customEventJson, setCustomEventJson] = useState('');
  const [simResult, setSimResult] = useState<{ matched: boolean; execution_time_ms: number } | null>(null);
  const [simLoading, setSimLoading] = useState(false);

  // Lifecycle change state
  const [selectedLifecycle, setSelectedLifecycle] = useState<string>(rule?.lifecycle || 'production');
  const [lifecycleReason, setLifecycleReason] = useState('');
  const [lifecycleSubmitting, setLifecycleSubmitting] = useState(false);

  const canManage = userPermissions.includes('detections.manage');

  useEffect(() => {
    if (rule) {
      setSelectedLifecycle(rule.lifecycle);
      setTestResult(null);
      setSimResult(null);
      if (rule.test_samples?.positive?.length) {
        setCustomEventJson(JSON.stringify(rule.test_samples.positive[0], null, 2));
      } else {
        setCustomEventJson('{\n  "event_id": "4625",\n  "message": "Sample event"\n}');
      }
    }
  }, [rule]);

  if (!rule) return null;

  const handleRunTests = async () => {
    try {
      setTestingRunning(true);
      const res = await runDetectionRuleTests(rule.id);
      setTestResult(res);
    } catch (err: any) {
      alert(err.message || 'فشل تشغيل عينات الاختبار');
    } finally {
      setTestingRunning(false);
    }
  };

  const handleRunSimulator = async () => {
    try {
      setSimLoading(true);
      const parsedEvent = JSON.parse(customEventJson);
      const res = await testDetectionRuleSimulator(rule, parsedEvent);
      setSimResult(res);
    } catch (err: any) {
      alert(err.message || 'صيغة JSON غير صحيحة للسجل');
    } finally {
      setSimLoading(false);
    }
  };

  const handleLifecycleChange = async () => {
    if (!lifecycleReason.trim()) {
      alert('يرجى كتابة سبب تغيير دورة الحياة.');
      return;
    }
    try {
      setLifecycleSubmitting(true);
      const updated = await updateDetectionLifecycle(rule.id, selectedLifecycle, lifecycleReason);
      onRuleUpdated(updated);
      setLifecycleReason('');
      alert('تم تحديث دورة حياة القاعدة بنجاح.');
    } catch (err: any) {
      alert(err.message || 'فشل تحديث دورة الحياة');
    } finally {
      setLifecycleSubmitting(false);
    }
  };

  const handleToggle = async () => {
    try {
      const updated = await toggleDetectionRule(rule.id, !rule.enabled);
      onRuleUpdated(updated);
    } catch (err: any) {
      alert(err.message || 'فشل تبديل حالة القاعدة');
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">حرج (Critical)</span>;
      case 'high':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/30">مرتفع (High)</span>;
      case 'medium':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">متوسط (Medium)</span>;
      case 'low':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">منخفض (Low)</span>;
      default:
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-500/15 text-slate-300 border border-slate-500/30">{sev}</span>;
    }
  };

  const getLifecycleBadge = (lifecycle: string) => {
    switch (lifecycle.toLowerCase()) {
      case 'production':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">إنتاج (Production)</span>;
      case 'testing':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">اختبار (Testing)</span>;
      case 'development':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30">تطوير (Development)</span>;
      case 'deprecated':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-600/20 text-slate-400 border border-slate-600/30">موقوفة (Deprecated)</span>;
      default:
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-700/20 text-slate-300 border border-slate-700/30">{lifecycle}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm flex justify-end transition-opacity">
      <div className="w-full max-w-3xl bg-slate-900 border-r border-white/10 h-full flex flex-col shadow-2xl text-slate-100 animate-in slide-in-from-left duration-200">
        {/* Header */}
        <div className="px-6 py-5 border-b border-white/10 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 font-mono font-bold text-sm">
              DET
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-amber-400">{rule.id}</span>
                <span className="text-slate-400 text-xs">• v{rule.version}</span>
                {getLifecycleBadge(rule.lifecycle)}
                {getSeverityBadge(rule.severity)}
              </div>
              <h2 className="text-lg font-bold text-white mt-0.5">{rule.name}</h2>
              <div className="text-xs text-slate-400 font-sans">{rule.name_en}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {canManage && (
              <button
                type="button"
                onClick={handleToggle}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors flex items-center gap-1.5 ${
                  rule.enabled
                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/25'
                    : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                }`}
              >
                <Activity className="w-3.5 h-3.5" />
                <span>{rule.enabled ? 'مفعلة (Enabled)' : 'معطلة (Disabled)'}</span>
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab navigation */}
        <div className="px-6 border-b border-white/10 bg-slate-900/50 flex gap-4">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'overview'
                ? 'border-amber-400 text-amber-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>نظرة عامة والتحليل</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('condition')}
            className={`py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'condition'
                ? 'border-amber-400 text-amber-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code className="w-4 h-4" />
            <span>الشروط وسياسة الحادث</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('simulator')}
            className={`py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'simulator'
                ? 'border-amber-400 text-amber-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-4 h-4 text-primary" />
            <span>محاكي الاختبار (Simulator)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('history')}
            className={`py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'history'
                ? 'border-amber-400 text-amber-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="w-4 h-4" />
            <span>سجل الإصدارات والتعديلات</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Telemetry Metrics */}
              <div className="grid grid-cols-4 gap-3">
                <div className="p-3.5 rounded-xl bg-white/5 border border-white/10">
                  <div className="text-[11px] text-slate-400">السجلات المفحوصة</div>
                  <div className="text-xl font-mono font-bold text-white mt-1">
                    {rule.metrics?.evaluated_events?.toLocaleString('en-US') || 0}
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-white/5 border border-white/10">
                  <div className="text-[11px] text-slate-400">مرات التطابق</div>
                  <div className="text-xl font-mono font-bold text-amber-400 mt-1">
                    {rule.metrics?.match_count?.toLocaleString('en-US') || 0}
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-white/5 border border-white/10">
                  <div className="text-[11px] text-slate-400">متوسط التنفيذ</div>
                  <div className="text-xl font-mono font-bold text-emerald-400 mt-1">
                    {rule.metrics?.execution_time_ms ? `${rule.metrics.execution_time_ms} ms` : '0.05 ms'}
                  </div>
                </div>
                <div className="p-3.5 rounded-xl bg-white/5 border border-white/10">
                  <div className="text-[11px] text-slate-400">إيجابيات كاذبة (FP)</div>
                  <div className="text-xl font-mono font-bold text-red-400 mt-1">
                    {rule.metrics?.false_positive_count || 0}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2">
                <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">وصف التهديد الأمني</h3>
                <p className="text-sm text-slate-200 leading-relaxed">{rule.description || 'لا يوجد وصف تفصيلي.'}</p>
              </div>

              {/* MITRE ATT&CK Matrix v14.1 */}
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-primary" />
                    <span>مصفوفة MITRE ATT&CK ({rule.mitre_attack?.version || 'v14.1'})</span>
                  </h3>
                  <span className="text-[11px] text-primary font-mono font-semibold">
                    {rule.mitre_attack?.tactics?.length || 0} Tactics • {rule.mitre_attack?.techniques?.length || 0} Techniques
                  </span>
                </div>
                <div className="space-y-2">
                  <div>
                    <div className="text-[11px] text-slate-400 mb-1.5">التكتيكات (Tactics):</div>
                    <div className="flex flex-wrap gap-1.5">
                      {(rule.mitre_attack?.tactics || []).map((tac, idx) => (
                        <span key={idx} className="px-2.5 py-1 rounded-md text-xs bg-primary/10 text-primary border border-primary/20">
                          {tac}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="pt-2">
                    <div className="text-[11px] text-slate-400 mb-1.5">التقنيات (Techniques):</div>
                    <div className="flex flex-wrap gap-1.5">
                      {(rule.mitre_attack?.techniques || []).map((tech, idx) => (
                        <span key={idx} className="px-2.5 py-1 rounded-md text-xs font-mono bg-white/5 text-slate-200 border border-white/10">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommendations */}
              {rule.recommendations && rule.recommendations.length > 0 && (
                <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>إجراءات الاستجابة الموصى بها (Playbook)</span>
                  </h3>
                  <ul className="space-y-1.5 pr-4 list-disc text-xs text-slate-300">
                    {rule.recommendations.map((rec, idx) => (
                      <li key={idx} className="leading-relaxed">{rec}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Lifecycle State Management (Only for Managers) */}
              {canManage && (
                <div className="p-4 rounded-xl bg-slate-950/80 border border-amber-500/20 space-y-3">
                  <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Sliders className="w-3.5 h-3.5 text-amber-400" />
                    <span>إدارة دورة حياة القاعدة (Lifecycle Transition)</span>
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">الحالة المستهدفة</label>
                      <select
                        value={selectedLifecycle}
                        onChange={(e) => setSelectedLifecycle(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-white/10 text-xs text-white focus:outline-none focus:border-amber-400"
                      >
                        <option value="development">Development (قيد التطوير)</option>
                        <option value="testing">Testing (قيد الاختبار)</option>
                        <option value="production">Production (إنتاج ونشط)</option>
                        <option value="deprecated">Deprecated (موقوفة تاريخياً)</option>
                      </select>
                    </div>
                    <div className="sm:col-span-2">
                      <label className="text-[11px] text-slate-400 block mb-1">مبرر التعديل (إلزامي في التدقيق)</label>
                      <input
                        type="text"
                        value={lifecycleReason}
                        onChange={(e) => setLifecycleReason(e.target.value)}
                        placeholder="مثال: اجتياز اختبارات الانحدار وتدقيق معدل FP"
                        className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-white/10 text-xs text-white focus:outline-none focus:border-amber-400"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      onClick={handleLifecycleChange}
                      disabled={lifecycleSubmitting || selectedLifecycle === rule.lifecycle}
                      className="px-4 py-1.5 rounded-lg bg-amber-500 text-slate-950 font-bold text-xs hover:bg-amber-400 disabled:opacity-50 transition-colors flex items-center gap-1.5"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${lifecycleSubmitting ? 'animate-spin' : ''}`} />
                      <span>تحديث دورة الحياة</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'condition' && (
            <div className="space-y-6">
              {/* Condition JSON */}
              <div className="p-4 rounded-xl bg-slate-950 border border-white/10 space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Code className="w-3.5 h-3.5 text-amber-400" />
                    <span>منطق شرط الكشف (Condition Logic)</span>
                  </h3>
                  <span className="text-[11px] text-slate-400 font-mono">Declarative AST</span>
                </div>
                <pre className="p-3.5 rounded-lg bg-slate-900/90 text-amber-300 font-mono text-xs overflow-x-auto border border-white/5 dir-ltr text-left">
                  {JSON.stringify(rule.condition, null, 2)}
                </pre>
              </div>

              {/* Incident Policy */}
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-primary" />
                    <span>سياسة إنشاء الحوادث (Incident Policy)</span>
                  </h3>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    rule.incident_policy?.auto_promote
                      ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      : 'bg-slate-700/20 text-slate-400 border border-slate-700'
                  }`}>
                    {rule.incident_policy?.auto_promote ? 'ترقية تلقائية مفعلة' : 'ترقية يدوية'}
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-white/5">
                    <div className="text-slate-400 text-[11px]">العتبة (Threshold)</div>
                    <div className="font-mono font-bold text-white mt-1">
                      {rule.incident_policy?.threshold || 1} محاولات
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-white/5">
                    <div className="text-slate-400 text-[11px]">النافذة الزمنية</div>
                    <div className="font-mono font-bold text-white mt-1">
                      {rule.incident_policy?.time_window_seconds || 60} ثانية
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-white/5">
                    <div className="text-slate-400 text-[11px]">أدنى ثقة مطلوبة</div>
                    <div className="font-mono font-bold text-amber-400 mt-1">
                      {rule.incident_policy?.min_confidence || 75}%
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-white/5">
                    <div className="text-slate-400 text-[11px]">تجميع حسب</div>
                    <div className="font-mono text-white text-[11px] mt-1 truncate">
                      {(rule.incident_policy?.group_by || ['username']).join(', ')}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'simulator' && (
            <div className="space-y-6">
              {/* Regression Test Samples */}
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Play className="w-3.5 h-3.5 text-emerald-400" />
                      <span>عينات فحص الانحدار المعيارية (Positive / Negative Tests)</span>
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      يتم اختبار القاعدة ضد عينات إيجابية مؤكدة وأخرى سلبية بريئة للتحقق من عدم حدوث تجاوزات أو إيجابيات كاذبة.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleRunTests}
                    disabled={testingRunning}
                    className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-colors flex items-center gap-1.5"
                  >
                    <Play className={`w-3.5 h-3.5 ${testingRunning ? 'animate-spin' : ''}`} />
                    <span>تشغيل الفحص الآلي</span>
                  </button>
                </div>

                {testResult && (
                  <div className={`p-4 rounded-xl border ${
                    testResult.all_passed
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : 'bg-red-500/10 border-red-500/30'
                  }`}>
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2 font-bold text-sm">
                        {testResult.all_passed ? (
                          <>
                            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                            <span className="text-emerald-400">اجتازت القاعدة جميع عينات الفحص بنجاح 100%</span>
                          </>
                        ) : (
                          <>
                            <XCircle className="w-5 h-5 text-red-400" />
                            <span className="text-red-400">فشلت بعض عينات الفحص في التطابق المطلوب</span>
                          </>
                        )}
                      </div>
                      <div className="text-xs font-mono text-slate-300">
                        {testResult.positive.passed}/{testResult.positive.total} Positive • {testResult.negative.passed}/{testResult.negative.total} Negative
                      </div>
                    </div>

                    <div className="space-y-2">
                      <div className="text-[11px] font-semibold text-slate-400">تفاصيل العينات الإيجابية (يجب أن تتطابق):</div>
                      {testResult.positive.details.map((d, i) => (
                        <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/60">
                          <span className="truncate max-w-md font-mono text-slate-300">{JSON.stringify(d.sample)}</span>
                          {d.passed ? (
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> تطابقت
                            </span>
                          ) : (
                            <span className="text-red-400 font-semibold flex items-center gap-1">
                              <XCircle className="w-3.5 h-3.5" /> لم تتطابق
                            </span>
                          )}
                        </div>
                      ))}

                      <div className="text-[11px] font-semibold text-slate-400 pt-2">تفاصيل العينات السلبية (يجب ألا تتطابق):</div>
                      {testResult.negative.details.map((d, i) => (
                        <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/60">
                          <span className="truncate max-w-md font-mono text-slate-300">{JSON.stringify(d.sample)}</span>
                          {d.passed ? (
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> لم تتطابق (سليمة)
                            </span>
                          ) : (
                            <span className="text-red-400 font-semibold flex items-center gap-1">
                              <XCircle className="w-3.5 h-3.5" /> تطابقت بالخطأ (FP)
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Custom Live Simulator */}
              <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-primary" />
                    <span>محاكي فحص سجل مخصص (Interactive Dry-Run)</span>
                  </h3>
                  <span className="text-[11px] text-slate-400">اختبر أي حدث بصيغة JSON فورياً</span>
                </div>
                <textarea
                  value={customEventJson}
                  onChange={(e) => setCustomEventJson(e.target.value)}
                  rows={6}
                  dir="ltr"
                  className="w-full p-3 rounded-lg bg-slate-950 border border-white/10 font-mono text-xs text-amber-300 focus:outline-none focus:border-amber-400 text-left"
                  placeholder="ضع كائن JSON لحدث هنا..."
                />
                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={handleRunSimulator}
                    disabled={simLoading}
                    className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-colors flex items-center gap-1.5"
                  >
                    <Sparkles className={`w-3.5 h-3.5 ${simLoading ? 'animate-spin' : ''}`} />
                    <span>فحص السجل ضد القاعدة</span>
                  </button>
                  {simResult && (
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-slate-400 font-mono">
                        زمن الفحص: {simResult.execution_time_ms} ms
                      </span>
                      {simResult.matched ? (
                        <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                          <CheckCircle2 className="w-4 h-4" /> تطابق شرط الكشف (Match)
                        </span>
                      ) : (
                        <span className="px-3 py-1 rounded-full text-xs font-bold bg-slate-700/20 text-slate-400 border border-slate-700 flex items-center gap-1">
                          <XCircle className="w-4 h-4" /> لم يتطابق (No Match)
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5 text-primary" />
                  <span>تاريخ إصدارات القاعدة وتعديلاتها (Version History)</span>
                </h3>
                <span className="text-xs text-slate-400 font-mono">
                  {rule.version_history?.length || 0} إصدارات مسجلة
                </span>
              </div>

              <div className="relative pr-6 border-r border-white/10 space-y-6">
                {(rule.version_history || []).map((ver, idx) => (
                  <div key={idx} className="relative">
                    <div className="absolute -right-[31px] top-1 w-3 h-3 rounded-full bg-amber-400 border-2 border-slate-900" />
                    <div className="p-3.5 rounded-xl bg-white/5 border border-white/10 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-bold text-xs text-amber-400">الإصدار v{ver.version}</span>
                        <span className="text-[11px] text-slate-400 font-mono">{ver.timestamp}</span>
                      </div>
                      <div className="text-xs text-slate-200">{ver.reason}</div>
                      <div className="text-[11px] text-slate-400 flex items-center gap-1">
                        <User className="w-3 h-3 text-slate-500" />
                        <span>بواسطة: {ver.changed_by}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
