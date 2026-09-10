'use client';

import React, { useState } from 'react';
import { X, PlusCircle, UploadCloud, AlertCircle, CheckCircle, FileText, Loader2 } from 'lucide-react';
import { createIOC, importIOCs } from '../../lib/api';
import { IOCItem, IOCType, IOCSeverity, IOCTLP, IOCThreatType } from '../../lib/types';

interface AddIOCModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function AddIOCModal({ isOpen, onClose, onSuccess }: AddIOCModalProps) {
  const [activeTab, setActiveTab] = useState<'manual' | 'import'>('manual');

  // Manual Form State
  const [iocType, setIocType] = useState<IOCType>('ip');
  const [value, setValue] = useState('');
  const [threatType, setThreatType] = useState<IOCThreatType>('c2');
  const [severity, setSeverity] = useState<IOCSeverity>('high');
  const [confidence, setConfidence] = useState(85);
  const [tlp, setTlp] = useState<IOCTLP>('amber');
  const [source, setSource] = useState('SOC Manual Entry');
  const [description, setDescription] = useState('');
  const [tagsInput, setTagsInput] = useState('');
  const [threatActor, setThreatActor] = useState('');
  const [mitreTactics, setMitreTactics] = useState('');
  const [mitreTechniques, setMitreTechniques] = useState('');

  // Bulk Import State
  const [importFormat, setImportFormat] = useState<'csv' | 'json' | 'stix'>('csv');
  const [importContent, setImportContent] = useState('');
  const [onDuplicate, setOnDuplicate] = useState<'skip' | 'overwrite'>('skip');

  // Request States
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<{ imported: number; skipped: number; errors: string[] } | null>(null);

  if (!isOpen) return null;

  const handleManualSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) {
      setError('يرجى إدخال قيمة مؤشر التهديد.');
      return;
    }

    setLoading(true);
    setError(null);

    const tags = tagsInput
      .split(',')
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    const tactics = mitreTactics
      .split(',')
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    const techniques = mitreTechniques
      .split(',')
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    try {
      await createIOC({
        type: iocType,
        value: value.trim(),
        threat_type: threatType,
        severity,
        confidence,
        tlp,
        source: source.trim() || 'Internal SOC',
        description: description.trim(),
        tags,
        related_threat_actor: threatActor.trim(),
        mitre_attack: {
          tactics,
          techniques,
        },
      });

      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'فشل في إضافة مؤشر التهديد.');
    } finally {
      setLoading(false);
    }
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importContent.trim()) {
      setError('يرجى لصق أو رفع محتوى الحزمة للاستيراد.');
      return;
    }

    setLoading(true);
    setError(null);
    setImportResult(null);

    try {
      const res = await importIOCs(importContent, importFormat, onDuplicate);
      setImportResult(res);
      if (res.imported > 0) {
        onSuccess();
      }
    } catch (err: any) {
      setError(err.message || 'فشل في استيراد حزمة المؤشرات.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Detect format
    if (file.name.endsWith('.csv')) setImportFormat('csv');
    else if (file.name.endsWith('.json')) setImportFormat('json');

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setImportContent(text || '');
    };
    reader.readAsText(file);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div
        className="relative w-full max-w-2xl max-h-[92vh] flex flex-col rounded-2xl bg-dark-900/95 border border-white/10 shadow-2xl overflow-hidden"
        dir="rtl"
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-white/[0.02]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              {activeTab === 'manual' ? <PlusCircle className="w-5 h-5" /> : <UploadCloud className="w-5 h-5" />}
            </div>
            <div>
              <h2 className="text-base font-bold text-white tracking-wide">
                {activeTab === 'manual' ? 'إضافة مؤشر اختراق جديد' : 'استيراد حزمة مؤشرات استخباراتية'}
              </h2>
              <p className="text-xs text-slate-400">
                تسجيل في قاعدة المعرفة المركزية مع المطابقة الفورية والتدقيق الأمني
              </p>
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

        {/* Tab Switcher */}
        <div className="flex border-b border-white/10 bg-white/[0.01] px-6 pt-2">
          <button
            type="button"
            onClick={() => {
              setActiveTab('manual');
              setError(null);
            }}
            className={`pb-3 px-4 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === 'manual'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <PlusCircle className="w-4 h-4" />
            <span>إدخال يدوي منفرد</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('import');
              setError(null);
            }}
            className={`pb-3 px-4 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
              activeTab === 'import'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>استيراد جماعي (CSV / JSON / STIX 2.1)</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 flex-1 overflow-y-auto space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {activeTab === 'manual' ? (
            <form onSubmit={handleManualSubmit} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">نوع المؤشر (Type):</label>
                  <select
                    value={iocType}
                    onChange={(e) => setIocType(e.target.value as IOCType)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="ip">IP Address (IPv4 / IPv6 / CIDR)</option>
                    <option value="domain">Domain Name</option>
                    <option value="url">URL Address</option>
                    <option value="hash_sha256">File Hash (SHA256)</option>
                    <option value="hash_md5">File Hash (MD5)</option>
                    <option value="hash_sha1">File Hash (SHA1)</option>
                    <option value="certificate">SSL/TLS Certificate Fingerprint</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">تصنيف التهديد (Threat Type):</label>
                  <select
                    value={threatType}
                    onChange={(e) => setThreatType(e.target.value as IOCThreatType)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="c2">Command & Control (C2)</option>
                    <option value="malware">Malware Payload / Dropper</option>
                    <option value="phishing">Phishing / Credential Harvesting</option>
                    <option value="ransomware">Ransomware</option>
                    <option value="scanner">Vulnerability Scanner</option>
                    <option value="exploit">Exploit Attempt</option>
                    <option value="botnet">Botnet Infrastructure</option>
                    <option value="apt">Advanced Persistent Threat (APT)</option>
                    <option value="crypto_miner">Cryptocurrency Miner</option>
                    <option value="suspicious">Suspicious / Generic</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">قيمة المؤشر (Indicator Value):</label>
                <input
                  type="text"
                  required
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder="e.g. 198.51.100.44 or malicious-domain.com"
                  dir="ltr"
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-sm font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">مستوى الخطورة (Severity):</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as IOCSeverity)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="critical">Critical (حرج جدًا)</option>
                    <option value="high">High (مرتفع)</option>
                    <option value="medium">Medium (متوسط)</option>
                    <option value="low">Low (منخفض)</option>
                    <option value="info">Info (معلوماتي)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    درجة الموثوقية: {confidence}%
                  </label>
                  <input
                    type="range"
                    min="10"
                    max="100"
                    step="5"
                    value={confidence}
                    onChange={(e) => setConfidence(Number(e.target.value))}
                    className="w-full h-2 mt-2 bg-white/10 rounded-lg appearance-none cursor-pointer accent-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">مستوى السرية (TLP):</label>
                  <select
                    value={tlp}
                    onChange={(e) => setTlp(e.target.value as IOCTLP)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="amber">TLP:AMBER (مقيد داخليًا)</option>
                    <option value="red">TLP:RED (سري للغاية)</option>
                    <option value="green">TLP:GREEN (مجتمع الأمن)</option>
                    <option value="white">TLP:WHITE (عام مفتوح)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">مصدر المعلومة (Source):</label>
                  <input
                    type="text"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                    placeholder="e.g. AlienVault OTX, AbuseIPDB, Internal SOC"
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">الفاعل / العصابة المرتبطة (Actor):</label>
                  <input
                    type="text"
                    value={threatActor}
                    onChange={(e) => setThreatActor(e.target.value)}
                    placeholder="e.g. LockBit 3.0, FIN7, APT29"
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    تكتيكات MITRE ATT&CK (مفصولة بفواصل):
                  </label>
                  <input
                    type="text"
                    value={mitreTactics}
                    onChange={(e) => setMitreTactics(e.target.value)}
                    placeholder="e.g. Command and Control, Initial Access"
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    تقنيات MITRE ATT&CK (مفصولة بفواصل):
                  </label>
                  <input
                    type="text"
                    value={mitreTechniques}
                    onChange={(e) => setMitreTechniques(e.target.value)}
                    placeholder="e.g. T1071.001, T1566.002"
                    dir="ltr"
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">الوسوم (Tags - مفصولة بفواصل):</label>
                <input
                  type="text"
                  value={tagsInput}
                  onChange={(e) => setTagsInput(e.target.value)}
                  placeholder="e.g. cobalt_strike, beacon, lockbit, phishing"
                  dir="ltr"
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">الوصف والتحليل الجنائي:</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  placeholder="شرح طبيعة التهديد وسياق الرصد الجنائي..."
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 resize-none"
                />
              </div>

              <div className="pt-2 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-semibold text-slate-300 transition-colors"
                >
                  إلغاء
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <PlusCircle className="w-4 h-4" />}
                  <span>حفظ المؤشر في قاعدة المعرفة</span>
                </button>
              </div>
            </form>
          ) : (
            <form onSubmit={handleImportSubmit} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">صيغة الحزمة (Format):</label>
                  <select
                    value={importFormat}
                    onChange={(e) => setImportFormat(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="csv">ملف مجدول CSV (value, type, threat_type, severity...)</option>
                    <option value="json">مصفوفة JSON المهيكلة</option>
                    <option value="stix">حزمة معيارية STIX 2.1 JSON Bundle</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    استراتيجية معالجة التكرار (Duplicate Policy):
                  </label>
                  <select
                    value={onDuplicate}
                    onChange={(e) => setOnDuplicate(e.target.value as any)}
                    className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs text-white focus:outline-none focus:border-emerald-500"
                  >
                    <option value="skip">تخطي التكرار (Skip Existing - آمن)</option>
                    <option value="overwrite">تحديث القائم (Overwrite with new fields)</option>
                  </select>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-semibold text-slate-300">محتوى الحزمة (Paste Content):</label>
                  <label className="text-[11px] text-emerald-400 hover:text-emerald-300 cursor-pointer flex items-center gap-1 font-semibold">
                    <FileText className="w-3.5 h-3.5" />
                    <span>تحميل من ملف محلي</span>
                    <input type="file" accept=".csv,.json,.txt" onChange={handleFileUpload} className="hidden" />
                  </label>
                </div>
                <textarea
                  value={importContent}
                  onChange={(e) => setImportContent(e.target.value)}
                  rows={8}
                  dir="ltr"
                  placeholder={
                    importFormat === 'csv'
                      ? 'type,value,threat_type,severity,confidence,source\nip,198.51.100.55,c2,critical,90,ThreatFox\ndomain,evil-c2-sync.org,malware,high,85,AlienVault'
                      : importFormat === 'stix'
                      ? '{\n  "type": "bundle",\n  "id": "bundle--...",\n  "objects": [...]\n}'
                      : '[\n  {"type": "ip", "value": "198.51.100.55", "threat_type": "c2", "severity": "high"}\n]'
                  }
                  className="w-full px-3 py-2 rounded-xl bg-black/40 border border-white/15 text-xs font-mono text-white placeholder:text-slate-600 focus:outline-none focus:border-emerald-500 resize-none"
                />
              </div>

              {importResult && (
                <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 space-y-1">
                  <div className="flex items-center gap-2 font-bold">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    <span>اكتملت معالجة الحزمة بنجاح:</span>
                  </div>
                  <div className="flex items-center gap-4 text-slate-300 pt-1">
                    <span>مؤشرات أضيفت: <strong className="text-white">{importResult.imported}</strong></span>
                    <span>مؤشرات تم تخطيها: <strong className="text-white">{importResult.skipped}</strong></span>
                    {importResult.errors.length > 0 && (
                      <span className="text-amber-400">أخطاء: {importResult.errors.length}</span>
                    )}
                  </div>
                </div>
              )}

              <div className="pt-2 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-semibold text-slate-300 transition-colors"
                >
                  إغلاق
                </button>
                <button
                  type="submit"
                  disabled={loading || !importContent.trim()}
                  className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <UploadCloud className="w-4 h-4" />}
                  <span>استيراد ومعالجة الحزمة الآن</span>
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
