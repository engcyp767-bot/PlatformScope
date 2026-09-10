import React, { useState, useEffect } from 'react';
import {
  Database, Download, Upload, RotateCcw, AlertTriangle, CheckCircle2,
  AlertCircle, FileJson, Layers, ShieldCheck, Archive, Trash2, RefreshCw, Loader2
} from 'lucide-react';
import { PlatformConfig, PlatformBackupItem } from '../../../lib/types';
import { SectionCard, ConfirmModal } from './FormControls';
import {
  getPlatformBackups,
  createPlatformBackup,
  restorePlatformBackup,
  deletePlatformBackup,
} from '../../../lib/api';

export function TabMaintenance({
  config,
  defaults,
  onImportConfig,
  onResetAll,
  onResetSection,
}: {
  config: PlatformConfig;
  defaults: PlatformConfig | null;
  onImportConfig: (imported: PlatformConfig) => Promise<void>;
  onResetAll: () => void;
  onResetSection: () => void;
}) {
  const [resetModalOpen, setResetModalOpen] = useState(false);
  const [importDiffModalOpen, setImportDiffModalOpen] = useState(false);
  const [pendingImport, setPendingImport] = useState<PlatformConfig | null>(null);
  const [importError, setImportError] = useState('');
  const [diffItems, setDiffItems] = useState<Array<{ section: string; key: string; oldVal: any; newVal: any }>>([]);

  // Full Platform Backups state
  const [backups, setBackups] = useState<PlatformBackupItem[]>([]);
  const [loadingBackups, setLoadingBackups] = useState(false);
  const [creatingBackup, setCreatingBackup] = useState(false);
  const [backupNote, setBackupNote] = useState('');
  const [restoreModalOpen, setRestoreModalOpen] = useState(false);
  const [restoreTarget, setRestoreTarget] = useState<PlatformBackupItem | null>(null);
  const [restoring, setRestoring] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [backupFeedback, setBackupFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const loadBackups = async () => {
    setLoadingBackups(true);
    try {
      const res = await getPlatformBackups();
      setBackups(res?.backups || []);
    } catch {
      // silently handle or set empty
    } finally {
      setLoadingBackups(false);
    }
  };

  useEffect(() => {
    loadBackups();
  }, []);

  const handleCreateBackup = async () => {
    setCreatingBackup(true);
    setBackupFeedback(null);
    try {
      const res = await createPlatformBackup({ note: backupNote });
      setBackupFeedback({
        type: 'success',
        message: `تم إنشاء النسخة الاحتياطية بنجاح: ${res.filename} (${res.size_mb} ميغابايت، ${res.file_count} ملفات)`,
      });
      setBackupNote('');
      loadBackups();
    } catch (err: any) {
      setBackupFeedback({ type: 'error', message: err.message || 'فشل إنشاء النسخة الاحتياطية' });
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleRestoreConfirm = async () => {
    if (!restoreTarget) return;
    setRestoring(true);
    setBackupFeedback(null);
    try {
      const res = await restorePlatformBackup(restoreTarget.backup_id, true);
      setBackupFeedback({
        type: 'success',
        message: `تمت استعادة المنصة بنجاح من النسخة ${restoreTarget.filename} (${res.restored_files_count} ملفات). تم حفظ لقطة أمان تلقائية.`,
      });
      setRestoreModalOpen(false);
      setRestoreTarget(null);
      loadBackups();
    } catch (err: any) {
      setBackupFeedback({ type: 'error', message: err.message || 'فشلت عملية استعادة المنصة' });
    } finally {
      setRestoring(false);
    }
  };

  const handleDeleteBackup = async (filename: string) => {
    if (!confirm(`هل أنت متأكد من رغبتك في حذف النسخة الاحتياطية ${filename}؟`)) return;
    setDeletingId(filename);
    setBackupFeedback(null);
    try {
      await deletePlatformBackup(filename);
      setBackupFeedback({ type: 'success', message: `تم حذف ملف النسخة الاحتياطية: ${filename}` });
      loadBackups();
    } catch (err: any) {
      setBackupFeedback({ type: 'error', message: err.message || 'فشل حذف النسخة الاحتياطية' });
    } finally {
      setDeletingId(null);
    }
  };


  // Safe Export: masks or removes any secrets, outputs formatted JSON
  const handleExport = () => {
    const exportPayload = {
      meta: {
        platform: 'Unified Security Platform',
        exported_at: new Date().toISOString(),
        version: config.version,
      },
      config: {
        ...config,
        // Ensure sensitive secrets remain masked in export file
        providers: {
          ...config.providers,
          virustotal: { ...config.providers.virustotal, api_keys: ['••••••••••••'] },
          abuseipdb: { ...config.providers.abuseipdb, api_key: '••••••••••••' },
          malwarebazaar: { ...config.providers.malwarebazaar, api_key: '••••••••••••' },
        },
        ai_providers: (config.ai_providers || []).map((p) => ({ ...p, api_key: '••••••••••••' })),
        external_apis: (config.external_apis || []).map((e) => ({ ...e, api_key: '••••••••••••' })),
      },
    };

    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `platform_config_backup_v${config.version}_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Safe Import with validation and schema checking
  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError('');
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const raw = JSON.parse(evt.target?.result as string);
        const candidate: PlatformConfig = raw.config || raw;

        // Basic Schema Validation
        if (!candidate.general || !candidate.appearance || !candidate.network || !candidate.features) {
          throw new Error('الملف لا يطابق بنية إعدادات المنصة المعتمدة (Missing required sections).');
        }

        // Calculate Diff
        const diffs: Array<{ section: string; key: string; oldVal: any; newVal: any }> = [];
        const sections: (keyof PlatformConfig)[] = [
          'general', 'appearance', 'analysis', 'uploads', 'reports', 'storage', 'logging', 'security', 'features', 'network'
        ];

        sections.forEach((sec) => {
          const currentSec = (config as any)[sec] || {};
          const candidateSec = (candidate as any)[sec] || {};
          Object.keys(candidateSec).forEach((k) => {
            if (JSON.stringify(currentSec[k]) !== JSON.stringify(candidateSec[k])) {
              diffs.push({
                section: sec,
                key: k,
                oldVal: currentSec[k],
                newVal: candidateSec[k],
              });
            }
          });
        });

        setPendingImport(candidate);
        setDiffItems(diffs);
        setImportDiffModalOpen(true);
      } catch (err: any) {
        setImportError(err.message || 'فشل قراءة ملف التكوين.');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const confirmImport = async () => {
    if (!pendingImport) return;
    try {
      await onImportConfig(pendingImport);
      setImportDiffModalOpen(false);
      setPendingImport(null);
    } catch (err: any) {
      setImportError(err.message || 'فشل تطبيق الإعدادات المستوردة.');
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Export / Import Section */}
      <SectionCard
        title="تصدير واستيراد الإعدادات الآمن (Safe Configuration Backup)"
        subtitle="حفظ نسخة احتياطية من التكوين أو استيرادها مع الفحص الهيكلي ومنع تسريب المفاتيح السرية"
      >
        {importError && (
          <div className="p-3.5 rounded-xl border border-rose-500/25 bg-rose-500/10 text-xs text-rose-300 font-bold mb-4">
            {importError}
          </div>
        )}

        <div className="grid md:grid-cols-2 gap-5">
          <div className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-3">
            <div className="flex items-center gap-2.5 text-white font-bold text-sm">
              <Download className="w-5 h-5 text-cyan-400" />
              تصدير نسخة احتياطية (Export JSON)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              تنزيل ملف تكوين JSON مهيكل يحتوي على كافة إعدادات المنصة الحالية. تُحجب جميع المفاتيح السرية
              تلقائيًا في ملف التصدير لحمايتها من التسريب.
            </p>
            <button
              type="button"
              onClick={handleExport}
              className="px-4 py-2.5 rounded-xl bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 border border-cyan-500/30 text-xs font-bold flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4" />
              تصدير ملف التكوين الآن
            </button>
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/[0.015] p-5 space-y-3">
            <div className="flex items-center gap-2.5 text-white font-bold text-sm">
              <Upload className="w-5 h-5 text-purple-400" />
              استيراد تكوين سابق (Import JSON)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              تحميل ملف تكوين احتياطي تم تصديره سابقًا. ستقوم المنصة بفحص سلامة البيانات وعرض الفروقات (Diff Preview)
              قبل التطبيق النهائي.
            </p>
            <label className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-purple-500/15 text-purple-300 hover:bg-purple-500/25 border border-purple-500/30 text-xs font-bold cursor-pointer transition-colors">
              <Upload className="w-4 h-4" />
              اختيار ملف تكوين لاستيراده
              <input type="file" accept=".json" onChange={handleFileSelect} className="hidden" />
            </label>
          </div>
        </div>
      </SectionCard>

      {/* Full Platform State Backup & Disaster Recovery */}
      <SectionCard
        title="النسخ الاحتياطي الشامل واستعادة المنصة (Full Platform Backup & Recovery)"
        subtitle="إنشاء أرشيفات ZIP مشفرة بهيكل SHA-256 تشمل قواعد البيانات والتكوينات وقواعد Sigma مع استعادة آمنة"
        action={
          <button
            type="button"
            onClick={loadBackups}
            disabled={loadingBackups}
            className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-300 flex items-center gap-1.5 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loadingBackups ? 'animate-spin' : ''}`} />
            تحديث القائمة
          </button>
        }
      >
        {backupFeedback && (
          <div
            className={`p-3.5 rounded-xl border text-xs font-bold mb-4 flex items-center gap-2 ${
              backupFeedback.type === 'success'
                ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300'
                : 'border-rose-500/25 bg-rose-500/10 text-rose-300'
            }`}
          >
            {backupFeedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            )}
            <span>{backupFeedback.message}</span>
          </div>
        )}

        <div className="space-y-4">
          <div className="p-4 rounded-xl border border-cyan-500/20 bg-cyan-500/5 space-y-3">
            <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
              <input
                type="text"
                value={backupNote}
                onChange={(e) => setBackupNote(e.target.value)}
                placeholder="ملاحظة أو وصف للنسخة الاحتياطية (اختياري)..."
                className="flex-1 bg-dark-900/60 border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
              />
              <button
                type="button"
                disabled={creatingBackup}
                onClick={handleCreateBackup}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shrink-0"
              >
                {creatingBackup ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Archive className="w-4 h-4" />
                )}
                <span>إنشاء نسخة احتياطية شاملة الآن</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              يقوم النظام بتجميع كافة قواعد البيانات التابعة للمنصة (SQLite)، وملفات التكوين، وقواعد الكشف والسيغما،
              وتغليفها في ملف ZIP مدعوم ببيان مطابقة وبصمة رقمية SHA-256 مانعة للتلاعب.
            </p>
          </div>

          <div className="rounded-xl border border-white/10 overflow-hidden bg-white/[0.01]">
            <div className="p-3.5 border-b border-white/10 bg-white/[0.02] flex items-center justify-between text-xs font-bold text-slate-300">
              <div className="flex items-center gap-2">
                <Archive className="w-4 h-4 text-cyan-400" />
                <span>أرشيفات النسخ الاحتياطية المتوفرة ({backups.length})</span>
              </div>
            </div>

            {loadingBackups ? (
              <div className="p-8 text-center text-xs text-slate-400 flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                <span>جاري قراءة سجل النسخ الاحتياطية...</span>
              </div>
            ) : backups.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                لا توجد نسخ احتياطية مسجلة حالياً. يمكنك إنشاء أول نسخة عبر الزر أعلاه.
              </div>
            ) : (
              <div className="divide-y divide-white/5">
                {backups.map((b) => (
                  <div key={b.backup_id} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs hover:bg-white/[0.015] transition-colors">
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-white text-xs">{b.filename}</span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-white/5 border border-white/10 text-slate-300">
                          {b.size_mb} MB
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 flex items-center gap-1">
                          <Layers className="w-3 h-3" />
                          {b.file_count} ملف
                        </span>
                        {b.valid && (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 flex items-center gap-1">
                            <ShieldCheck className="w-3 h-3" />
                            سليمة SHA-256
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-3 text-[11px] text-slate-400">
                        <span>التاريخ: {new Date(b.created_at).toLocaleString('ar-SA')}</span>
                        {b.actor && <span>المشغل: {b.actor}</span>}
                        {b.note && <span className="text-slate-300 italic truncate max-w-md">"{b.note}"</span>}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end md:self-auto shrink-0">
                      <a
                        href={`/api/platform/backup/download?filename=${encodeURIComponent(b.filename)}`}
                        download={b.filename}
                        className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-slate-200 font-bold text-xs flex items-center gap-1.5 transition-colors"
                      >
                        <Download className="w-3.5 h-3.5 text-cyan-400" />
                        <span>تنزيل</span>
                      </a>
                      <button
                        type="button"
                        onClick={() => {
                          setRestoreTarget(b);
                          setRestoreModalOpen(true);
                        }}
                        className="px-3 py-1.5 rounded-xl border border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 font-bold text-xs flex items-center gap-1.5 transition-colors"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>استعادة</span>
                      </button>
                      <button
                        type="button"
                        disabled={deletingId === b.filename}
                        onClick={() => handleDeleteBackup(b.filename)}
                        className="p-1.5 rounded-xl border border-rose-500/20 bg-rose-500/5 hover:bg-rose-500/15 text-rose-400 transition-colors disabled:opacity-40"
                        title="حذف الأرشيف"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </SectionCard>

      {/* Reset to Factory Defaults */}
      <SectionCard
        title="استعادة الإعدادات الافتراضية (Reset to Platform Defaults)"
        subtitle="إعادة تعيين قيم المنصة إلى الإعدادات القياسية المعتمدة من المصنع"
      >
        <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-500/5 space-y-3 text-xs">
          <div className="flex items-center gap-2 text-amber-300 font-bold">
            <AlertTriangle className="w-4 h-4" />
            إجراء حساس يتطلب الحذر
          </div>
          <p className="text-slate-300 leading-relaxed">
            استعادة الإعدادات الافتراضية تعيد ضبط جميع الخيارات (المظهر، حدود الرفع، نسب الخطورة، سياسات الاحتفاظ)
            إلى قيمها الأولى. لن يتم حذف أي مهام تحليلية مسجلة أو حسابات مستخدمين، ولكن ستتغير خيارات الضبط.
          </p>
          <div className="pt-1">
            <button
              type="button"
              onClick={() => setResetModalOpen(true)}
              className="px-4 py-2 rounded-xl border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              استعادة الإعدادات الافتراضية للمنصة
            </button>
          </div>
        </div>
      </SectionCard>

      {/* Reset Confirmation Modal */}
      <ConfirmModal
        isOpen={resetModalOpen}
        title="تأكيد استعادة الإعدادات الافتراضية"
        message="هل أنت متأكد من رغبتك في استعادة كافة إعدادات المنصة الافتراضية؟ سيتم استبدال التخصيصات الحالية."
        confirmText="استعادة الافتراضيات"
        cancelText="إلغاء"
        isDanger
        onConfirm={() => {
          setResetModalOpen(false);
          onResetAll();
        }}
        onCancel={() => setResetModalOpen(false)}
      />

      {/* Restore Confirmation Modal */}
      <ConfirmModal
        isOpen={restoreModalOpen}
        title="تأكيد استعادة المنصة من النسخة الاحتياطية"
        message={`هل أنت متأكد من رغبتك في استعادة بيانات المنصة من الأرشيف (${restoreTarget?.filename})؟ سيتم أخذ لقطة أمان تلقائية للبيانات الحالية قبل الاستبدال.`}
        confirmText={restoring ? 'جاري الاستعادة...' : 'تأكيد واستعادة البيانات'}
        cancelText="إلغاء"
        isDanger
        onConfirm={handleRestoreConfirm}
        onCancel={() => {
          if (!restoring) {
            setRestoreModalOpen(false);
            setRestoreTarget(null);
          }
        }}
      />


      {/* Import Diff Preview Modal */}
      {importDiffModalOpen && pendingImport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm animate-fade-in">
          <div className="glass-panel max-w-2xl w-full p-6 sm:p-7 rounded-2xl border border-white/15 space-y-5 my-8 max-h-[85vh] flex flex-col">
            <div className="border-b border-white/10 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <FileJson className="w-5 h-5 text-cyan-400" />
                معاينة فروقات الاستيراد (Configuration Diff Preview)
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                راجع التغييرات التي سيتم تطبيقها على إعدادات المنصة ({diffItems.length} تغييرات مكتشفة).
              </p>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 text-xs">
              {diffItems.length === 0 ? (
                <div className="p-6 text-center text-slate-400">
                  الملف المستورد يطابق التكوين الحالي تمامًا؛ لا توجد فروقات.
                </div>
              ) : (
                diffItems.map((d, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl border border-white/5 bg-white/[0.015] space-y-1 font-mono"
                  >
                    <div className="text-cyan-300 font-bold text-[11px]">
                      [{d.section}] {d.key}
                    </div>
                    <div className="flex items-center gap-3 text-[10px]">
                      <span className="text-rose-400 line-through truncate max-w-[240px]">
                        السابق: {JSON.stringify(d.oldVal)}
                      </span>
                      <span className="text-slate-500">➔</span>
                      <span className="text-emerald-400 font-bold truncate max-w-[240px]">
                        الجديد: {JSON.stringify(d.newVal)}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-white/10 shrink-0">
              <button
                type="button"
                onClick={() => setImportDiffModalOpen(false)}
                className="px-4 py-2 rounded-xl border border-white/10 text-xs font-bold text-slate-300 hover:bg-white/5"
              >
                إلغاء
              </button>
              <button
                type="button"
                onClick={confirmImport}
                disabled={diffItems.length === 0}
                className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black transition-colors disabled:opacity-40"
              >
                تأكيد واستيراد الإعدادات
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
