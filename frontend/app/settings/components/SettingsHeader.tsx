import React from 'react';
import Link from 'next/link';
import { LucideIcon, HelpCircle, AlertTriangle, RefreshCw, Save, RotateCcw } from 'lucide-react';

export function SettingsHeader({
  title,
  subtitle,
  icon: Icon,
  badge,
  isRestartRequired,
  helpAnchor,
  onSave,
  onReset,
  onReload,
  saving,
  isDirty,
}: {
  title: string;
  subtitle: string;
  icon: LucideIcon;
  badge?: React.ReactNode;
  isRestartRequired?: boolean;
  helpAnchor?: string;
  onSave: () => void;
  onReset: () => void;
  onReload: () => void;
  saving: boolean;
  isDirty: boolean;
}) {
  return (
    <div className="space-y-4 mb-6 border-b border-white/5 pb-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5 flex-wrap">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-400">
              <Icon className="w-5 h-5" />
            </div>
            <h1 className="text-2xl font-black text-white tracking-wide">{title}</h1>
            {badge}
            {isRestartRequired && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold bg-amber-500/10 border border-amber-500/30 text-amber-300">
                <AlertTriangle className="w-3.5 h-3.5" />
                يتطلب إعادة تشغيل المنصة
              </span>
            )}
            {helpAnchor && (
              <Link
                href={`/help#${helpAnchor}`}
                className="inline-flex items-center gap-1 text-xs font-semibold text-slate-400 hover:text-cyan-300 bg-white/5 hover:bg-cyan-500/10 border border-white/10 px-2.5 py-1 rounded-lg transition-colors"
                title="عرض الشرح التفصيلي في مركز المساعدة"
              >
                <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
                دليل الاستخدام
              </Link>
            )}
          </div>
          <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">{subtitle}</p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
          <button
            type="button"
            onClick={onReset}
            disabled={!isDirty || saving}
            className="px-3.5 py-2 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-300 flex items-center gap-1.5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="التراجع عن التغييرات غير المحفوظة في هذا القسم"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            تراجع
          </button>
          <button
            type="button"
            onClick={onReload}
            disabled={saving}
            className="px-3.5 py-2 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-300 flex items-center gap-1.5 transition-colors disabled:opacity-50"
            title="إعادة تحميل أحدث إعدادات من الخادم"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${saving ? 'animate-spin' : ''}`} />
            تحديث
          </button>
          <button
            type="button"
            onClick={onSave}
            disabled={saving || !isDirty}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 text-slate-950 text-xs font-black flex items-center gap-2 transition-all shadow-lg shadow-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'جارٍ الحفظ...' : 'حفظ التغييرات'}
          </button>
        </div>
      </div>
    </div>
  );
}
