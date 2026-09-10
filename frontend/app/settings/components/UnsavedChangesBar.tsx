import React from 'react';
import { AlertCircle, Save, RotateCcw } from 'lucide-react';

export function UnsavedChangesBar({
  isDirty,
  saving,
  dirtyCount = 1,
  onSave,
  onReset,
}: {
  isDirty: boolean;
  saving: boolean;
  dirtyCount?: number;
  onSave: () => void;
  onReset: () => void;
}) {
  if (!isDirty) return null;

  return (
    <aside
      aria-label="شريط حفظ التغييرات"
      className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 w-[95%] max-w-2xl bg-dark-900/95 border border-cyan-500/30 rounded-2xl shadow-2xl shadow-cyan-500/10 p-3.5 sm:p-4 backdrop-blur-md animate-fade-in"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-amber-500/10 border border-amber-500/25 flex items-center justify-center text-amber-400 shrink-0">
            <AlertCircle className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              لديك تعديلات غير محفوظة
              <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {dirtyCount} تم تعديلها
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              احرص على حفظ التغييرات لتفعيلها على مستوى المنصة أو التراجع عنها.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 justify-end shrink-0">
          <button
            type="button"
            onClick={onReset}
            disabled={saving}
            className="px-4 py-2 rounded-xl border border-white/10 hover:bg-white/10 text-xs font-bold text-slate-300 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            إلغاء التعديلات
          </button>
          <button
            type="button"
            onClick={onSave}
            disabled={saving}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black flex items-center gap-2 transition-all shadow-md shadow-cyan-500/20 disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            {saving ? 'جارٍ الحفظ...' : 'حفظ الآن'}
          </button>
        </div>
      </div>
    </aside>
  );
}
