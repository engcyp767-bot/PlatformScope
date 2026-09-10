import React from 'react';
import { HelpCircle, AlertCircle } from 'lucide-react';

export const inputClass = 'w-full rounded-xl bg-dark-950/65 border border-white/10 px-3.5 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500/50 placeholder:text-slate-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed';
export const selectClass = 'w-full rounded-xl bg-dark-950/65 border border-white/10 px-3.5 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed';

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
}) {
  return (
    <label
      className={`flex items-start justify-between gap-4 p-3.5 rounded-xl border transition-all ${
        checked ? 'bg-cyan-500/5 border-cyan-500/25' : 'bg-white/[0.02] border-white/10'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:border-white/20'}`}
    >
      <div className="space-y-0.5 select-none">
        <span className="text-sm font-semibold text-slate-200 block">{label}</span>
        {description && <span className="text-xs text-slate-400 block leading-relaxed">{description}</span>}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={(e) => {
          e.preventDefault();
          if (!disabled) onChange(!checked);
        }}
        className={`relative inline-flex shrink-0 w-11 h-6 rounded-full border transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500/40 ${
          checked ? 'bg-cyan-500/40 border-cyan-400/80' : 'bg-slate-800 border-white/15'
        }`}
      >
        <span
          className={`pointer-events-none inline-block w-4 h-4 rounded-full bg-white shadow-sm transition-transform duration-200 ease-in-out mt-[3px] ${
            checked ? '-translate-x-[22px]' : '-translate-x-[3px]'
          }`}
        />
      </button>
    </label>
  );
}

export function Field({
  label,
  children,
  hint,
  error,
  required,
  tooltip,
  id,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
  error?: string;
  required?: boolean;
  tooltip?: string;
  id?: string;
}) {
  return (
    <div className="space-y-2" id={id}>
      <div className="flex items-center justify-between gap-2">
        <label className="block text-xs font-bold text-slate-300">
          {label}
          {required && <span className="text-rose-400 mr-1">*</span>}
        </label>
        {tooltip && (
          <span className="text-slate-500 hover:text-slate-300 transition-colors text-xs cursor-help" title={tooltip}>
            <HelpCircle className="w-3.5 h-3.5" />
          </span>
        )}
      </div>
      {children}
      {hint && !error && <p className="text-[11px] text-slate-400 leading-relaxed">{hint}</p>}
      {error && (
        <p className="text-[11px] text-rose-400 flex items-center gap-1.5 leading-relaxed">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          {error}
        </p>
      )}
    </div>
  );
}

export function SectionCard({
  title,
  subtitle,
  badge,
  action,
  children,
  className = '',
}: {
  title: string;
  subtitle?: string;
  badge?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-2xl border border-white/10 bg-white/[0.02] overflow-hidden shadow-xs ${className}`}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 sm:px-6 py-4 bg-slate-800/50 dark:bg-white/[0.03] border-b border-white/10">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-1.5 h-4 rounded-full bg-cyan-400 shrink-0 shadow-xs shadow-cyan-400/40" />
            <h3 className="text-base font-bold text-white tracking-wide">{title}</h3>
            {badge}
          </div>
          {subtitle && <p className="text-xs text-slate-400 leading-relaxed mr-4">{subtitle}</p>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
      <div className="p-5 sm:p-6 space-y-5">
        {children}
      </div>
    </div>
  );
}

export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmText = 'تأكيد',
  cancelText = 'إلغاء',
  isDanger = false,
  onConfirm,
  onCancel,
}: {
  isOpen: boolean;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  isDanger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in">
      <div className="glass-panel max-w-md w-full p-6 rounded-2xl border border-white/15 space-y-5">
        <div className="space-y-2">
          <h4 className="text-lg font-bold text-white">{title}</h4>
          <p className="text-sm text-slate-300 leading-relaxed">{message}</p>
        </div>
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 rounded-xl border border-white/10 text-sm font-semibold text-slate-300 hover:bg-white/5 transition-colors"
          >
            {cancelText}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={`px-4 py-2 rounded-xl text-sm font-bold transition-colors ${
              isDanger
                ? 'bg-rose-500 hover:bg-rose-600 text-white'
                : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
