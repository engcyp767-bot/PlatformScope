'use client';

import React, { useState } from 'react';
import { Copy, X, AlertTriangle } from 'lucide-react';
import { Role } from '../../../lib/types';

interface CloneRoleModalProps {
  isOpen: boolean;
  onClose: () => void;
  sourceRole: Role | null;
  onClone: (sourceRoleId: string, payload: {
    name: string;
    label_ar: string;
    description: string;
  }) => Promise<void>;
}

export function CloneRoleModal({
  isOpen,
  onClose,
  sourceRole,
  onClone,
}: CloneRoleModalProps) {
  const [cloneNewName, setCloneNewName] = useState(sourceRole ? `${sourceRole.name}_copy` : '');
  const [cloneNewLabelAr, setCloneNewLabelAr] = useState(
    sourceRole ? `${sourceRole.label_ar} (نسخة)` : ''
  );
  const [cloneDescription, setCloneDescription] = useState(
    sourceRole ? `نسخة مستنسخة من دور ${sourceRole.label_ar}` : ''
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen || !sourceRole) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cloneNewName.trim() || !cloneNewLabelAr.trim()) {
      setError('الاسم البرمجي والاسم المعروض مطلوبان.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onClone(sourceRole.id, {
        name: cloneNewName.trim(),
        label_ar: cloneNewLabelAr.trim(),
        description: cloneDescription.trim(),
      });
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'فشل استنساخ الدور.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-lg shadow-2xl border-white/15 overflow-hidden rounded-2xl bg-dark-900">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Copy className="w-5 h-5 text-blue-400" />
            <span>استنساخ دور: {sourceRole.label_ar}</span>
          </h3>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="p-3 rounded-xl bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
            سيتم استنساخ مصفوفة الصلاحيات بالكامل ({sourceRole.permissions?.length || 0} صلاحية)
            والنطاق الافتراضي للدور الجديد.
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              الاسم المعرف الجديد (Code Name)
            </label>
            <input
              type="text"
              required
              value={cloneNewName}
              onChange={(e) => setCloneNewName(e.target.value)}
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              الاسم المعروض بالعربية
            </label>
            <input
              type="text"
              required
              value={cloneNewLabelAr}
              onChange={(e) => setCloneNewLabelAr(e.target.value)}
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">الوصف</label>
            <textarea
              value={cloneDescription}
              onChange={(e) => setCloneDescription(e.target.value)}
              rows={2}
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-blue-500 focus:outline-none resize-none"
            />
          </div>

          <div className="pt-4 border-t border-white/10 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 text-xs font-bold transition-colors"
            >
              إلغاء
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-lg shadow-blue-600/20 transition-all disabled:opacity-50"
            >
              {submitting ? 'جارٍ الاستنساخ...' : 'تأكيد الاستنساخ'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

