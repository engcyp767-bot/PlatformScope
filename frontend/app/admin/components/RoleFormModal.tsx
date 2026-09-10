'use client';

import React, { useState } from 'react';
import { Key, X, AlertTriangle, Info } from 'lucide-react';
import { Role, DataScope, ScopeInfo, PermissionCatalog } from '../../../lib/types';

interface RoleFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  editingRole: Role | null;
  scopes: ScopeInfo[];
  catalog: PermissionCatalog | null;
  onSave: (payload: {
    name: string;
    label_ar: string;
    description: string;
    default_scope: DataScope;
    permissions: string[];
  }) => Promise<void>;
}

export function RoleFormModal({
  isOpen,
  onClose,
  editingRole,
  scopes,
  catalog,
  onSave,
}: RoleFormModalProps) {
  const [roleName, setRoleName] = useState(editingRole?.name || '');
  const [roleLabelAr, setRoleLabelAr] = useState(editingRole?.label_ar || '');
  const [roleDescription, setRoleDescription] = useState(editingRole?.description || '');
  const [roleDefaultScope, setRoleDefaultScope] = useState<DataScope>(
    editingRole?.default_scope || 'own_shared'
  );
  const [rolePermissions, setRolePermissions] = useState<string[]>(
    editingRole?.permissions || ['portal.access', 'incidents.view', 'history.view']
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!roleName.trim() || !roleLabelAr.trim()) {
      setError('الاسم البرمجي والاسم العربي مطلوبان.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onSave({
        name: roleName.trim(),
        label_ar: roleLabelAr.trim(),
        description: roleDescription.trim(),
        default_scope: roleDefaultScope,
        permissions: rolePermissions,
      });
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'حدث خطأ أثناء حفظ الدور.');
    } finally {
      setSubmitting(false);
    }
  };

  const togglePermission = (code: string) => {
    if (rolePermissions.includes(code)) {
      setRolePermissions(rolePermissions.filter((p) => p !== code));
    } else {
      setRolePermissions([...rolePermissions, code]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl border-white/15 overflow-hidden rounded-2xl bg-dark-900">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-blue-400" />
            <span>{editingRole ? `تعديل الدور: ${editingRole.label_ar}` : 'إنشاء دور وظيفي مخصص'}</span>
          </h3>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-5 flex-1">
          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                الاسم المعرف (Code Name)
              </label>
              <input
                type="text"
                required
                disabled={editingRole !== null}
                value={roleName}
                onChange={(e) => setRoleName(e.target.value)}
                placeholder="مثال: junior_analyst"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none disabled:opacity-50"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                الاسم المعروض (العربية)
              </label>
              <input
                type="text"
                required
                value={roleLabelAr}
                onChange={(e) => setRoleLabelAr(e.target.value)}
                placeholder="مثال: محلل أمني مساعد"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              الوصف الوظيفي (Description)
            </label>
            <textarea
              value={roleDescription}
              onChange={(e) => setRoleDescription(e.target.value)}
              rows={2}
              placeholder="وصف المهام والمسؤوليات المنوطة بهذا الدور..."
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none resize-none"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              نطاق البيانات الافتراضي (Default Data Scope)
            </label>
            <select
              value={roleDefaultScope}
              onChange={(e) => setRoleDefaultScope(e.target.value as DataScope)}
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-blue-500 focus:outline-none"
            >
              {scopes.map((s) => (
                <option key={s.scope} value={s.scope}>
                  {s.label_ar} ({s.scope})
                </option>
              ))}
            </select>
          </div>

          {/* Permissions Selector */}
          {catalog && (
            <div className="pt-2 border-t border-white/10 space-y-3">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-bold text-slate-300">
                  مصفوفة صلاحيات هذا الدور
                </label>
                <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  {rolePermissions.length} صلاحية محددة
                </span>
              </div>

              <div className="space-y-4 max-h-60 overflow-y-auto p-3 bg-black/40 rounded-xl border border-white/5 pr-1">
                {catalog.groups.map((grp) => (
                  <div key={grp.name} className="space-y-1.5">
                    <span className="text-xs font-bold text-blue-300 block">{grp.name}</span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {grp.permissions.map((p) => {
                        const checked = rolePermissions.includes(p.code);
                        return (
                          <label
                            key={p.code}
                            className={`flex items-center gap-2 p-2 rounded-xl text-xs transition-colors border cursor-pointer ${
                              checked
                                ? 'bg-blue-500/20 border-blue-500/35 text-blue-200'
                                : 'bg-white/5 border-white/5 text-slate-400 hover:text-slate-200 hover:bg-white/10'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => togglePermission(p.code)}
                              className="rounded text-blue-500 bg-dark-950 border-white/20"
                            />
                            <span className="truncate text-[11px]">{p.label}</span>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

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
              {submitting ? 'جارٍ الحفظ...' : 'حفظ الدور'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

