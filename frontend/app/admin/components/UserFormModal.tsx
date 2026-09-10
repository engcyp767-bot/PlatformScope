'use client';

import React, { useState } from 'react';
import {
  Shield,
  X,
  AlertTriangle,
  Info,
  Sliders,
  ChevronDown,
  ChevronUp,
  Search,
} from 'lucide-react';
import { User, Role, Group, ScopeInfo, DataScope, PermissionCatalog } from '../../../lib/types';

interface UserFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  editingUser: User | null;
  roles: Role[];
  groups: Group[];
  scopes: ScopeInfo[];
  catalog: PermissionCatalog | null;
  onSave: (payload: {
    username: string;
    display_name: string;
    password?: string;
    role_id: string;
    data_scope: DataScope;
    department: string;
    groups: string[];
    active: boolean;
    custom_permissions: string[];
  }) => Promise<void>;
}

export function UserFormModal({
  isOpen,
  onClose,
  editingUser,
  roles,
  groups,
  scopes,
  catalog,
  onSave,
}: UserFormModalProps) {
  const [formUsername, setFormUsername] = useState(editingUser?.username || '');
  const [formDisplayName, setFormDisplayName] = useState(editingUser?.display_name || '');
  const [formPassword, setFormPassword] = useState('');
  const [formRoleId, setFormRoleId] = useState(editingUser?.role_id || 'analyst');
  const [formDataScope, setFormDataScope] = useState<DataScope>(
    (editingUser?.data_scope as DataScope) || 'own_shared'
  );
  const [formDepartment, setFormDepartment] = useState(editingUser?.department || '');
  const [formGroupIds, setFormGroupIds] = useState<string[]>(editingUser?.groups || []);
  const [formActive, setFormActive] = useState(editingUser !== null ? editingUser.active : true);
  const [formCustomPermissions, setFormCustomPermissions] = useState<string[]>(
    editingUser?.custom_permissions || []
  );

  const [showAdvancedPerms, setShowAdvancedPerms] = useState(
    (editingUser?.custom_permissions || []).length > 0
  );
  const [userPermSearch, setUserPermSearch] = useState('');
  const [userPermFilter, setUserPermFilter] = useState<'all' | 'granted' | 'available'>('all');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser && !formPassword) {
      setError('كلمة المرور مطلوبة لإنشاء مستخدم جديد.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onSave({
        username: formUsername,
        display_name: formDisplayName,
        password: formPassword || undefined,
        role_id: formRoleId,
        data_scope: formDataScope,
        department: formDepartment,
        groups: formGroupIds,
        active: formActive,
        custom_permissions: formCustomPermissions,
      });
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'حدث خطأ أثناء حفظ بيانات المستخدم.');
    } finally {
      setSubmitting(false);
    }
  };

  const currentFormRole = roles.find((r) => r.id === formRoleId);
  const rolePerms = new Set(currentFormRole?.permissions || []);
  const selectedGroups = groups.filter((g) => formGroupIds.includes(g.id));
  const groupRoleIds = Array.from(new Set(selectedGroups.flatMap((g) => g.roles || [])));
  const groupPerms = new Set(
    groupRoleIds.flatMap((rid) => roles.find((r) => r.id === rid)?.permissions || [])
  );
  const customPerms = new Set(formCustomPermissions);
  const effectivePermsCount = new Set([...rolePerms, ...groupPerms, ...customPerms]).size;
  const totalCatalogPerms = catalog
    ? catalog.groups.reduce((acc, g) => acc + g.permissions.length, 0)
    : 0;

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl border-white/15 overflow-hidden rounded-2xl bg-dark-900">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-purple-400" />
            <span>{editingUser ? `تعديل المستخدم: ${editingUser.username}` : 'إضافة مستخدم جديد'}</span>
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
                اسم المستخدم (Username)
              </label>
              <input
                type="text"
                required
                value={formUsername}
                onChange={(e) => setFormUsername(e.target.value)}
                placeholder="مثال: ali_analyst"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                الاسم المعروض (Display Name)
              </label>
              <input
                type="text"
                required
                value={formDisplayName}
                onChange={(e) => setFormDisplayName(e.target.value)}
                placeholder="مثال: علي الأحمد"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              {editingUser
                ? 'كلمة المرور الجديدة (اتركها فارغة للإبقاء على الحالية)'
                : 'كلمة المرور'}
            </label>
            <input
              type="password"
              required={!editingUser}
              value={formPassword}
              onChange={(e) => setFormPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none"
            />
            <span className="block text-[11px] text-slate-400 mt-1">
              يجب ألا تقل كلمة المرور عن 8 أحرف.
            </span>
          </div>

          {/* Role & Scope Selection */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-white/10">
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                الدور الوظيفي (Role)
              </label>
              <select
                value={formRoleId}
                onChange={(e) => {
                  const rid = e.target.value;
                  setFormRoleId(rid);
                  const matched = roles.find((r) => r.id === rid);
                  if (matched && matched.default_scope) {
                    setFormDataScope(matched.default_scope);
                  }
                }}
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-purple-500 focus:outline-none"
              >
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.label_ar} ({r.name}) {r.is_builtin ? '' : '- مخصص'}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                نطاق البيانات (Data Scope)
              </label>
              <select
                value={formDataScope}
                onChange={(e) => setFormDataScope(e.target.value as DataScope)}
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-purple-500 focus:outline-none"
              >
                {scopes.map((s) => (
                  <option key={s.scope} value={s.scope}>
                    {s.label_ar} ({s.scope})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Data Scope Explanatory Guide */}
          <div className="p-3 rounded-xl bg-purple-500/10 border border-purple-500/20 space-y-1.5">
            <div className="flex items-center gap-1.5 text-xs font-bold text-purple-300">
              <Info className="w-3.5 h-3.5 shrink-0" />
              <span>توضيح نطاق الرؤية ({formDataScope}) لهذا المستخدم:</span>
            </div>
            <p className="text-[11px] text-slate-300 leading-relaxed">
              {formDataScope === 'own' &&
                'يقتصر وصول المستخدم على البيانات والحوادث والمهام التي أنشأها بنفسه فقط.'}
              {formDataScope === 'own_shared' &&
                'يرى المستخدم بياناته الخاصة، بالإضافة إلى أي حوادث أو أصول قام محللون آخرون بمشاركتها معه بالاسم أو مع مجموعته.'}
              {formDataScope === 'group' &&
                'يرى المستخدم بياناته الخاصة وبيانات جميع مجموعات العمل التي ينتمي إليها.'}
              {formDataScope === 'department' &&
                'يرى المستخدم كافة بيانات وسجلات قسمه بالكامل (مثل: قسم العمليات الأمنية SOC).'}
              {formDataScope === 'organization' &&
                'يرى المستخدم كافة سجلات وبيانات المنشأة بالكامل.'}
              {formDataScope === 'all' &&
                'وصول سيادي شامل وغير مقيد لجميع بيانات وسجلات المنصة.'}
            </p>
            <div className="text-[10px] text-amber-300/90 pt-1.5 border-t border-white/5 flex items-start gap-1">
              <span className="shrink-0">💡</span>
              <span>
                <strong>تنبيه توضيحي:</strong> «نطاق البيانات» يحدد حدود ما يُسمح لهذا المستخدم
                برؤيته فقط. لمشاركة مورد معين، انتقل إلى تبويب <strong>«الموارد المشتركة»</strong>.
              </span>
            </div>
          </div>

          {/* Department */}
          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              القسم / الإدارة (Department)
            </label>
            <input
              type="text"
              value={formDepartment}
              onChange={(e) => setFormDepartment(e.target.value)}
              placeholder="مثال: SOC, IT, Security Operations, Threat Intelligence"
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none"
            />
          </div>

          {/* Work Groups */}
          {groups.length > 0 && (
            <div className="pt-2 border-t border-white/10">
              <label className="block text-xs font-bold text-slate-300 mb-2">
                مجموعات العمل المنضم إليها
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-2 gap-2">
                {groups.map((g) => (
                  <label
                    key={g.id}
                    className={`flex items-center gap-2 p-2.5 rounded-xl border cursor-pointer transition-all ${
                      formGroupIds.includes(g.id)
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-white'
                        : 'bg-white/5 border-white/5 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={formGroupIds.includes(g.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setFormGroupIds([...formGroupIds, g.id]);
                        } else {
                          setFormGroupIds(formGroupIds.filter((id) => id !== g.id));
                        }
                      }}
                      className="rounded text-emerald-500 bg-dark-950 border-white/20"
                    />
                    <span className="text-xs font-medium">{g.label_ar}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Active Toggle */}
          <div className="pt-2 border-t border-white/10 flex items-center gap-2">
            <input
              type="checkbox"
              id="userActiveFormModal"
              checked={formActive}
              onChange={(e) => setFormActive(e.target.checked)}
              className="rounded text-purple-500 bg-dark-950 border-white/20"
            />
            <label
              htmlFor="userActiveFormModal"
              className="text-xs text-slate-200 cursor-pointer font-bold"
            >
              الحساب نشط (Active) — تعطيل الحساب يمنع المستخدم من الدخول فوراً
            </label>
          </div>

          {/* Advanced Custom Permissions Matrix */}
          <div className="pt-2 border-t border-white/10 space-y-3">
            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() => setShowAdvancedPerms(!showAdvancedPerms)}
                className="flex items-center gap-2 text-xs font-bold text-slate-300 hover:text-white py-1"
              >
                <Sliders className="w-4 h-4 text-purple-400" />
                <span>الصلاحيات الممنوحة للمستخدم (من الدور والتخصيص الإضافي)</span>
                {showAdvancedPerms ? (
                  <ChevronUp className="w-4 h-4 text-slate-400" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-slate-400" />
                )}
              </button>
              <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
                {effectivePermsCount} من أصل {totalCatalogPerms} صلاحية مفعلة
              </span>
            </div>

            {showAdvancedPerms && catalog && (
              <div className="p-4 rounded-xl bg-black/40 border border-white/10 space-y-3">
                <div className="p-3 rounded-lg bg-white/5 border border-white/5 space-y-2 text-[11px]">
                  <div className="text-slate-300 font-bold flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-blue-400" />
                    <span>دليل مصادر الصلاحيات المفعلة للمستخدم:</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[10px]">
                    <div className="flex items-center gap-1.5 text-blue-300">
                      <span className="w-2 h-2 rounded-full bg-blue-400" />
                      <span>
                        <strong>ممنوحة عبر الدور:</strong> {rolePerms.size} صلاحية تلقائية
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 text-emerald-300">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      <span>
                        <strong>ممنوحة عبر المجموعات:</strong> {groupPerms.size} صلاحية
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 text-purple-300">
                      <span className="w-2 h-2 rounded-full bg-purple-400" />
                      <span>
                        <strong>تخصيص يدوي إضافي:</strong> {formCustomPermissions.length} صلاحية
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row items-center justify-between gap-2 pt-1">
                  <div className="flex items-center gap-1 bg-white/5 p-1 rounded-xl border border-white/5 w-full sm:w-auto">
                    <button
                      type="button"
                      onClick={() => setUserPermFilter('all')}
                      className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${
                        userPermFilter === 'all'
                          ? 'bg-purple-600 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      الكل ({totalCatalogPerms})
                    </button>
                    <button
                      type="button"
                      onClick={() => setUserPermFilter('granted')}
                      className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${
                        userPermFilter === 'granted'
                          ? 'bg-blue-600 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      الممنوحة ({effectivePermsCount})
                    </button>
                    <button
                      type="button"
                      onClick={() => setUserPermFilter('available')}
                      className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition-all ${
                        userPermFilter === 'available'
                          ? 'bg-slate-700 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      غير الممنوحة ({Math.max(0, totalCatalogPerms - effectivePermsCount)})
                    </button>
                  </div>
                  <div className="relative w-full sm:w-48">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute right-2.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={userPermSearch}
                      onChange={(e) => setUserPermSearch(e.target.value)}
                      placeholder="بحث في الصلاحيات..."
                      className="w-full pr-8 pl-3 py-1.5 rounded-xl bg-white/5 border border-white/10 text-[11px] text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div className="space-y-4 max-h-64 overflow-y-auto pr-1">
                  {catalog.groups.map((grp) => {
                    const filteredPerms = grp.permissions.filter((p) => {
                      const fromRole = rolePerms.has(p.code);
                      const fromGroup = !fromRole && groupPerms.has(p.code);
                      const fromCustom = formCustomPermissions.includes(p.code);
                      const isGranted = fromRole || fromGroup || fromCustom;

                      if (userPermFilter === 'granted' && !isGranted) return false;
                      if (userPermFilter === 'available' && isGranted) return false;
                      if (userPermSearch.trim()) {
                        const q = userPermSearch.trim().toLowerCase();
                        return p.label.toLowerCase().includes(q) || p.code.toLowerCase().includes(q);
                      }
                      return true;
                    });

                    if (filteredPerms.length === 0) return null;

                    return (
                      <div key={grp.name} className="space-y-1.5">
                        <span className="text-xs font-bold text-purple-300 block">{grp.name}</span>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                          {filteredPerms.map((p) => {
                            const fromRole = rolePerms.has(p.code);
                            const fromGroup = !fromRole && groupPerms.has(p.code);
                            const fromCustom = formCustomPermissions.includes(p.code);
                            const isGranted = fromRole || fromGroup || fromCustom;

                            return (
                              <label
                                key={p.code}
                                className={`flex items-center justify-between gap-2 p-2 rounded-xl text-xs transition-colors border ${
                                  fromRole
                                    ? 'bg-blue-500/10 border-blue-500/30 text-blue-200 cursor-default'
                                    : fromGroup
                                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200 cursor-default'
                                    : fromCustom
                                    ? 'bg-purple-500/20 border-purple-500/35 text-purple-200 cursor-pointer'
                                    : 'bg-white/5 border-white/5 text-slate-400 hover:text-slate-200 hover:bg-white/10 cursor-pointer'
                                }`}
                              >
                                <div className="flex items-center gap-2 overflow-hidden">
                                  <input
                                    type="checkbox"
                                    checked={isGranted}
                                    disabled={fromRole || fromGroup}
                                    onChange={() => {
                                      if (fromRole || fromGroup) return;
                                      if (fromCustom) {
                                        setFormCustomPermissions(
                                          formCustomPermissions.filter((c) => c !== p.code)
                                        );
                                      } else {
                                        setFormCustomPermissions([...formCustomPermissions, p.code]);
                                      }
                                    }}
                                    className={`rounded ${
                                      fromRole
                                        ? 'text-blue-500 bg-blue-950/60 border-blue-500/40'
                                        : fromGroup
                                        ? 'text-emerald-500 bg-emerald-950/60 border-emerald-500/40'
                                        : 'text-purple-500 bg-dark-950 border-white/20'
                                    }`}
                                  />
                                  <span className="truncate text-[11px]">{p.label}</span>
                                </div>
                                <div className="shrink-0 flex items-center gap-1">
                                  {fromRole && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-semibold border border-blue-500/30">
                                      من الدور
                                    </span>
                                  )}
                                  {fromGroup && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30">
                                      من المجموعة
                                    </span>
                                  )}
                                  {fromCustom && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/30 text-purple-200 font-semibold border border-purple-500/40">
                                      تخصيص يدوي
                                    </span>
                                  )}
                                </div>
                              </label>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
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
              className="px-6 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs shadow-lg shadow-purple-600/20 transition-all disabled:opacity-50"
            >
              {submitting ? 'جارٍ الحفظ...' : 'حفظ المستخدم'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

