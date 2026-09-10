'use client';

import React, { useState } from 'react';
import { Layers, X, AlertTriangle } from 'lucide-react';
import { Group, Role, ScopeInfo, DataScope, User } from '../../../lib/types';

interface GroupFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  editingGroup: Group | null;
  roles: Role[];
  scopes: ScopeInfo[];
  users: User[];
  onSave: (payload: {
    name: string;
    label_ar: string;
    description: string;
    department: string;
    default_scope: DataScope;
    roles: string[];
    members: string[];
  }) => Promise<void>;
}

export function GroupFormModal({
  isOpen,
  onClose,
  editingGroup,
  roles,
  scopes,
  users,
  onSave,
}: GroupFormModalProps) {
  const [groupName, setGroupName] = useState(editingGroup?.name || '');
  const [groupLabelAr, setGroupLabelAr] = useState(editingGroup?.label_ar || '');
  const [groupDescription, setGroupDescription] = useState(editingGroup?.description || '');
  const [groupDepartment, setGroupDepartment] = useState(editingGroup?.department || '');
  const [groupDefaultScope, setGroupDefaultScope] = useState<DataScope>(
    (editingGroup?.default_scope as DataScope) || 'group'
  );
  const [groupRoles, setGroupRoles] = useState<string[]>(editingGroup?.roles || ['analyst']);
  const [groupMembers, setGroupMembers] = useState<string[]>(editingGroup?.members || []);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupName.trim() || !groupLabelAr.trim()) {
      setError('الاسم البرمجي والاسم العربي مطلوبان.');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      await onSave({
        name: groupName.trim(),
        label_ar: groupLabelAr.trim(),
        description: groupDescription.trim(),
        department: groupDepartment.trim(),
        default_scope: groupDefaultScope,
        roles: groupRoles,
        members: groupMembers,
      });
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'فشل حفظ مجموعة العمل.');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleRole = (roleId: string) => {
    if (groupRoles.includes(roleId)) {
      setGroupRoles(groupRoles.filter((r) => r !== roleId));
    } else {
      setGroupRoles([...groupRoles, roleId]);
    }
  };

  const toggleMember = (username: string) => {
    if (groupMembers.includes(username)) {
      setGroupMembers(groupMembers.filter((m) => m !== username));
    } else {
      setGroupMembers([...groupMembers, username]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl border-white/15 overflow-hidden rounded-2xl bg-dark-900">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-emerald-400" />
            <span>{editingGroup ? `تعديل مجموعة: ${editingGroup.label_ar}` : 'إنشاء مجموعة عمل جديدة'}</span>
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
                disabled={editingGroup !== null}
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                placeholder="مثال: tier2_incident_responders"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-emerald-500 focus:outline-none disabled:opacity-50"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                الاسم المعروض (العربية)
              </label>
              <input
                type="text"
                required
                value={groupLabelAr}
                onChange={(e) => setGroupLabelAr(e.target.value)}
                placeholder="مثال: فريق الاستجابة للحوادث المستوى 2"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-emerald-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                القسم التابع له (Department)
              </label>
              <input
                type="text"
                value={groupDepartment}
                onChange={(e) => setGroupDepartment(e.target.value)}
                placeholder="مثال: Cyber Defense Center"
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-emerald-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">
                نطاق البيانات الافتراضي
              </label>
              <select
                value={groupDefaultScope}
                onChange={(e) => setGroupDefaultScope(e.target.value as DataScope)}
                className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-emerald-500 focus:outline-none"
              >
                {scopes.map((s) => (
                  <option key={s.scope} value={s.scope}>
                    {s.label_ar} ({s.scope})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">الوصف</label>
            <textarea
              value={groupDescription}
              onChange={(e) => setGroupDescription(e.target.value)}
              rows={2}
              className="w-full px-3 py-2.5 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-emerald-500 focus:outline-none resize-none"
            />
          </div>

          {/* Group Roles */}
          <div className="pt-2 border-t border-white/10 space-y-2">
            <label className="block text-xs font-bold text-slate-300">
              الأدوار المورثة لأعضاء المجموعة (تمنح صلاحياتها لجميع الأعضاء):
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {roles.map((r) => {
                const checked = groupRoles.includes(r.id);
                return (
                  <label
                    key={r.id}
                    className={`flex items-center gap-2 p-2.5 rounded-xl border text-xs cursor-pointer transition-all ${
                      checked
                        ? 'bg-blue-500/20 border-blue-500/35 text-blue-200'
                        : 'bg-white/5 border-white/5 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleRole(r.id)}
                      className="rounded text-blue-500 bg-dark-950 border-white/20"
                    />
                    <span className="truncate">{r.label_ar}</span>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Group Members */}
          <div className="pt-2 border-t border-white/10 space-y-2">
            <label className="block text-xs font-bold text-slate-300">
              أعضاء المجموعة ({groupMembers.length} محدد):
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 max-h-48 overflow-y-auto p-2 bg-black/40 rounded-xl border border-white/5">
              {users.map((u) => {
                const checked = groupMembers.includes(u.username);
                return (
                  <label
                    key={u.id}
                    className={`flex items-center gap-2 p-2 rounded-lg text-xs cursor-pointer transition-all ${
                      checked
                        ? 'bg-emerald-500/20 border border-emerald-500/30 text-emerald-200'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleMember(u.username)}
                      className="rounded text-emerald-500 bg-dark-950 border-white/20"
                    />
                    <span className="truncate font-mono">{u.username}</span>
                  </label>
                );
              })}
            </div>
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
              className="px-6 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-lg shadow-emerald-600/20 transition-all disabled:opacity-50"
            >
              {submitting ? 'جارٍ الحفظ...' : 'حفظ المجموعة'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

