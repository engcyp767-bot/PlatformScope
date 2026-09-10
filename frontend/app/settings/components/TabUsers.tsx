import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Users, UserPlus, Shield, Check, X, Trash2, Edit3, UserCheck,
  UserX, ExternalLink, RefreshCw, KeyRound, Lock
} from 'lucide-react';
import { User, PermissionCode } from '../../../lib/types';
import { getAdminUsers, createAdminUser, updateAdminUser, deleteAdminUser } from '../../../lib/api';
import { SectionCard, Field, inputClass, ConfirmModal } from './FormControls';

export function TabUsers() {
  const [users, setUsers] = useState<User[]>([]);
  const [catalog, setCatalog] = useState<{
    groups: { name: string; permissions: { code: PermissionCode; label: string }[] }[];
    presets: Record<string, PermissionCode[]>;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);

  // Form states
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [selectedPermissions, setSelectedPermissions] = useState<PermissionCode[]>([]);
  const [active, setActive] = useState(true);
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await getAdminUsers();
      setUsers(res.users || []);
      setCatalog(res.catalog || null);
    } catch (err: any) {
      setError(err.message || 'تعذر تحميل المستخدمين.');
    }
    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  const openCreateModal = () => {
    setEditingUser(null);
    setUsername('');
    setDisplayName('');
    setPassword('');
    setSelectedPermissions(catalog?.presets.analyst || []);
    setActive(true);
    setFormError('');
    setModalOpen(true);
  };

  const openEditModal = (user: User) => {
    setEditingUser(user);
    setUsername(user.username);
    setDisplayName(user.display_name);
    setPassword('');
    setSelectedPermissions(user.permissions || []);
    setActive(user.active);
    setFormError('');
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    setSubmitting(true);

    try {
      if (editingUser) {
        await updateAdminUser(editingUser.id, {
          username,
          display_name: displayName,
          password: password || undefined,
          permissions: selectedPermissions,
          active,
        });
      } else {
        if (!password) {
          throw new Error('كلمة المرور مطلوبة لإنشاء مستخدم جديد.');
        }
        await createAdminUser({
          username,
          display_name: displayName,
          password,
          permissions: selectedPermissions,
          active,
        });
      }
      setModalOpen(false);
      loadData();
    } catch (err: any) {
      setFormError(err.message || 'فشل حفظ بيانات المستخدم.');
    }
    setSubmitting(false);
  };

  const handleDelete = async () => {
    if (!deleteTargetId) return;
    try {
      await deleteAdminUser(deleteTargetId);
      setDeleteTargetId(null);
      loadData();
    } catch (err: any) {
      alert(err.message || 'فشل حذف المستخدم.');
    }
  };

  const togglePermission = (code: PermissionCode) => {
    setSelectedPermissions((prev) =>
      prev.includes(code) ? prev.filter((p) => p !== code) : [...prev, code]
    );
  };

  const applyPreset = (presetName: string) => {
    if (catalog?.presets[presetName]) {
      setSelectedPermissions(catalog.presets[presetName]);
    }
  };

  const adminCount = users.filter((u) => u.permissions?.includes('users.manage')).length;
  const analystCount = users.filter((u) => !u.permissions?.includes('users.manage') && u.permissions?.includes('flowscope.analyze')).length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4 text-center">
          <div className="text-xs text-slate-400">إجمالي الحسابات</div>
          <div className="text-2xl font-black text-white mt-1">{users.length}</div>
        </div>
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4 text-center">
          <div className="text-xs text-slate-400">الحسابات النشطة</div>
          <div className="text-2xl font-black text-emerald-400 mt-1">
            {users.filter((u) => u.active).length}
          </div>
        </div>
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4 text-center">
          <div className="text-xs text-slate-400">مديرو النظام (Admins)</div>
          <div className="text-2xl font-black text-purple-400 mt-1">{adminCount}</div>
        </div>
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4 text-center">
          <div className="text-xs text-slate-400">المحللون الأمنيون</div>
          <div className="text-2xl font-black text-cyan-400 mt-1">{analystCount}</div>
        </div>
      </div>

      {/* Users Table Card */}
      <SectionCard
        title="دليل المستخدمين والصلاحيات (RBAC)"
        subtitle="إدارة حسابات المحللين وتعيين مصفوفة الصلاحيات الـ 21 وأدوار الوصول"
        action={
          <div className="flex items-center gap-2">
            <Link
              href="/admin"
              className="px-3 py-2 rounded-xl border border-white/10 text-xs font-semibold text-slate-300 hover:bg-white/5 flex items-center gap-1.5 transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              الواجهة الموسعة
            </Link>
            <button
              type="button"
              onClick={openCreateModal}
              className="px-3.5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black flex items-center gap-1.5 transition-colors"
            >
              <UserPlus className="w-4 h-4" />
              إضافة مستخدم
            </button>
          </div>
        }
      >
        {loading ? (
          <div className="py-12 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            جارٍ تحميل بيانات المستخدمين...
          </div>
        ) : error ? (
          <div className="p-4 rounded-xl border border-rose-500/20 bg-rose-500/5 text-xs text-rose-300">
            {error}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs">
              <thead>
                <tr className="border-b border-white/10 text-slate-400 font-semibold">
                  <th className="pb-3 px-3">المستخدم</th>
                  <th className="pb-3 px-3">الاسم المعروض</th>
                  <th className="pb-3 px-3">الحالة</th>
                  <th className="pb-3 px-3">الدور / الصلاحيات</th>
                  <th className="pb-3 px-3 text-left">الإجراءات</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {users.map((user) => {
                  const isAdmin = user.permissions?.includes('users.manage');
                  return (
                    <tr key={user.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-3 font-bold text-white flex items-center gap-2">
                        <div className="w-7 h-7 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-300">
                          {user.username.charAt(0).toUpperCase()}
                        </div>
                        {user.username}
                      </td>
                      <td className="py-3 px-3 text-slate-300">{user.display_name}</td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            user.active
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25'
                              : 'bg-rose-500/10 text-rose-400 border border-rose-500/25'
                          }`}
                        >
                          {user.active ? (
                            <>
                              <UserCheck className="w-3 h-3" /> نشط
                            </>
                          ) : (
                            <>
                              <UserX className="w-3 h-3" /> معطل
                            </>
                          )}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[10px] font-bold ${
                            isAdmin
                              ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30'
                              : 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                          }`}
                        >
                          <Shield className="w-3 h-3" />
                          {isAdmin ? 'مدير النظام (Admin)' : `محلل أمني (${user.permissions?.length || 0})`}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-left">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => openEditModal(user)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-white/5 transition-colors"
                            title="تعديل المستخدم"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteTargetId(user.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                            title="حذف المستخدم"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      {/* Create / Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in overflow-y-auto">
          <div className="glass-panel max-w-2xl w-full p-6 sm:p-7 rounded-2xl border border-white/15 space-y-5 my-8">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Users className="w-5 h-5 text-cyan-400" />
                {editingUser ? 'تعديل بيانات المستخدم والصلاحيات' : 'إنشاء حساب مستخدم جديد'}
              </h3>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-xl border border-rose-500/25 bg-rose-500/10 text-xs text-rose-300">
                {formError}
              </div>
            )}

            <form onSubmit={handleSave} className="space-y-5">
              <div className="grid sm:grid-cols-2 gap-4">
                <Field label="اسم المستخدم (Username)" required>
                  <input
                    type="text"
                    dir="ltr"
                    className={inputClass}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                </Field>
                <Field label="الاسم المعروض (Display Name)" required>
                  <input
                    type="text"
                    className={inputClass}
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    required
                  />
                </Field>
              </div>

              <Field
                label={editingUser ? 'كلمة المرور الجديدة (اتركها فارغة للإبقاء على الحالية)' : 'كلمة المرور'}
                required={!editingUser}
              >
                <input
                  type="password"
                  dir="ltr"
                  className={inputClass}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required={!editingUser}
                />
              </Field>

              {/* Role Presets */}
              <div className="space-y-2">
                <label className="block text-xs font-bold text-slate-300">الأدوار الجاهزة (Presets)</label>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => applyPreset('administrator')}
                    className="px-3 py-1.5 rounded-xl border border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 text-xs font-bold text-purple-300 transition-colors"
                  >
                    مدير النظام (Administrator)
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('analyst')}
                    className="px-3 py-1.5 rounded-xl border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-xs font-bold text-cyan-300 transition-colors"
                  >
                    محلل أمني (Analyst)
                  </button>
                  <button
                    type="button"
                    onClick={() => applyPreset('viewer')}
                    className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-bold text-slate-300 transition-colors"
                  >
                    مشاهد فقط (Viewer)
                  </button>
                </div>
              </div>

              {/* Permissions Checklist */}
              {catalog && (
                <div className="space-y-3 pt-2">
                  <label className="block text-xs font-bold text-slate-300">
                    مصفوفة الصلاحيات التفصيلية ({selectedPermissions.length} محددة)
                  </label>
                  <div className="max-h-60 overflow-y-auto space-y-3 p-3 rounded-xl border border-white/10 bg-dark-950/60 pr-2">
                    {catalog.groups.map((group) => (
                      <div key={group.name} className="space-y-1.5">
                        <div className="text-[11px] font-bold text-slate-400 border-b border-white/5 pb-1">
                          {group.name}
                        </div>
                        <div className="grid sm:grid-cols-2 gap-1.5">
                          {group.permissions.map((perm) => {
                            const isChecked = selectedPermissions.includes(perm.code);
                            return (
                              <label
                                key={perm.code}
                                className={`flex items-center gap-2 p-2 rounded-lg text-xs cursor-pointer select-none transition-colors ${
                                  isChecked
                                    ? 'bg-cyan-500/10 text-cyan-200'
                                    : 'text-slate-400 hover:bg-white/5'
                                }`}
                              >
                                <input
                                  type="checkbox"
                                  checked={isChecked}
                                  onChange={() => togglePermission(perm.code)}
                                  className="rounded border-white/20 text-cyan-500 focus:ring-cyan-500/30"
                                />
                                <span className="truncate">{perm.label}</span>
                              </label>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-4 border-t border-white/10">
                <label className="flex items-center gap-2 text-xs font-semibold text-slate-300 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={active}
                    onChange={(e) => setActive(e.target.checked)}
                    className="rounded border-white/20 text-cyan-500 focus:ring-cyan-500/30"
                  />
                  حساب نشط ومصرح له بالدخول
                </label>

                <div className="flex items-center gap-2.5">
                  <button
                    type="button"
                    onClick={() => setModalOpen(false)}
                    className="px-4 py-2 rounded-xl border border-white/10 text-xs font-bold text-slate-400 hover:text-white transition-colors"
                  >
                    إلغاء
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black transition-colors disabled:opacity-50"
                  >
                    {submitting ? 'جارٍ الحفظ...' : editingUser ? 'حفظ التعديلات' : 'إنشاء الحساب'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={Boolean(deleteTargetId)}
        title="تأكيد حذف الحساب"
        message="هل أنت متأكد من حذف هذا الحساب نهائيًا؟ لن يتمكن المستخدم من الوصول للمنصة بعد الآن."
        confirmText="حذف المستخدم"
        cancelText="إلغاء"
        isDanger
        onConfirm={handleDelete}
        onCancel={() => setDeleteTargetId(null)}
      />
    </div>
  );
}
