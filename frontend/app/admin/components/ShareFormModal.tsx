'use client';

import React, { useState } from 'react';
import { Share2, X, AlertTriangle } from 'lucide-react';
import { User, Group } from '../../../lib/types';

interface ShareFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  users: User[];
  groups: Group[];
  onSave: (payload: {
    resource_type: string;
    resource_id: string;
    grantee_type: 'user' | 'group' | 'department';
    grantee_id: string;
    permissions: string[];
    expires_at: string | null;
  }) => Promise<void>;
}

export function ShareFormModal({
  isOpen,
  onClose,
  users,
  groups,
  onSave,
}: ShareFormModalProps) {
  const [resourceType, setResourceType] = useState('incident');
  const [resourceId, setResourceId] = useState('');
  const [granteeType, setGranteeType] = useState<'user' | 'group' | 'department'>('user');
  const [granteeId, setGranteeId] = useState(users.length > 0 ? users[0].username : '');
  const [permissions, setPermissions] = useState<string[]>(['view']);
  const [expiryPreset, setExpiryPreset] = useState<'never' | '24h' | '7d' | '30d'>('never');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resourceId.trim()) {
      setError('معرف المورد مطلوب.');
      return;
    }
    if (!granteeId.trim()) {
      setError('يجب تحديد الجهة أو المستخدم المستفيد.');
      return;
    }
    if (permissions.length === 0) {
      setError('يجب اختيار صلاحية واحدة على الأقل للمشاركة.');
      return;
    }

    setSubmitting(true);
    setError('');

    let expiresAt: string | null = null;
    const nowMs = Date.now();
    if (expiryPreset === '24h') {
      expiresAt = new Date(nowMs + 24 * 60 * 60 * 1000).toISOString();
    } else if (expiryPreset === '7d') {
      expiresAt = new Date(nowMs + 7 * 24 * 60 * 60 * 1000).toISOString();
    } else if (expiryPreset === '30d') {
      expiresAt = new Date(nowMs + 30 * 24 * 60 * 60 * 1000).toISOString();
    }

    try {
      await onSave({
        resource_type: resourceType,
        resource_id: resourceId.trim(),
        grantee_type: granteeType,
        grantee_id: granteeId.trim(),
        permissions,
        expires_at: expiresAt,
      });
      onClose();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'حدث خطأ أثناء حفظ المشاركة.');
    } finally {
      setSubmitting(false);
    }
  };

  const togglePermission = (perm: string) => {
    if (permissions.includes(perm)) {
      setPermissions(permissions.filter((p) => p !== perm));
    } else {
      setPermissions([...permissions, perm]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-dark-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="glass-panel w-full max-w-lg shadow-2xl border-white/15 overflow-hidden rounded-2xl bg-dark-900">
        <div className="p-6 border-b border-white/10 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Share2 className="w-5 h-5 text-amber-400" />
            <span>مشاركة مورد أمني جديد</span>
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

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">نوع المورد</label>
              <select
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                className="w-full px-3 py-2 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-amber-500 focus:outline-none"
              >
                <option value="incident">حادث أمني (Incident)</option>
                <option value="asset">أصل أمني (Asset)</option>
                <option value="analysis_job">مهمة تحليل (Job)</option>
                <option value="report">تقرير أمني (Report)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">معرف المورد</label>
              <input
                type="text"
                required
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
                placeholder="مثال: INC-2026-001 أو ID"
                className="w-full px-3 py-2 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-amber-500 focus:outline-none font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">المشاركة مع</label>
              <select
                value={granteeType}
                onChange={(e) => {
                  const gt = e.target.value as 'user' | 'group' | 'department';
                  setGranteeType(gt);
                  if (gt === 'user' && users.length > 0) setGranteeId(users[0].username);
                  else if (gt === 'group' && groups.length > 0) setGranteeId(groups[0].id);
                  else setGranteeId('');
                }}
                className="w-full px-3 py-2 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-amber-500 focus:outline-none"
              >
                <option value="user">مستخدم محدد (User)</option>
                <option value="group">مجموعة عمل (Group)</option>
                <option value="department">قسم كامل (Department)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-300 mb-1.5">الجهة المستفيدة</label>
              {granteeType === 'user' ? (
                <select
                  value={granteeId}
                  onChange={(e) => setGranteeId(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-amber-500 focus:outline-none"
                >
                  {users.map((u) => (
                    <option key={u.id} value={u.username}>
                      {u.display_name} ({u.username})
                    </option>
                  ))}
                </select>
              ) : granteeType === 'group' ? (
                <select
                  value={granteeId}
                  onChange={(e) => setGranteeId(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-amber-500 focus:outline-none"
                >
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.label_ar} ({g.name})
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  required
                  value={granteeId}
                  onChange={(e) => setGranteeId(e.target.value)}
                  placeholder="مثال: SOC, IT"
                  className="w-full px-3 py-2 rounded-xl bg-dark-950/80 border border-white/10 text-xs text-white focus:border-amber-500 focus:outline-none"
                />
              )}
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">الصلاحيات الممنوحة</label>
            <div className="grid grid-cols-4 gap-2">
              {[
                { code: 'view', label: 'قراءة' },
                { code: 'comment', label: 'تعليق' },
                { code: 'edit', label: 'تعديل' },
                { code: 'export', label: 'تصدير' },
              ].map((p) => {
                const checked = permissions.includes(p.code);
                return (
                  <label
                    key={p.code}
                    className={`flex items-center justify-center gap-1.5 p-2 rounded-xl border text-xs cursor-pointer transition-all ${
                      checked
                        ? 'bg-amber-500/20 border-amber-500/40 text-amber-300 font-bold'
                        : 'bg-white/5 border-white/10 text-slate-400 hover:text-white'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => togglePermission(p.code)}
                      className="rounded text-amber-500 bg-dark-950 border-white/20"
                    />
                    <span>{p.label}</span>
                  </label>
                );
              })}
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-300 mb-1.5">
              مدة الصلاحية التلقائية (TTL Expiry)
            </label>
            <div className="grid grid-cols-4 gap-2">
              {[
                { code: 'never', label: 'دائم' },
                { code: '24h', label: '24 ساعة' },
                { code: '7d', label: '7 أيام' },
                { code: '30d', label: '30 يوماً' },
              ].map((item) => (
                <button
                  type="button"
                  key={item.code}
                  onClick={() => setExpiryPreset(item.code as 'never' | '24h' | '7d' | '30d')}
                  className={`py-2 rounded-xl text-xs font-bold border transition-all ${
                    expiryPreset === item.code
                      ? 'bg-amber-500/20 border-amber-500/40 text-amber-300 shadow-sm'
                      : 'bg-white/5 border-white/5 text-slate-400 hover:text-white'
                  }`}
                >
                  {item.label}
                </button>
              ))}
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
              className="px-6 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs shadow-lg shadow-amber-600/20 transition-all disabled:opacity-50"
            >
              {submitting ? 'جارٍ الحفظ...' : 'تأكيد المشاركة'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

