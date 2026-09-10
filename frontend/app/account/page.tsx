'use client';

import React, { useEffect, useState } from 'react';
import { Navbar } from '../../components/Navbar';
import { User, Lock, CheckCircle2, AlertCircle, Shield, Key, Layers, ChevronDown, ChevronUp } from 'lucide-react';
import { fetchApi, getAuthStatus, getMyAccessProfile } from '../../lib/api';
import { AccessProfile } from '../../lib/types';
import { useTranslation } from '../../lib/i18n';

export default function AccountPage() {
  const { t } = useTranslation();
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [accessProfile, setAccessProfile] = useState<AccessProfile | null>(null);
  const [showPermsList, setShowPermsList] = useState(false);
  const [displayName, setDisplayName] = useState('');
  const [username, setUsername] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    getAuthStatus().then((res) => {
      if (res.authenticated && res.user) {
        setCurrentUser(res.user);
        setDisplayName(res.user.display_name);
        setUsername(res.user.username);
      }
    });
    getMyAccessProfile()
      .then((profile) => setAccessProfile(profile))
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (newPassword && newPassword !== confirmPassword) {
      setError(t('account.pass_mismatch'));
      return;
    }

    setLoading(true);
    try {
      await fetchApi('/api/auth/account', {
        method: 'POST',
        body: JSON.stringify({
          current_password: currentPassword,
          username,
          display_name: displayName,
          new_password: newPassword || undefined,
        }),
      });
      setSuccess(t('account.success_update'));
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : t('account.fail_update'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-1 max-w-2xl w-full mx-auto px-4 sm:px-6 py-10">
        <div className="mb-8">
          <div className="flex items-center gap-2">
            <User className="w-5 h-5 text-blue-400" />
            <span className="text-xs font-bold text-blue-400 uppercase tracking-wider font-heading">
              PROFILE & SECURITY
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
            {t('account.title')}
          </h1>
        </div>

        {/* Access Profile & Data Scope Card */}
        {accessProfile && (
          <div className="glass-panel p-6 mb-8 border border-white/10 rounded-2xl">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-purple-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-heading">
                ملف الصلاحيات ونطاق البيانات (My Access Profile)
              </h2>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-xl bg-white/5 border border-white/5 mb-4">
              <div>
                <span className="text-[11px] text-slate-400 block">الدور المخصص</span>
                <span className="font-bold text-blue-400 text-xs">
                  {accessProfile.role_label_ar} ({accessProfile.role_name})
                </span>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block">نطاق البيانات</span>
                <span className="font-bold text-amber-300 text-xs">
                  {accessProfile.scope_label_ar}
                </span>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block">القسم التابع</span>
                <span className="font-bold text-emerald-400 text-xs">
                  {accessProfile.department || 'عام / غير محدد'}
                </span>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block">عدد الصلاحيات</span>
                <span className="font-bold text-purple-400 text-xs font-mono">
                  {accessProfile.permission_count} صلاحية
                </span>
              </div>
            </div>

            {accessProfile.groups && accessProfile.groups.length > 0 && (
              <div className="mb-4">
                <span className="text-xs text-slate-400 block mb-1.5 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-emerald-400" />
                  <span>مجموعات العمل المنضم إليها:</span>
                </span>
                <div className="flex flex-wrap gap-2">
                  {accessProfile.groups.map((g) => (
                    <span
                      key={g.id}
                      className="px-2.5 py-1 rounded-lg text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-medium"
                    >
                      {g.label_ar}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div>
              <button
                type="button"
                onClick={() => setShowPermsList(!showPermsList)}
                className="flex items-center justify-between w-full text-xs font-bold text-slate-300 hover:text-white py-1 transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Key className="w-4 h-4 text-purple-400" />
                  <span>استعراض مصفوفة الصلاحيات الفعّالة بالتفصيل</span>
                </span>
                {showPermsList ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>

              {showPermsList && (
                <div className="mt-3 p-4 rounded-xl bg-black/40 border border-white/5 max-h-48 overflow-y-auto flex flex-wrap gap-1.5">
                  {accessProfile.effective_permissions.map((p) => (
                    <span
                      key={p}
                      className="px-2 py-0.5 rounded-lg text-[10px] font-mono bg-white/5 border border-white/10 text-slate-300"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        <div className="glass-panel p-8">
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-3 text-rose-300 text-sm">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="mb-6 p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-300 text-sm">
              <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1.5">{t('account.username_label')}</label>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1.5">{t('account.display_name_label')}</label>
                <input
                  type="text"
                  required
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500"
                />
              </div>
            </div>

            <div className="pt-4 border-t border-white/10 space-y-4">
              <div className="text-xs font-bold text-slate-300">{t('account.change_pass')}</div>

              <div>
                <label className="block text-xs text-slate-400 mb-1.5">
                  {t('account.current_pass_label')}
                </label>
                <input
                  type="password"
                  required
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-3 py-2.5 rounded-xl bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-slate-400 mb-1.5">{t('account.new_pass_label')}</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder={t('account.new_pass_hint')}
                    className="w-full px-3 py-2.5 rounded-xl bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500"
                  />
                </div>

                <div>
                  <label className="block text-xs text-slate-400 mb-1.5">{t('account.confirm_pass_label')}</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder={t('account.confirm_pass_placeholder')}
                    className="w-full px-3 py-2.5 rounded-xl bg-dark-950/60 border border-white/10 text-xs text-white placeholder-slate-500"
                  />
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-white/10 flex justify-end">
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 rounded-xl bg-primary hover:bg-primary-hover text-dark-950 font-bold text-xs shadow-lg shadow-primary/20 transition-all disabled:opacity-50"
              >
                {loading ? t('account.saving') : t('account.save_changes')}
              </button>
            </div>
          </form>
        </div>
      </main>
    </div>
  );
}
