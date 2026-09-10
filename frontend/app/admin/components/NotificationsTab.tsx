'use client';

import React, { useState, useEffect } from 'react';
import {
  Bell,
  CheckCheck,
  Plus,
  RefreshCw,
  AlertCircle,
  AlertTriangle,
  Info,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  Send,
  X,
} from 'lucide-react';
import { AppNotification } from '../../../lib/types';
import {
  getNotifications,
  markNotificationRead,
  markAllNotificationsRead,
  createNotification,
} from '../../../lib/api';

export function NotificationsTab() {
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [unreadOnly, setUnreadOnly] = useState<boolean>(false);
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [creating, setCreating] = useState<boolean>(false);

  // Form state
  const [newTitle, setNewTitle] = useState('');
  const [newMessage, setNewMessage] = useState('');
  const [newCategory, setNewCategory] = useState('system');
  const [newSeverity, setNewSeverity] = useState('info');
  const [newTargetUser, setNewTargetUser] = useState('*');
  const [newLink, setNewLink] = useState('');

  const loadNotifications = async () => {
    try {
      setLoading(true);
      const res = await getNotifications({
        unread: unreadOnly ? true : undefined,
        category: selectedCategory !== 'all' ? selectedCategory : undefined,
        limit: 100,
      });
      setNotifications(res.notifications || []);
      setUnreadCount(res.unread_count || 0);
    } catch (err) {
      console.error('Failed to load notifications', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadNotifications();
  }, [selectedCategory, selectedSeverity, unreadOnly]);

  const handleMarkRead = async (id: string) => {
    try {
      await markNotificationRead(id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, is_read: true, read_at: new Date().toISOString() } : n))
      );
      setUnreadCount((c) => Math.max(0, c - 1));
    } catch (err) {
      console.error('Failed to mark notification as read', err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await markAllNotificationsRead();
      setNotifications((prev) =>
        prev.map((n) => ({ ...n, is_read: true, read_at: new Date().toISOString() }))
      );
      setUnreadCount(0);
    } catch (err) {
      console.error('Failed to mark all notifications as read', err);
    }
  };

  const handleCreateNotification = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newMessage.trim()) return;

    try {
      setCreating(true);
      await createNotification({
        title: newTitle.trim(),
        message: newMessage.trim(),
        category: newCategory,
        severity: newSeverity,
        target_user: newTargetUser.trim() || '*',
        link: newLink.trim() || undefined,
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewMessage('');
      setNewLink('');
      await loadNotifications();
    } catch (err) {
      console.error('Failed to create notification', err);
    } finally {
      setCreating(false);
    }
  };

  const filteredNotifications = notifications.filter((n) => {
    if (selectedSeverity !== 'all' && n.severity !== selectedSeverity) return false;
    return true;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return {
          icon: ShieldAlert,
          bg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
          label: 'حرج جداً',
        };
      case 'warning':
        return {
          icon: AlertTriangle,
          bg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
          label: 'تحذير',
        };
      case 'success':
        return {
          icon: CheckCircle2,
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
          label: 'نجاح',
        };
      default:
        return {
          icon: Info,
          bg: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
          label: 'معلومات',
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-2xl bg-dark-900/60 border border-white/10 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Bell className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold font-heading text-white">مركز التنبيهات والإشعارات</h2>
              {unreadCount > 0 && (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 border border-rose-500/30 text-rose-300">
                  {unreadCount} غير مقروء
                </span>
              )}
            </div>
            <p className="text-sm text-slate-400 mt-0.5">
              إدارة الإشعارات المركزية، التنبيهات الأمنية الحية، والبث الإداري لمستخدمي المنصة
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={loadNotifications}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-xs font-medium text-slate-300 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>تحديث</span>
          </button>
          {unreadCount > 0 && (
            <button
              onClick={handleMarkAllRead}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 text-xs font-medium text-emerald-300 transition-colors"
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>تحديد الكل كمقروء</span>
            </button>
          )}
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-xs font-semibold text-white shadow-lg shadow-purple-600/20 transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>بث إشعار جديد</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3 p-4 rounded-xl bg-dark-900/40 border border-white/5">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          <span className="text-xs text-slate-400 ml-2">الفئة:</span>
          {['all', 'system', 'security', 'task', 'incident', 'audit'].map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                selectedCategory === cat
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                  : 'bg-white/5 text-slate-400 hover:text-slate-200 border border-transparent'
              }`}
            >
              {cat === 'all'
                ? 'الكل'
                : cat === 'system'
                ? 'النظام'
                : cat === 'security'
                ? 'الأمان'
                : cat === 'task'
                ? 'المهام'
                : cat === 'incident'
                ? 'الحوادث'
                : 'التدقيق'}
            </button>
          ))}
        </div>

        <div className="h-4 w-px bg-white/10 hidden md:block" />

        <div className="flex items-center gap-1.5">
          <span className="text-xs text-slate-400 ml-2">الأهمية:</span>
          {['all', 'critical', 'warning', 'info', 'success'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                selectedSeverity === sev
                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                  : 'bg-white/5 text-slate-400 hover:text-slate-200 border border-transparent'
              }`}
            >
              {sev === 'all'
                ? 'الكل'
                : sev === 'critical'
                ? 'حرج'
                : sev === 'warning'
                ? 'تحذير'
                : sev === 'info'
                ? 'معلومات'
                : 'نجاح'}
            </button>
          ))}
        </div>

        <div className="mr-auto flex items-center gap-2">
          <button
            onClick={() => setUnreadOnly(!unreadOnly)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
              unreadOnly
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'bg-white/5 text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            فقط غير المقروءة
          </button>
        </div>
      </div>

      {/* Notifications List */}
      <div className="space-y-3">
        {filteredNotifications.length === 0 ? (
          <div className="text-center py-16 p-6 rounded-2xl bg-dark-900/40 border border-white/5">
            <div className="w-12 h-12 mx-auto rounded-full bg-white/5 flex items-center justify-center text-slate-500 mb-3">
              <Bell className="w-6 h-6" />
            </div>
            <h3 className="text-base font-semibold text-slate-300">لا توجد إشعارات تطابق المعايير</h3>
            <p className="text-xs text-slate-500 mt-1">جميع التنبيهات الحالية مقروءة أو تم فلترتها</p>
          </div>
        ) : (
          filteredNotifications.map((notif) => {
            const badge = getSeverityBadge(notif.severity);
            const Icon = badge.icon;
            return (
              <div
                key={notif.id}
                className={`p-4 rounded-xl border transition-all flex flex-col md:flex-row md:items-start justify-between gap-4 ${
                  notif.is_read
                    ? 'bg-dark-900/30 border-white/5 opacity-80'
                    : 'bg-dark-900/70 border-purple-500/20 shadow-md shadow-purple-500/5'
                }`}
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div className={`p-2 rounded-lg border shrink-0 mt-0.5 ${badge.bg}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h4 className={`text-sm font-semibold ${notif.is_read ? 'text-slate-300' : 'text-white'}`}>
                        {notif.title}
                      </h4>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${badge.bg}`}>
                        {badge.label}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono bg-white/5 px-2 py-0.5 rounded">
                        {notif.category}
                      </span>
                      {!notif.is_read && (
                        <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                      )}
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed break-words whitespace-pre-line">
                      {notif.message}
                    </p>
                    <div className="flex items-center gap-3 text-[11px] text-slate-500 pt-1">
                      <span>{new Date(notif.created_at).toLocaleString('ar-SA')}</span>
                      <span>•</span>
                      <span>المستهدف: {notif.target_user === '*' ? 'جميع المستخدمين' : notif.target_user}</span>
                      {notif.is_read && notif.read_at && (
                        <>
                          <span>•</span>
                          <span className="text-slate-400">
                            تمت القراءة: {new Date(notif.read_at).toLocaleTimeString('ar-SA')}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 self-end md:self-start">
                  {notif.link && (
                    <a
                      href={notif.link}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs text-purple-300 border border-purple-500/20 transition-colors"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>فتح الرابط</span>
                    </a>
                  )}
                  {!notif.is_read && (
                    <button
                      onClick={() => handleMarkRead(notif.id)}
                      className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs text-slate-300 transition-colors"
                      title="تحديد كمقروء"
                    >
                      <CheckCheck className="w-3.5 h-3.5" />
                      <span>مقروء</span>
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Broadcast Creation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-2xl bg-dark-900 border border-white/15 shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-2 text-purple-400">
                <Send className="w-5 h-5" />
                <h3 className="text-lg font-bold text-white">بث إشعار أمني أو إداري جديد</h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateNotification} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">عنوان التنبيه</label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="مثال: تحديث أمني عاجل على محرك Sigma"
                  className="w-full px-3 py-2 rounded-xl bg-dark-950 border border-white/10 text-white text-sm focus:outline-none focus:border-purple-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">نص الرسالة</label>
                <textarea
                  required
                  rows={3}
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  placeholder="اكتب تفاصيل التنبيه أو التعليمات الموجهة للمحللين..."
                  className="w-full px-3 py-2 rounded-xl bg-dark-950 border border-white/10 text-white text-sm focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">الفئة</label>
                  <select
                    value={newCategory}
                    onChange={(e) => setNewCategory(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-dark-950 border border-white/10 text-white text-sm focus:outline-none focus:border-purple-500"
                  >
                    <option value="system">نظام (System)</option>
                    <option value="security">أمان (Security)</option>
                    <option value="task">مهام (Task)</option>
                    <option value="incident">حوادث (Incident)</option>
                    <option value="audit">تدقيق (Audit)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">الأهمية</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-dark-950 border border-white/10 text-white text-sm focus:outline-none focus:border-purple-500"
                  >
                    <option value="info">معلومات (Info)</option>
                    <option value="warning">تحذير (Warning)</option>
                    <option value="critical">حرج (Critical)</option>
                    <option value="success">نجاح (Success)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">المستهدف (* للجميع)</label>
                  <input
                    type="text"
                    value={newTargetUser}
                    onChange={(e) => setNewTargetUser(e.target.value)}
                    placeholder="* أو اسم المستخدم"
                    className="w-full px-3 py-2 rounded-xl bg-dark-950 border border-white/10 text-white text-sm focus:outline-none focus:border-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">رابط الإحالة (اختياري)</label>
                  <input
                    type="text"
                    value={newLink}
                    onChange={(e) => setNewLink(e.target.value)}
                    placeholder="/incidents أو /admin?tab=jobs"
                    className="w-full px-3 py-2 rounded-xl bg-dark-950 border border-white/10 text-white text-sm focus:outline-none focus:border-purple-500"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-4 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl bg-white/5 hover:bg-white/10 text-xs font-medium text-slate-300 transition-colors"
                >
                  إلغاء
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-xs font-semibold text-white transition-all shadow-lg shadow-purple-600/25"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{creating ? 'جاري الإرسال...' : 'إرسال وبث الآن'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
