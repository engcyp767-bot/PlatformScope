'use client';

import React, { useEffect, useState } from 'react';
import { Navbar } from '../../components/Navbar';
import {
  Shield,
  Search,
  Plus,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import {
  fetchApi,
  getRoles,
  createCustomRole,
  updateCustomRole,
  deleteCustomRole,
  cloneRole,
  getGroups,
  createGroup,
  updateGroup,
  deleteGroup,
  getAvailableScopes,
  getMyShares,
  shareResource,
  revokeShare,
  simulateUserAccess,
} from '../../lib/api';
import {
  User,
  Role,
  Group,
  DataScope,
  ScopeInfo,
  ResourceShare,
  SimulatedAccess,
  PermissionCatalog,
} from '../../lib/types';
import { useTranslation } from '../../lib/i18n';

// Modular Components
import { AdminTab } from './components/types';
import { AdminNavTabs } from './components/AdminNavTabs';
import { UserManagementTab } from './components/UserManagementTab';
import { UserFormModal } from './components/UserFormModal';
import { RolesTab } from './components/RolesTab';
import { RoleFormModal } from './components/RoleFormModal';
import { CloneRoleModal } from './components/CloneRoleModal';
import { GroupsTab } from './components/GroupsTab';
import { GroupFormModal } from './components/GroupFormModal';
import { DataAccessTab } from './components/DataAccessTab';
import { SharesTab } from './components/SharesTab';
import { ShareFormModal } from './components/ShareFormModal';
import { AuditOverviewTab } from './components/AuditOverviewTab';
import { SettingsOverviewTab } from './components/SettingsOverviewTab';
import { HealthOverviewTab } from './components/HealthOverviewTab';
import { JobsTab } from './components/JobsTab';
import { NotificationsTab } from './components/NotificationsTab';
import { SimulationModal } from './components/SimulationModal';
import { LicensingTab } from './components/LicensingTab';

export default function AdminPage() {
  const { t, lang } = useTranslation();

  // Active tab: 'users' | 'roles' | 'groups' | 'data-access' | 'shares' | 'audit' | 'settings' | 'health'
  const [activeTab, setActiveTab] = useState<AdminTab>('users');

  // Data states
  const [users, setUsers] = useState<User[]>([]);
  const [catalog, setCatalog] = useState<PermissionCatalog | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [scopes, setScopes] = useState<ScopeInfo[]>([]);
  const [shares, setShares] = useState<ResourceShare[]>([]);

  // Loading & Filter states
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Modals state
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);

  const [roleModalOpen, setRoleModalOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);

  const [cloneModalOpen, setCloneModalOpen] = useState(false);
  const [cloneSourceRole, setCloneSourceRole] = useState<Role | null>(null);

  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<Group | null>(null);

  const [shareModalOpen, setShareModalOpen] = useState(false);

  const [simModalOpen, setSimModalOpen] = useState(false);
  const [simData, setSimData] = useState<SimulatedAccess | null>(null);
  const [simLoading, setSimLoading] = useState(false);

  // --------------------------------------------------------------------
  // Load All System Data
  // --------------------------------------------------------------------
  const loadAllData = async () => {
    setLoading(true);
    setLoadError('');
    try {
      const [usersRes, rolesRes, groupsRes, scopesRes, sharesRes] = await Promise.all([
        fetchApi('/api/admin/users'),
        getRoles(),
        getGroups(),
        getAvailableScopes(),
        getMyShares().catch(() => []),
      ]);
      setUsers(usersRes.users || []);
      setCatalog(usersRes.catalog || null);
      setRoles(rolesRes || []);
      setGroups(groupsRes || []);
      setScopes(scopesRes || []);
      setShares(sharesRes || []);
    } catch (err: unknown) {
      setLoadError(
        err instanceof Error ? err.message : 'تعذر تحميل بيانات الإدارة والتفويض من الخادم.'
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  // --------------------------------------------------------------------
  // User Actions
  // --------------------------------------------------------------------
  const handleSaveUser = async (payload: {
    username: string;
    display_name: string;
    password?: string;
    role_id: string;
    data_scope: DataScope;
    department: string;
    groups: string[];
    active: boolean;
    custom_permissions: string[];
  }) => {
    if (editingUser) {
      await fetchApi(`/api/admin/users/${editingUser.id}`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
    } else {
      await fetchApi('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
    }
    await loadAllData();
  };

  const handleDeleteUser = async (userId: string) => {
    if (
      !window.confirm('هل أنت متأكد من رغبتك في حذف هذا المستخدم؟ لا يمكن التراجع عن هذا الإجراء.')
    ) {
      return;
    }
    try {
      await fetchApi(`/api/admin/users/${userId}`, { method: 'DELETE' });
      await loadAllData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'فشل حذف المستخدم.');
    }
  };

  const handleSimulate = async (user: User) => {
    setSimModalOpen(true);
    setSimLoading(true);
    setSimData(null);
    try {
      const data = await simulateUserAccess(user.id);
      setSimData(data);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'فشل محاكاة صلاحيات المستخدم.');
      setSimModalOpen(false);
    } finally {
      setSimLoading(false);
    }
  };

  // --------------------------------------------------------------------
  // Role Actions
  // --------------------------------------------------------------------
  const handleSaveRole = async (payload: {
    name: string;
    label_ar: string;
    description: string;
    default_scope: DataScope;
    permissions: string[];
  }) => {
    if (editingRole) {
      await updateCustomRole(editingRole.id, {
        label_ar: payload.label_ar,
        description: payload.description,
        default_scope: payload.default_scope,
        permissions: payload.permissions,
      });
    } else {
      await createCustomRole(payload);
    }
    await loadAllData();
  };

  const handleDeleteRole = async (roleId: string) => {
    if (!window.confirm('هل أنت متأكد من رغبتك في حذف هذا الدور المخصص؟')) {
      return;
    }
    try {
      await deleteCustomRole(roleId);
      await loadAllData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'فشل حذف الدور.');
    }
  };

  const handleCloneRole = async (
    sourceRoleId: string,
    payload: { name: string; label_ar: string; description: string }
  ) => {
    await cloneRole(sourceRoleId, payload);
    await loadAllData();
  };

  // --------------------------------------------------------------------
  // Group Actions
  // --------------------------------------------------------------------
  const handleSaveGroup = async (payload: {
    name: string;
    label_ar: string;
    description: string;
    department: string;
    default_scope: DataScope;
    roles: string[];
    members: string[];
  }) => {
    if (editingGroup) {
      await updateGroup(editingGroup.id, payload);
    } else {
      await createGroup(payload);
    }
    await loadAllData();
  };

  const handleDeleteGroup = async (groupId: string) => {
    if (!window.confirm('هل أنت متأكد من حذف مجموعة العمل هذه؟')) {
      return;
    }
    try {
      await deleteGroup(groupId);
      await loadAllData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'فشل حذف مجموعة العمل.');
    }
  };

  // --------------------------------------------------------------------
  // Share Actions
  // --------------------------------------------------------------------
  const handleSaveShare = async (payload: {
    resource_type: string;
    resource_id: string;
    grantee_type: 'user' | 'group' | 'department';
    grantee_id: string;
    permissions: string[];
    expires_at: string | null;
  }) => {
    await shareResource(payload);
    await loadAllData();
  };

  const handleRevokeShare = async (shareId: string) => {
    if (!window.confirm('هل أنت متأكد من إلغاء مشاركة هذا المورد؟')) {
      return;
    }
    try {
      await revokeShare(shareId);
      await loadAllData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'فشل إلغاء المشاركة.');
    }
  };

  // --------------------------------------------------------------------
  // Filtered lists
  // --------------------------------------------------------------------
  const query = searchQuery.trim().toLowerCase();
  const filteredUsers = users.filter((u) => {
    if (!query) return true;
    return (
      u.username.toLowerCase().includes(query) ||
      u.display_name.toLowerCase().includes(query) ||
      (u.department && u.department.toLowerCase().includes(query)) ||
      (u.role_id && u.role_id.toLowerCase().includes(query))
    );
  });

  const filteredRoles = roles.filter((r) => {
    if (!query) return true;
    return (
      r.name.toLowerCase().includes(query) ||
      r.label_ar.toLowerCase().includes(query) ||
      (r.description && r.description.toLowerCase().includes(query))
    );
  });

  const filteredGroups = groups.filter((g) => {
    if (!query) return true;
    return (
      g.name.toLowerCase().includes(query) ||
      g.label_ar.toLowerCase().includes(query) ||
      (g.department && g.department.toLowerCase().includes(query))
    );
  });

  const filteredShares = shares.filter((s) => {
    if (!query) return true;
    return (
      s.resource_id.toLowerCase().includes(query) ||
      s.resource_type.toLowerCase().includes(query) ||
      s.grantee_id.toLowerCase().includes(query) ||
      s.shared_by.toLowerCase().includes(query)
    );
  });

  return (
    <div className="min-h-screen bg-dark-950 text-slate-100 flex flex-col font-sans">
      <Navbar />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-6">
        {/* Central Administration Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6 rounded-3xl border border-white/10 bg-gradient-to-r from-purple-900/20 via-dark-900 to-dark-900">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-black text-white flex items-center gap-2">
                <span>مركز الإدارة والحوكمة (Central Administration Hub)</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  Governance Layer
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-1">
                إدارة المستخدمين، الأدوار، الصلاحيات، مجموعات العمل، نطاق البيانات، الموارد المشتركة، والرقابة
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={loadAllData}
              disabled={loading}
              className="p-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-slate-300 transition-colors"
              title="تحديث البيانات"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-purple-400' : ''}`} />
            </button>

            {activeTab === 'users' && (
              <button
                onClick={() => {
                  setEditingUser(null);
                  setUserModalOpen(true);
                }}
                className="px-4 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-purple-600/20 transition-all"
              >
                <Plus className="w-4 h-4" />
                <span>إضافة مستخدم</span>
              </button>
            )}

            {activeTab === 'roles' && (
              <button
                onClick={() => {
                  setEditingRole(null);
                  setRoleModalOpen(true);
                }}
                className="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-blue-600/20 transition-all"
              >
                <Plus className="w-4 h-4" />
                <span>إنشاء دور مخصص</span>
              </button>
            )}

            {activeTab === 'groups' && (
              <button
                onClick={() => {
                  setEditingGroup(null);
                  setGroupModalOpen(true);
                }}
                className="px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
              >
                <Plus className="w-4 h-4" />
                <span>إنشاء مجموعة عمل</span>
              </button>
            )}

            {activeTab === 'shares' && (
              <button
                onClick={() => setShareModalOpen(true)}
                className="px-4 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs flex items-center gap-2 shadow-lg shadow-amber-600/20 transition-all"
              >
                <Plus className="w-4 h-4" />
                <span>مشاركة مورد جديد</span>
              </button>
            )}
          </div>
        </div>

        {/* Global Error Banner */}
        {loadError && (
          <div className="p-4 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400" />
            <span>{loadError}</span>
          </div>
        )}

        {/* Top Controls: Tabs & Search */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <AdminNavTabs
            activeTab={activeTab}
            onTabChange={setActiveTab}
            counts={{
              users: users.length,
              roles: roles.length,
              groups: groups.length,
              scopes: scopes.length,
              shares: shares.length,
            }}
          />

          {['users', 'roles', 'groups', 'shares'].includes(activeTab) && (
            <div className="relative w-full sm:w-72">
              <Search className="w-4 h-4 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="بحث وتصفية..."
                className="w-full pr-9 pl-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs text-white placeholder-slate-500 focus:border-purple-500 focus:outline-none transition-colors"
              />
            </div>
          )}
        </div>

        {/* Dynamic Tab Body */}
        {activeTab === 'users' && (
          <UserManagementTab
            users={filteredUsers}
            groups={groups}
            onSimulate={handleSimulate}
            onEdit={(user) => {
              setEditingUser(user);
              setUserModalOpen(true);
            }}
            onDelete={handleDeleteUser}
          />
        )}

        {activeTab === 'roles' && (
          <RolesTab
            roles={filteredRoles}
            onClone={(role) => {
              setCloneSourceRole(role);
              setCloneModalOpen(true);
            }}
            onEdit={(role) => {
              setEditingRole(role);
              setRoleModalOpen(true);
            }}
            onDelete={handleDeleteRole}
          />
        )}

        {activeTab === 'groups' && (
          <GroupsTab
            groups={filteredGroups}
            roles={roles}
            onEdit={(group) => {
              setEditingGroup(group);
              setGroupModalOpen(true);
            }}
            onDelete={handleDeleteGroup}
          />
        )}

        {activeTab === 'data-access' && (
          <DataAccessTab
            scopes={scopes}
            users={users}
            groups={groups}
            roles={roles}
          />
        )}

        {activeTab === 'shares' && (
          <SharesTab
            shares={filteredShares}
            onRevoke={handleRevokeShare}
          />
        )}

        {activeTab === 'jobs' && <JobsTab />}
        {activeTab === 'notifications' && <NotificationsTab />}
        {activeTab === 'audit' && <AuditOverviewTab />}
        {activeTab === 'settings' && <SettingsOverviewTab />}
        {activeTab === 'health' && <HealthOverviewTab />}
        {activeTab === 'licensing' && <LicensingTab />}
      </main>

      {/* Modals */}
      <UserFormModal
        isOpen={userModalOpen}
        onClose={() => setUserModalOpen(false)}
        editingUser={editingUser}
        roles={roles}
        groups={groups}
        scopes={scopes}
        catalog={catalog}
        onSave={handleSaveUser}
      />

      <RoleFormModal
        isOpen={roleModalOpen}
        onClose={() => setRoleModalOpen(false)}
        editingRole={editingRole}
        scopes={scopes}
        catalog={catalog}
        onSave={handleSaveRole}
      />

      <CloneRoleModal
        isOpen={cloneModalOpen}
        onClose={() => setCloneModalOpen(false)}
        sourceRole={cloneSourceRole}
        onClone={handleCloneRole}
      />

      <GroupFormModal
        isOpen={groupModalOpen}
        onClose={() => setGroupModalOpen(false)}
        editingGroup={editingGroup}
        roles={roles}
        scopes={scopes}
        users={users}
        onSave={handleSaveGroup}
      />

      <ShareFormModal
        isOpen={shareModalOpen}
        onClose={() => setShareModalOpen(false)}
        users={users}
        groups={groups}
        onSave={handleSaveShare}
      />

      <SimulationModal
        isOpen={simModalOpen}
        onClose={() => setSimModalOpen(false)}
        loading={simLoading}
        data={simData}
      />
    </div>
  );
}
