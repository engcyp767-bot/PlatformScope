import {
  User,
  Role,
  Group,
  DataScope,
  ScopeInfo,
  ResourceShare,
  SimulatedAccess,
  PermissionCatalog,
} from '../../../lib/types';

export type AdminTab =
  | 'users'
  | 'roles'
  | 'groups'
  | 'data-access'
  | 'shares'
  | 'jobs'
  | 'notifications'
  | 'audit'
  | 'settings'
  | 'health'
  | 'licensing';

export interface AdminCommonProps {
  users: User[];
  roles: Role[];
  groups: Group[];
  scopes: ScopeInfo[];
  shares: ResourceShare[];
  catalog: PermissionCatalog | null;
  loading: boolean;
  onRefresh: () => void;
}

