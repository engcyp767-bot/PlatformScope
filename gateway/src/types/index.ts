export type PermissionCode =
  | 'portal.access'
  | 'history.view'
  | 'flowscope.view'
  | 'flowscope.analyze'
  | 'flowscope.enrich'
  | 'flowscope.export'
  | 'flowscope.feedback'
  | 'flowscope.delete'
  | 'threatscope.view'
  | 'threatscope.analyze'
  | 'threatscope.enrich'
  | 'threatscope.export'
  | 'threatscope.feedback'
  | 'threatscope.delete'
  | 'logscope.view'
  | 'logscope.analyze'
  | 'logscope.enrich'
  | 'logscope.export'
  | 'logscope.feedback'
  | 'logscope.delete'
  | 'incidents.view'
  | 'incidents.manage'
  | 'incidents.export'
  | 'copilot.query'
  | 'detections.view'
  | 'detections.manage'
  | 'intel.view'
  | 'intel.manage'
  | 'assets.view'
  | 'assets.manage'
  | 'assets.isolate'
  | 'correlation.view'
  | 'correlation.manage'
  | 'users.manage'
  | 'system.status'
  | 'database.status'
  | 'enterprise.view'
  | 'enterprise.manage';

export interface User {
  id: string;
  username: string;
  display_name: string;
  active: boolean;
  permissions: PermissionCode[];
  password_salt?: string;
  password_hash?: string;
  session_version?: number;
  created_at: string;
  updated_at: string;
}

export interface PublicUser {
  id: string;
  username: string;
  display_name: string;
  active: boolean;
  permissions: PermissionCode[];
  created_at: string;
  updated_at: string;
}

export interface AuthConfig {
  version: number;
  session_secret: string;
  users: User[];
}

export interface OperationHistoryItem {
  id: string;
  application: 'flowscope' | 'threatscope' | 'logscope';
  job_id: string;
  target_url: string;
  operation: 'analysis' | 'source_scan' | 'refresh';
  status: string;
  timestamp: string;
  records: number;
  indicators: number;
  data_type: string;
  source_system: string;
  source_system_label: string;
  cached?: number;
  new?: number;
}
