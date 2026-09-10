import {
  User, OperationHistoryItem, AuditEvent, AuditSummary, Incident, IncidentSummary,
  IncidentStatus, EvidenceType, SigmaRuleItem, SigmaValidationResult,
  SigmaCompatibilityReport, SigmaConvertResult,
  IOCItem, IOCHitItem, IOCSummary, IOCFilterOptions, IOCLookupResult, IOCImportResult,
  PlatformConfig, StorageStats, PlatformHealth, ModelStatus, PermissionCode,
  Asset, AssetsSummary, AssetFilterParams, AssetContainmentAction,
  GraphSnapshot,
  AttackChain,
  LateralMovement,
  InsiderThreat,
  CorrelationSummary,
  CaseVerificationResult,
  CopilotStatus,
  CopilotInvestigationResult,
  PlatformLogLevel,
  PlatformLogItem,
  PlatformLogsResponse,
  CorrelationTimelineResponse,
  PlatformHealthResponse,
  PlatformHealthHistoryResponse,
  PlatformPerformanceResponse,
  PlatformTimeStatus,
  PlatformTimeConfig,
  Role,
  Group,
  ScopeInfo,
  ResourceShare,
  AccessProfile,
  SimulatedAccess,
  EnterpriseTasksResponse,
  EnterpriseTaskItem,
  AppNotification,
  NotificationsResponse,
  ConfigRevision,
  GovernanceConfig,
  PlatformBackupsResponse,
  GlobalSearchResponse,
  GlobalSearchResultItem,
  InvestigationCase,
  InvestigationSummary,
  InvestigationsResponse,
  InvestigationItem,
  InvestigationNote,
} from './types';

// The browser always uses the same origin. Next.js forwards /api to the private
// gateway, so remote users never accidentally call their own 127.0.0.1.
const API_BASE = '';

export async function fetchApi<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const url = path.startsWith('http') ? path : `${API_BASE}${path.startsWith('/') ? path : `/${path}`}`;
  let res: Response;
  try {
    res = await fetch(url, {
      cache: 'no-store',
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    });
  } catch {
    throw new Error('فشل الاتصال بالخادم. يرجى التأكد من تشغيل منصة التحليل الأمني والتحقق من الاتصال بالشبكة.');
  }

  if (
    res.status === 401 &&
    typeof window !== 'undefined' &&
    !window.location.pathname.startsWith('/login') &&
    !window.location.pathname.startsWith('/help')
  ) {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
  }

  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || `خطأ ${res.status}`);
    }
    return data;
  }

  if (!res.ok) {
    throw new Error(`خطأ ${res.status}`);
  }

  return (await res.text()) as unknown as T;
}

export async function getAuthStatus(): Promise<{ authenticated: boolean; user: User | null }> {
  try {
    return await fetchApi('/api/auth/status');
  } catch {
    return { authenticated: false, user: null };
  }
}

export async function getHistory(): Promise<{ total: number; operations: OperationHistoryItem[] }> {
  return await fetchApi('/api/history');
}

export async function getServicesStatus(): Promise<{ flowscope: boolean; threatscope: boolean; logscope: boolean }> {
  return await fetchApi('/api/system/services');
}

export async function getAuditLogs(params: Record<string, string | number> = {}): Promise<{
  total: number; page: number; limit: number; events: AuditEvent[];
}> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== '' && value !== undefined) query.set(key, String(value));
  });
  return await fetchApi(`/api/audit/logs?${query.toString()}`);
}

export async function getAuditSummary(): Promise<AuditSummary> {
  return await fetchApi('/api/audit/summary');
}

export async function verifyAuditIntegrity(): Promise<{ verified: boolean; message: string }> {
  return await fetchApi('/api/audit/verify');
}

export async function getIncidents(params: Record<string, string | number> = {}): Promise<{
  total: number; limit: number; offset: number; incidents: Incident[];
}> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== '' && value !== undefined) query.set(key, String(value));
  });
  return await fetchApi(`/api/incidents?${query.toString()}`);
}

export async function getIncidentSummary(): Promise<IncidentSummary> {
  return await fetchApi('/api/incidents/summary');
}

export async function getIncident(incidentId: string): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}`);
}

export async function createIncident(payload: Partial<Incident> & { reason?: string }): Promise<Incident> {
  return await fetchApi('/api/incidents', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateIncidentStatus(incidentId: string, status: IncidentStatus, reason: string): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status, reason }),
  });
}

export async function assignIncident(incidentId: string, assignedTo: string | null, reason?: string): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}/assign`, {
    method: 'PATCH',
    body: JSON.stringify({ assigned_to: assignedTo, reason: reason || 'Analyst assignment' }),
  });
}

export async function updateIncidentPriority(
  incidentId: string,
  data: { severity?: string; asset_criticality?: string; business_impact?: string; justification?: string }
): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}/priority`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });
}

export async function addIncidentNote(incidentId: string, noteText: string): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}/notes`, {
    method: 'POST',
    body: JSON.stringify({ note: noteText }),
  });
}

export async function addIncidentEvidence(
  incidentId: string,
  payload: {
    evidence_type: EvidenceType;
    name: string;
    value?: string;
    notes?: string;
    file_b64?: string;
    filename?: string;
    mime_type?: string;
  }
): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}/evidence`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function removeIncidentEvidence(incidentId: string, evidenceId: string): Promise<Incident> {
  return await fetchApi(`/api/incidents/${encodeURIComponent(incidentId)}/evidence/${encodeURIComponent(evidenceId)}`, {
    method: 'DELETE',
  });
}

export async function syncIncidents(): Promise<{ synced: number }> {
  return await fetchApi('/api/incidents/sync', { method: 'POST' });
}

// ----------------------------------------------------
// Detection Engineering API Client Functions
// ----------------------------------------------------

export async function getDetections(params: Record<string, string | number | boolean> = {}): Promise<{
  total: number; limit: number; offset: number; rules: any[]; summary: any;
}> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== '' && value !== undefined && value !== null) query.set(key, String(value));
  });
  return await fetchApi(`/api/detections?${query.toString()}`);
}

export async function getDetectionsSummary(): Promise<any> {
  return await fetchApi('/api/detections/summary');
}

export async function getDetectionRule(ruleId: string): Promise<any> {
  return await fetchApi(`/api/detections/${encodeURIComponent(ruleId)}`);
}

export async function createOrUpdateDetectionRule(payload: any): Promise<any> {
  return await fetchApi('/api/detections', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function toggleDetectionRule(ruleId: string, enabled: boolean): Promise<any> {
  return await fetchApi(`/api/detections/${encodeURIComponent(ruleId)}/toggle`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  });
}

export async function updateDetectionLifecycle(ruleId: string, lifecycle: string, reason: string): Promise<any> {
  return await fetchApi(`/api/detections/${encodeURIComponent(ruleId)}/lifecycle`, {
    method: 'PATCH',
    body: JSON.stringify({ lifecycle, reason }),
  });
}

export async function deleteDetectionRule(ruleId: string): Promise<any> {
  return await fetchApi(`/api/detections/${encodeURIComponent(ruleId)}`, {
    method: 'DELETE',
  });
}

export async function runDetectionRuleTests(ruleId: string): Promise<any> {
  return await fetchApi(`/api/detections/${encodeURIComponent(ruleId)}/run-tests`, {
    method: 'POST',
  });
}

export async function testDetectionRuleSimulator(rule: any, event: any): Promise<any> {
  return await fetchApi('/api/detections/test', {
    method: 'POST',
    body: JSON.stringify({ rule, event }),
  });
}

export async function exportDetectionRules(): Promise<any> {
  return await fetchApi('/api/detections/export');
}

export async function importDetectionRules(packageData: any): Promise<any> {
  return await fetchApi('/api/detections/import', {
    method: 'POST',
    body: JSON.stringify(packageData),
  });
}

export async function reloadDetectionRules(): Promise<{ reloaded: boolean; count: number }> {
  return await fetchApi('/api/detections/reload', {
    method: 'POST',
  });
}

export async function getSigmaRules(params?: {
  source_type?: string;
  status?: string;
  level?: string;
  search?: string;
}): Promise<{ rules: SigmaRuleItem[]; total: number }> {
  const query = new URLSearchParams();
  if (params?.source_type && params.source_type !== 'all') query.set('source_type', params.source_type);
  if (params?.status && params.status !== 'all') query.set('status', params.status);
  if (params?.level && params.level !== 'all') query.set('level', params.level);
  if (params?.search) query.set('search', params.search);
  const qs = query.toString();
  return await fetchApi(`/api/sigma/rules${qs ? `?${qs}` : ''}`);
}

export async function getSigmaRuleDetails(ruleId: string): Promise<any> {
  return await fetchApi(`/api/sigma/rules/${encodeURIComponent(ruleId)}`);
}

export async function validateSigmaRule(content: string): Promise<SigmaValidationResult> {
  return await fetchApi('/api/sigma/validate', {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
}

export async function analyzeSigmaCompatibility(content: string): Promise<{ format: string; compatibility: SigmaCompatibilityReport }> {
  return await fetchApi('/api/sigma/analyze-compatibility', {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
}

export async function convertSigmaRule(content: string): Promise<SigmaConvertResult> {
  return await fetchApi('/api/sigma/convert', {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
}

export async function importSigmaRule(content: string, force: boolean = false): Promise<any> {
  return await fetchApi('/api/sigma/import', {
    method: 'POST',
    body: JSON.stringify({ content, force }),
  });
}

export async function testSigmaRule(ruleId: string, customEvent?: Record<string, unknown>): Promise<any> {
  return await fetchApi(`/api/sigma/rules/${encodeURIComponent(ruleId)}/test`, {
    method: 'POST',
    body: JSON.stringify({ custom_event: customEvent }),
  });
}

export async function deleteCustomSigmaRule(ruleId: string): Promise<any> {
  return await fetchApi(`/api/sigma/rules/${encodeURIComponent(ruleId)}`, {
    method: 'DELETE',
  });
}

// ----------------------------------------------------------------------------
// Threat Intelligence & Central IOC Knowledge Base
// ----------------------------------------------------------------------------

export async function getIOCs(params?: IOCFilterOptions): Promise<{
  iocs: IOCItem[];
  total: number;
  next_cursor: string | null;
  limit: number;
  offset: number;
}> {
  const query = new URLSearchParams();
  if (params?.type && params.type !== 'all') query.set('type', params.type);
  if (params?.severity && params.severity !== 'all') query.set('severity', params.severity);
  if (params?.threat_type && params.threat_type !== 'all') query.set('threat_type', params.threat_type);
  if (params?.tlp && params.tlp !== 'all') query.set('tlp', params.tlp);
  if (typeof params?.is_active === 'boolean') query.set('is_active', String(params.is_active));
  if (params?.search) query.set('search', params.search);
  if (params?.page) query.set('page', String(params.page));
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.cursor) query.set('cursor', params.cursor);
  const qs = query.toString();
  return await fetchApi(`/api/intel/iocs${qs ? `?${qs}` : ''}`);
}

export async function getIOCSummary(): Promise<IOCSummary> {
  return await fetchApi('/api/intel/summary');
}

export async function getIOC(id: string): Promise<IOCItem> {
  return await fetchApi(`/api/intel/iocs/${encodeURIComponent(id)}`);
}

export async function getIOCHits(id: string): Promise<{ ioc_id: string; hits: IOCHitItem[]; total: number }> {
  return await fetchApi(`/api/intel/iocs/${encodeURIComponent(id)}/hits`);
}

export async function createIOC(payload: Partial<IOCItem>): Promise<IOCItem> {
  return await fetchApi('/api/intel/iocs', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateIOC(id: string, payload: Partial<IOCItem>): Promise<IOCItem> {
  return await fetchApi(`/api/intel/iocs/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function toggleIOC(id: string, isActive: boolean): Promise<IOCItem> {
  return await fetchApi(`/api/intel/iocs/${encodeURIComponent(id)}/toggle`, {
    method: 'PATCH',
    body: JSON.stringify({ is_active: isActive }),
  });
}

export async function deleteIOC(id: string): Promise<{ deleted: boolean; id: string }> {
  return await fetchApi(`/api/intel/iocs/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export async function lookupIOCs(values: string[]): Promise<{ results: IOCLookupResult[]; total: number }> {
  return await fetchApi('/api/intel/lookup', {
    method: 'POST',
    body: JSON.stringify({ values }),
  });
}

export async function importIOCs(content: string, format: string = 'csv', onDuplicate: string = 'skip'): Promise<IOCImportResult> {
  return await fetchApi('/api/intel/import', {
    method: 'POST',
    body: JSON.stringify({ content, format, on_duplicate: onDuplicate }),
  });
}

export async function getHelpGuide(): Promise<{
  success: boolean;
  title: string;
  content: string;
  lastModified: string;
  sizeBytes: number;
}> {
  return await fetchApi('/api/help/guide');
}

// ----------------------------------------------------------------------------
// Platform Configuration & Administration
// ----------------------------------------------------------------------------

export async function getPlatformConfig(): Promise<{
  config: PlatformConfig;
  defaults: PlatformConfig;
}> {
  return await fetchApi('/api/settings');
}

export async function savePlatformConfig(config: PlatformConfig, changeSummary?: string): Promise<{
  config: PlatformConfig;
  restart_required: boolean;
}> {
  return await fetchApi('/api/settings', {
    method: 'POST',
    body: JSON.stringify({ ...config, change_summary: changeSummary }),
  });
}

export async function getPlatformConfigHistory(limit: number = 50): Promise<{
  history: ConfigRevision[];
  total: number;
}> {
  return await fetchApi(`/api/settings/history?limit=${limit}`);
}

export async function rollbackPlatformConfig(revisionId?: number, version?: number): Promise<{
  config: PlatformConfig;
  success: boolean;
  message: string;
}> {
  return await fetchApi('/api/settings/rollback', {
    method: 'POST',
    body: JSON.stringify({ revision_id: revisionId, version }),
  });
}

export async function testPlatformConnection(payload: object): Promise<{
  ok: boolean;
  status?: number | null;
  message: string;
  sample?: string;
}> {
  return await fetchApi('/api/settings/test', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getStorageStats(): Promise<StorageStats> {
  return await fetchApi('/api/settings/storage-stats');
}

export async function getPlatformHealth(): Promise<PlatformHealth> {
  return await fetchApi('/api/health');
}

export async function getModelStatus(): Promise<ModelStatus> {
  return await fetchApi('/api/model/status');
}

export async function getAdminUsers(): Promise<{
  users: User[];
  catalog: {
    groups: { name: string; permissions: { code: PermissionCode; label: string }[] }[];
    presets: Record<string, PermissionCode[]>;
  };
}> {
  return await fetchApi('/api/admin/users');
}

export async function createAdminUser(data: {
  username: string;
  display_name: string;
  password?: string;
  permissions: PermissionCode[];
  active: boolean;
}): Promise<{ user: User }> {
  return await fetchApi('/api/admin/users', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateAdminUser(
  id: string,
  data: {
    username?: string;
    display_name?: string;
    password?: string;
    permissions?: PermissionCode[];
    active?: boolean;
  }
): Promise<{ user: User }> {
  return await fetchApi(`/api/admin/users/${encodeURIComponent(id)}`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function deleteAdminUser(id: string): Promise<{ deleted: boolean }> {
  return await fetchApi(`/api/admin/users/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

// ---------------------------------------------------------------------------
// Phase 5: Asset Intelligence & Inventory APIs
// ---------------------------------------------------------------------------

export async function getAssets(params?: AssetFilterParams): Promise<{
  assets: Asset[];
  total: number;
  limit: number;
  offset: number;
}> {
  const query = new URLSearchParams();
  if (params?.search) query.set('search', params.search);
  if (params?.criticality && params.criticality !== 'all') query.set('criticality', params.criticality);
  if (params?.asset_type && params.asset_type !== 'all') query.set('asset_type', params.asset_type);
  if (params?.status && params.status !== 'all') query.set('status', params.status);
  if (params?.department && params.department !== 'all') query.set('department', params.department);
  if (params?.min_risk !== undefined && params.min_risk > 0) query.set('min_risk', String(params.min_risk));
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.offset) query.set('offset', String(params.offset));
  if (params?.sort_by) query.set('sort_by', params.sort_by);
  if (params?.sort_order) query.set('sort_order', params.sort_order);

  const qs = query.toString();
  return await fetchApi(`/api/assets${qs ? `?${qs}` : ''}`);
}

export async function getAssetsSummary(): Promise<AssetsSummary> {
  return await fetchApi('/api/assets/summary');
}

export async function getAsset(id: string): Promise<Asset> {
  return await fetchApi(`/api/assets/${encodeURIComponent(id)}`);
}

export async function createAsset(data: Partial<Asset>): Promise<Asset> {
  return await fetchApi('/api/assets', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateAsset(id: string, data: Partial<Asset>): Promise<Asset> {
  return await fetchApi(`/api/assets/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(data),
  });
}

export async function deleteAsset(id: string): Promise<{ success: boolean; id: string }> {
  return await fetchApi(`/api/assets/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export async function createAssetContainment(
  assetId: string,
  actionType: string = 'network_isolation',
  provider: string = 'manual_playbook',
  payload?: any
): Promise<AssetContainmentAction> {
  return await fetchApi(`/api/assets/${encodeURIComponent(assetId)}/containment`, {
    method: 'POST',
    body: JSON.stringify({ action_type: actionType, provider, payload }),
  });
}

export async function confirmAssetContainment(actionId: string): Promise<{ action_id: string; asset_id: string; status: string }> {
  return await fetchApi(`/api/assets/containment/${encodeURIComponent(actionId)}/confirm`, {
    method: 'POST',
  });
}

export async function revokeAssetContainment(actionId: string): Promise<{ action_id: string; asset_id: string; status: string }> {
  return await fetchApi(`/api/assets/containment/${encodeURIComponent(actionId)}/revoke`, {
    method: 'POST',
  });
}

export async function discoverAssets(): Promise<{ success: boolean; discovered: number; updated: number; total_processed: number }> {
  return await fetchApi('/api/assets/discover', {
    method: 'POST',
  });
}

export async function importAssets(content: string, format: string = 'json', dryRun: boolean = false): Promise<any> {
  return await fetchApi('/api/assets/import', {
    method: 'POST',
    body: JSON.stringify({ content, format, dry_run: dryRun }),
  });
}

export function exportAssetsUrl(format: 'json' | 'csv' = 'json'): string {
  return `/api/assets/export?format=${format}`;
}





export async function getCorrelationSummary(): Promise<CorrelationSummary> {
  return await fetchApi('/api/correlation/summary');
}

export async function getCorrelationGraph(params?: { limit?: number; incident_id?: string; asset_id?: string }): Promise<GraphSnapshot> {
  const query = new URLSearchParams();
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.incident_id) query.set('incident_id', params.incident_id);
  if (params?.asset_id) query.set('asset_id', params.asset_id);
  const qStr = query.toString();
  return await fetchApi(`/api/correlation/graph${qStr ? `?${qStr}` : ''}`);
}

export async function getAttackChains(): Promise<{ attack_chains: AttackChain[] }> {
  return await fetchApi('/api/correlation/attack-chains');
}

export async function getLateralMovements(): Promise<{ lateral_movements: LateralMovement[] }> {
  return await fetchApi('/api/correlation/lateral-movements');
}

export async function getInsiderThreats(): Promise<{ insider_threats: InsiderThreat[] }> {
  return await fetchApi('/api/correlation/insider-threats');
}

export async function promoteGraphPatternToIncident(patternType: string, patternId: string): Promise<{ success: boolean; incident: any }> {
  return await fetchApi('/api/correlation/promote', {
    method: 'POST',
    body: JSON.stringify({ pattern_type: patternType, pattern_id: patternId }),
  });
}

export async function runCorrelationAnalysis(): Promise<{ success: boolean; result: any }> {
  return await fetchApi('/api/correlation/analyze', {
    method: 'POST',
  });
}

export function exportIncidentCaseUrl(incidentId: string): string {
  return `/api/incidents/${encodeURIComponent(incidentId)}/case-export`;
}

export async function verifyIncidentCase(fileOrBase64: File | string): Promise<CaseVerificationResult> {
  let body: string;
  if (typeof fileOrBase64 === 'string') {
    body = JSON.stringify({ zip_base64: fileOrBase64 });
  } else {
    const buffer = await fileOrBase64.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunk)));
    }
    const base64 = btoa(binary);
    body = JSON.stringify({ zip_base64: base64 });
  }
  return await fetchApi('/api/incidents/case-verify', {
    method: 'POST',
    body,
  });
}

// --- Phase 8: AI Security Copilot API ---
export async function getCopilotStatus(): Promise<CopilotStatus> {
  return await fetchApi('/api/copilot/status');
}

export async function queryCopilot(
  incidentId: string,
  intent: 'explain_severity' | 'attack_sequence' | 'recommended_actions' | 'custom_query' = 'explain_severity',
  customQuery?: string
): Promise<CopilotInvestigationResult> {
  return await fetchApi('/api/copilot/investigate', {
    method: 'POST',
    body: JSON.stringify({
      incident_id: incidentId,
      intent,
      custom_query: customQuery,
    }),
  });
}

export async function applyCopilotNote(incidentId: string, noteText: string): Promise<Incident> {
  return await fetchApi('/api/copilot/apply-note', {
    method: 'POST',
    body: JSON.stringify({
      incident_id: incidentId,
      note_text: noteText,
    }),
  });
}

// --- Platform Logging & Observability API ---
export async function getPlatformLogs(params: Record<string, string | number | undefined> = {}): Promise<PlatformLogsResponse> {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== '' && value !== undefined && value !== null) query.set(key, String(value));
  });
  return await fetchApi(`/api/platform/logs?${query.toString()}`);
}

export async function getCorrelationTimeline(correlationId: string): Promise<CorrelationTimelineResponse> {
  return await fetchApi(`/api/platform/logs/correlation/${encodeURIComponent(correlationId)}`);
}

export async function getPlatformDetailedHealth(): Promise<PlatformHealthResponse> {
  return await fetchApi('/api/platform/health');
}

export async function getPlatformHealthHistory(): Promise<PlatformHealthHistoryResponse> {
  return await fetchApi('/api/platform/health/history');
}

export async function getPlatformPerformance(): Promise<PlatformPerformanceResponse> {
  return await fetchApi('/api/platform/performance');
}

export async function setPlatformLogLevel(level: PlatformLogLevel): Promise<{ status: string; level: PlatformLogLevel; old_level: string }> {
  return await fetchApi('/api/platform/logs/level', {
    method: 'POST',
    body: JSON.stringify({ level }),
  });
}

// --- Platform Time & Synchronization API ---
export async function getPlatformTime(): Promise<PlatformTimeStatus> {
  return await fetchApi('/api/platform/time');
}

export async function syncPlatformTime(payload: { server?: string; port?: number } = {}): Promise<{
  ok: boolean;
  message: string;
  status: PlatformTimeStatus;
}> {
  return await fetchApi('/api/platform/time/sync', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ============================================================================
// Authorization & Data Scope APIs
// ============================================================================

export async function getRoles(): Promise<Role[]> {
  const res = await fetchApi<{ roles: Role[] }>('/api/authorization/roles');
  return res.roles || [];
}

export async function createCustomRole(payload: {
  name: string;
  label_ar: string;
  description?: string;
  permissions: string[];
  default_scope?: string;
}): Promise<Role> {
  const res = await fetchApi<{ role: Role }>('/api/authorization/roles', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return res.role;
}

export async function updateCustomRole(
  roleId: string,
  payload: {
    label_ar?: string;
    description?: string;
    permissions?: string[];
    default_scope?: string;
  }
): Promise<Role> {
  const res = await fetchApi<{ role: Role }>(`/api/authorization/roles/${encodeURIComponent(roleId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
  return res.role;
}

export async function deleteCustomRole(roleId: string): Promise<{ deleted: boolean; id: string }> {
  return await fetchApi(`/api/authorization/roles/${encodeURIComponent(roleId)}`, {
    method: 'DELETE',
  });
}

export async function cloneRole(
  sourceRoleId: string,
  payload: {
    name: string;
    label_ar: string;
    description?: string;
  }
): Promise<Role> {
  const res = await fetchApi<{ role: Role }>(`/api/authorization/roles/${encodeURIComponent(sourceRoleId)}/clone`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return res.role;
}

export async function getGroups(): Promise<Group[]> {
  const res = await fetchApi<{ groups: Group[] }>('/api/authorization/groups');
  return res.groups || [];
}

export async function createGroup(payload: {
  name: string;
  label_ar: string;
  description?: string;
  roles?: string[];
  default_scope?: string;
  department?: string;
  members?: string[];
}): Promise<Group> {
  const res = await fetchApi<{ group: Group }>('/api/authorization/groups', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return res.group;
}

export async function updateGroup(
  groupId: string,
  payload: {
    label_ar?: string;
    description?: string;
    roles?: string[];
    default_scope?: string;
    department?: string;
    members?: string[];
  }
): Promise<Group> {
  const res = await fetchApi<{ group: Group }>(`/api/authorization/groups/${encodeURIComponent(groupId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
  return res.group;
}

export async function deleteGroup(groupId: string): Promise<{ deleted: boolean; id: string }> {
  return await fetchApi(`/api/authorization/groups/${encodeURIComponent(groupId)}`, {
    method: 'DELETE',
  });
}

export async function getAvailableScopes(): Promise<ScopeInfo[]> {
  const res = await fetchApi<{ scopes: ScopeInfo[] }>('/api/authorization/scopes');
  return res.scopes || [];
}

export async function getMyAccessProfile(): Promise<AccessProfile> {
  return await fetchApi<AccessProfile>('/api/authorization/my-profile');
}

export async function simulateUserAccess(userId: string): Promise<SimulatedAccess> {
  return await fetchApi<SimulatedAccess>(`/api/authorization/simulate/${encodeURIComponent(userId)}`);
}

export async function getMyShares(resourceType?: string): Promise<ResourceShare[]> {
  const query = resourceType ? `?resource_type=${encodeURIComponent(resourceType)}` : '';
  const res = await fetchApi<{ shares: ResourceShare[] }>(`/api/authorization/sharing/my-shared${query}`);
  return res.shares || [];
}

export async function getResourceShares(resourceType: string, resourceId: string): Promise<ResourceShare[]> {
  const res = await fetchApi<{ shares: ResourceShare[] }>(
    `/api/authorization/sharing/resource?resource_type=${encodeURIComponent(resourceType)}&resource_id=${encodeURIComponent(resourceId)}`
  );
  return res.shares || [];
}

export async function shareResource(payload: {
  resource_type: string;
  resource_id: string;
  grantee_type: 'user' | 'group' | 'department';
  grantee_id: string;
  permissions?: string[];
  expires_at?: string | null;
}): Promise<ResourceShare> {
  const res = await fetchApi<{ share: ResourceShare }>('/api/authorization/sharing/share', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return res.share;
}

export async function revokeResourceShare(shareId: string): Promise<{ revoked: boolean }> {
  return await fetchApi<{ revoked: boolean }>('/api/authorization/sharing/revoke', {
    method: 'POST',
    body: JSON.stringify({ share_id: shareId }),
  });
}

export const revokeShare = revokeResourceShare;

// ============================================================================
// Enterprise Tasks & Background Jobs APIs
// ============================================================================
export async function getEnterpriseTasks(params?: {
  status?: string;
  tenant_id?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<EnterpriseTasksResponse> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.tenant_id) query.set('tenant_id', params.tenant_id);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.offset) query.set('offset', String(params.offset));
  const qs = query.toString();
  return await fetchApi(`/api/enterprise/tasks${qs ? `?${qs}` : ''}`);
}

export async function cancelEnterpriseTask(taskId: string): Promise<{ success: boolean; message: string }> {
  return await fetchApi(`/api/enterprise/tasks/${encodeURIComponent(taskId)}/cancel`, {
    method: 'POST',
  });
}

export async function retryEnterpriseTask(taskId: string): Promise<{ success: boolean; message: string }> {
  return await fetchApi(`/api/enterprise/tasks/${encodeURIComponent(taskId)}/retry`, {
    method: 'POST',
  });
}

// ============================================================================
// Notifications & Alerts APIs
// ============================================================================
export async function getNotifications(params?: {
  unread?: boolean;
  category?: string;
  limit?: number;
  offset?: number;
}): Promise<NotificationsResponse> {
  const query = new URLSearchParams();
  if (params?.unread !== undefined) query.set('unread', String(params.unread));
  if (params?.category) query.set('category', params.category);
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.offset) query.set('offset', String(params.offset));
  const qs = query.toString();
  return await fetchApi(`/api/notifications${qs ? `?${qs}` : ''}`);
}

export async function markNotificationRead(id: string): Promise<{ success: boolean }> {
  return await fetchApi(`/api/notifications/${encodeURIComponent(id)}/read`, {
    method: 'POST',
  });
}

export async function markAllNotificationsRead(): Promise<{ success: boolean; read_count: number }> {
  return await fetchApi('/api/notifications/read-all', {
    method: 'POST',
  });
}

export async function createNotification(payload: {
  title: string;
  message: string;
  category?: string;
  severity?: string;
  target_user?: string;
  link?: string;
  metadata?: Record<string, any>;
}): Promise<{ success: boolean; notification: AppNotification }> {
  return await fetchApi('/api/notifications', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// ============================================================================
// Storage Governance & Vacuum Lifecycle APIs
// ============================================================================
export async function vacuumStorageDatabases(): Promise<{
  success: boolean;
  reclaimed_total_bytes: number;
  reclaimed_total_mb: number;
  databases_processed: number;
  details: { database: string; reclaimed_bytes?: number; status: string; error?: string }[];
}> {
  return await fetchApi('/api/enterprise/storage/vacuum', {
    method: 'POST',
  });
}

export async function cleanupEnterpriseStorage(payload?: {
  jobs_days?: number;
  audit_days?: number;
  dry_run?: boolean;
}): Promise<{
  dry_run: boolean;
  archive: any;
  vacuum: any;
  timestamp: string;
}> {
  return await fetchApi('/api/enterprise/storage/cleanup', {
    method: 'POST',
    body: JSON.stringify(payload || {}),
  });
}

// ============================================================================
// Platform Backup & Recovery APIs
// ============================================================================
export async function getPlatformBackups(): Promise<PlatformBackupsResponse> {
  return await fetchApi('/api/platform/backups');
}

export async function createPlatformBackup(payload?: {
  note?: string;
  include_detections?: boolean;
  include_databases?: boolean;
  include_configs?: boolean;
}): Promise<any> {
  return await fetchApi('/api/platform/backup', {
    method: 'POST',
    body: JSON.stringify(payload || {}),
  });
}

export async function restorePlatformBackup(backup_id: string, create_safety_snapshot: boolean = true): Promise<any> {
  return await fetchApi('/api/platform/restore', {
    method: 'POST',
    body: JSON.stringify({ backup_id, create_safety_snapshot }),
  });
}

export async function deletePlatformBackup(backup_id: string): Promise<any> {
  return await fetchApi('/api/platform/backup/delete', {
    method: 'POST',
    body: JSON.stringify({ backup_id }),
  });
}

// ============================================================================
// Platform Global Search API
// ============================================================================
export async function globalSearch(query: string, entities?: string[], limit: number = 5): Promise<GlobalSearchResponse> {
  const params = new URLSearchParams();
  params.set('q', query);
  if (entities && entities.length > 0) {
    params.set('entities', entities.join(','));
  }
  params.set('limit', String(limit));
  return await fetchApi(`/api/platform/search?${params.toString()}`);
}

// ============================================================================
// Investigation Workspace APIs
// ============================================================================
export async function getInvestigations(params?: {
  status?: string;
  priority?: string;
  lead_analyst?: string;
  search?: string;
  limit?: number;
  offset?: number;
}): Promise<InvestigationsResponse> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.priority) query.set('priority', params.priority);
  if (params?.lead_analyst) query.set('lead_analyst', params.lead_analyst);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.offset) query.set('offset', String(params.offset));
  const qs = query.toString();
  return await fetchApi(`/api/investigations${qs ? `?${qs}` : ''}`);
}

export async function getInvestigationSummary(): Promise<InvestigationSummary> {
  return await fetchApi('/api/investigations/summary');
}

export async function getInvestigation(id: string): Promise<InvestigationCase> {
  return await fetchApi(`/api/investigations/${encodeURIComponent(id)}`);
}

export async function createInvestigation(payload: {
  title: string;
  description?: string;
  priority?: string;
  lead_analyst?: string;
  tags?: string[];
  hypothesis?: string;
}): Promise<InvestigationCase> {
  return await fetchApi('/api/investigations', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateInvestigation(id: string, updates: Partial<InvestigationCase>): Promise<InvestigationCase> {
  return await fetchApi(`/api/investigations/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(updates),
  });
}

export async function addInvestigationItem(id: string, payload: {
  item_type: string;
  item_id: string;
  title: string;
  metadata?: Record<string, any>;
}): Promise<InvestigationItem> {
  return await fetchApi(`/api/investigations/${encodeURIComponent(id)}/items`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function removeInvestigationItem(investigationId: string, itemId: string): Promise<{ deleted: boolean; id: string }> {
  return await fetchApi(`/api/investigations/${encodeURIComponent(investigationId)}/items/${encodeURIComponent(itemId)}`, {
    method: 'DELETE',
  });
}

export async function addInvestigationNote(id: string, content: string): Promise<InvestigationNote> {
  return await fetchApi(`/api/investigations/${encodeURIComponent(id)}/notes`, {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
}








