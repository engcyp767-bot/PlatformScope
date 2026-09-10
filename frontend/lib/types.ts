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

export type IncidentStatus = 'new' | 'triaged' | 'investigating' | 'contained' | 'resolved' | 'closed' | 'rejected';
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IncidentPriority = 'P1' | 'P2' | 'P3' | 'P4';
export type EvidenceType = 'ip' | 'domain' | 'url' | 'hash' | 'file' | 'log_snippet' | 'pcap' | 'cve' | 'other';

export type DetectionLifecycle = 'development' | 'testing' | 'production' | 'deprecated';
export type DetectionSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface RuleIncidentPolicy {
  auto_promote: boolean;
  threshold: number;
  time_window_seconds: number;
  min_confidence: number;
  group_by: string[];
}

export interface RuleMetrics {
  evaluated_events: number;
  match_count: number;
  execution_time_ms: number;
  false_positive_count: number;
  last_matched_at: string | null;
}

export interface RuleVersionHistoryItem {
  version: string;
  changed_by: string;
  timestamp: string;
  reason: string;
}

export interface RuleTestSamples {
  positive: Record<string, unknown>[];
  negative: Record<string, unknown>[];
}

export interface DetectionRule {
  id: string;
  name: string;
  name_en: string;
  description: string;
  category: 'windows' | 'network' | 'malware' | 'cloud' | 'database' | string;
  severity: DetectionSeverity;
  confidence: number;
  lifecycle: DetectionLifecycle;
  enabled: boolean;
  is_deleted: boolean;
  author: string;
  version: string;
  threat_family: string;
  mitre_attack: {
    version?: string;
    tactics: string[];
    techniques: string[];
  };
  condition: Record<string, unknown>;
  incident_policy: RuleIncidentPolicy;
  metrics: RuleMetrics;
  version_history: RuleVersionHistoryItem[];
  test_samples: RuleTestSamples;
  tags: string[];
  recommendations: string[];
  integrity_hash?: string;
  source_format?: 'native' | 'sigma' | string;
  sigma_id?: string;
  compatibility_score?: number;
}

export interface DetectionSummary {
  total_rules: number;
  active_rules: number;
  by_category: Record<string, number>;
  by_lifecycle: Record<string, number>;
  by_severity: Record<string, number>;
  mitre_coverage: {
    tactics_count: number;
    tactics: string[];
    techniques_count: number;
    techniques: string[];
    matrix_version: string;
  };
  telemetry: {
    total_evaluated_events: number;
    total_matches: number;
    total_false_positives: number;
  };
}

export interface RuleTestSampleDetail {
  index: number;
  type: 'positive' | 'negative';
  sample: Record<string, unknown>;
  matched: boolean;
  passed: boolean;
  error?: string | null;
}

export interface RuleTestResult {
  success: boolean;
  rule_id: string;
  all_passed: boolean;
  total_samples: number;
  positive: {
    total: number;
    passed: number;
    failed: number;
    details: RuleTestSampleDetail[];
  };
  negative: {
    total: number;
    passed: number;
    failed: number;
    details: RuleTestSampleDetail[];
  };
}

export interface SigmaCompatibilityReport {
  score: number;
  status: 'fully_compatible' | 'partial_mapping' | 'unsupported_fields';
  status_label_ar: string;
  total_fields: number;
  fully_compatible_fields: Array<{ sigma_field: string; target: string; description: string }>;
  partial_fields: Array<{ sigma_field: string; target: string; description: string }>;
  unsupported_fields: Array<{ sigma_field: string; reason: string }>;
}

export interface SigmaRuleItem {
  id: string;
  adapter_id: string;
  title: string;
  description: string;
  level: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  status: 'production' | 'testing' | 'development' | 'deprecated' | string;
  source_type: 'builtin' | 'custom';
  date?: string;
  modified?: string;
  license?: string;
  author: string;
  tags: string[];
  mitre_attack?: {
    tactics: string[];
    techniques: string[];
  };
  compatibility?: SigmaCompatibilityReport;
  has_tests: boolean;
  positive_samples_count: number;
  negative_samples_count: number;
}

export interface SigmaValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  format?: string;
}

export interface SigmaConvertResult {
  valid: boolean;
  errors: string[];
  format: string;
  compatibility: SigmaCompatibilityReport;
  adapter: DetectionRule;
}

export interface IncidentNote {
  id: string;
  incident_id: string;
  author: string;
  note_text: string;
  created_at: string;
}

export interface IncidentEvidence {
  id: string;
  incident_id: string;
  evidence_type: EvidenceType;
  name: string;
  value?: string;
  sha256?: string;
  size_bytes?: number;
  mime_type?: string;
  file_path?: string;
  notes?: string;
  added_by: string;
  added_at: string;
}

export interface IncidentTimelineItem {
  id: string;
  incident_id: string;
  action: string;
  actor: string;
  details: string;
  timestamp: string;
}

export interface IncidentAuditItem {
  id: string;
  incident_id: string;
  actor: string;
  action: string;
  timestamp: string;
  before_state?: string;
  after_state?: string;
  reason: string;
}

export interface Incident {
  id: string;
  correlation_id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  priority: IncidentPriority;
  asset_criticality: string;
  business_impact: string;
  status: IncidentStatus;
  source_app: 'logscope' | 'flowscope' | 'threatscope' | 'manual';
  source_job_id?: string;
  assigned_to?: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  entities: string[];
  detection_rule?: string;
  confidence: number;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  notes?: IncidentNote[];
  evidence?: IncidentEvidence[];
  timeline?: IncidentTimelineItem[];
  audit?: IncidentAuditItem[];
}

export interface IncidentSummary {
  total: number;
  by_status: Record<IncidentStatus, number>;
  by_severity: Record<IncidentSeverity, number>;
  by_priority: Record<IncidentPriority, number>;
  assigned: number;
  unassigned: number;
}

export type DataScope = 'own' | 'own_shared' | 'group' | 'department' | 'organization' | 'all';

export interface ScopeInfo {
  scope: DataScope;
  label_ar: string;
  description: string;
  level: number;
}

export interface Role {
  id: string;
  name: string;
  label_ar: string;
  description: string;
  permissions: string[];
  default_scope: DataScope;
  is_builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface Group {
  id: string;
  name: string;
  label_ar: string;
  description: string;
  roles: string[];
  default_scope: DataScope;
  department: string;
  members: string[];
  created_at: string;
  updated_at: string;
}

export interface ResourceShare {
  id: string;
  resource_type: string;
  resource_id: string;
  shared_by: string;
  grantee_type: 'user' | 'group' | 'department';
  grantee_id: string;
  permissions: string[];
  created_at: string;
  expires_at?: string | null;
}

export interface AccessProfile {
  user_id: string;
  username: string;
  display_name: string;
  role_id: string;
  role_name: string;
  role_label_ar: string;
  is_builtin_role: boolean;
  data_scope: DataScope;
  scope_label_ar: string;
  department: string;
  groups: Array<{
    id: string;
    name: string;
    label_ar: string;
    department?: string;
  }>;
  effective_permissions: string[];
  custom_permissions: string[];
  permission_count: number;
}

export interface SimulatedAccess {
  simulated_user: AccessProfile;
  acting_user: string;
  evaluation_sample: Record<string, boolean>;
}

export interface PermissionCatalogItem {
  code: string;
  label: string;
  action?: string;
}

export interface PermissionGroup {
  name: string;
  permissions: PermissionCatalogItem[];
}

export interface PermissionCatalog {
  groups: PermissionGroup[];
  presets?: Record<string, string[]>;
}

export interface User {
  id: string;
  username: string;
  display_name: string;
  active: boolean;
  permissions: PermissionCode[];
  created_at: string;
  updated_at: string;
  role_id?: string;
  role_name?: string;
  role_label_ar?: string;
  data_scope?: DataScope;
  scope_label_ar?: string;
  department?: string;
  custom_permissions?: string[];
  groups?: string[];
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

export type AuditLevel = 'info' | 'warning' | 'error';
export type AuditOutcome = 'success' | 'failure' | 'denied';

export interface AuditEvent {
  id: string;
  timestamp: string;
  level: AuditLevel;
  outcome: AuditOutcome;
  category: string;
  action: string;
  message: string;
  application: 'platform' | 'flowscope' | 'threatscope' | 'logscope';
  request_id?: string;
  user_id?: string;
  username?: string;
  display_name?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  status_code?: number;
  duration_ms?: number;
  job_id?: string;
  source_system?: string;
  details?: Record<string, unknown>;
}

export interface AuditSummary {
  retained_events: number;
  last_24_hours: number;
  failures_24h: number;
  users_24h: number;
  by_level: Record<string, number>;
  by_application: Record<string, number>;
  by_category: Record<string, number>;
}

export type IOCType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'certificate';
export type IOCSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IOCTLP = 'white' | 'green' | 'amber' | 'red';
export type IOCThreatType =
  | 'c2'
  | 'malware'
  | 'phishing'
  | 'ransomware'
  | 'botnet'
  | 'scanner'
  | 'exploit'
  | 'apt'
  | 'crypto_miner'
  | 'suspicious';

export interface IOCItem {
  id: string;
  type: IOCType;
  value: string;
  threat_type: IOCThreatType;
  severity: IOCSeverity;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  tlp: IOCTLP;
  description: string;
  mitre_attack: {
    tactics?: string[];
    techniques?: string[];
  };
  related_threat_actor?: string;
  is_active: boolean;
  hit_count: number;
  last_hit_at: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface IOCHitItem {
  id: string;
  ioc_id: string;
  source_app: string;
  incident_id: string | null;
  job_id: string | null;
  event_data: Record<string, unknown>;
  hit_timestamp: string;
}

export interface IOCSummary {
  total_iocs: number;
  active_iocs: number;
  total_hits: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_threat_type: Record<string, number>;
  top_hits: Array<{
    id: string;
    type: IOCType;
    value: string;
    threat_type: IOCThreatType;
    severity: IOCSeverity;
    hit_count: number;
    last_hit_at: string;
  }>;
  recent_added: Array<{
    id: string;
    type: IOCType;
    value: string;
    threat_type: IOCThreatType;
    severity: IOCSeverity;
    created_at: string;
  }>;
}

export interface IOCFilterOptions {
  type?: string;
  severity?: string;
  threat_type?: string;
  tlp?: string;
  is_active?: boolean;
  search?: string;
  page?: number;
  limit?: number;
  cursor?: string;
}

export interface IOCLookupResult {
  query: string;
  matched: boolean;
  matches: IOCItem[];
}

export interface IOCImportResult {
  imported: number;
  skipped: number;
  errors: string[];
}

export interface ExternalApi {
  id: string;
  name: string;
  enabled: boolean;
  scope: 'flowscope' | 'threatscope' | 'logscope' | 'both' | 'all';
  base_url: string;
  health_path: string;
  lookup_path: string;
  verdict_path: string;
  malicious_values: string;
  auth_header: string;
  api_key: string;
  timeout_seconds: number;
  configured?: boolean;
}

export interface AiProvider {
  id: string;
  name: string;
  enabled: boolean;
  base_url: string;
  chat_path: string;
  models_path: string;
  model: string;
  auth_header: string;
  auth_prefix: string;
  api_key: string;
  timeout_seconds: number;
  priority: number;
  configured?: boolean;
}

export interface PlatformConfig {
  version: number;
  general: {
    language: string;
    timezone: string;
    default_app: string;
    items_per_page: number;
    show_welcome: boolean;
    show_system_status: boolean;
  };
  appearance: {
    theme: string;
    primary_color: string;
    accent_color: string;
    compact_mode: boolean;
    animations: boolean;
    platform_title: string;
    platform_subtitle: string;
  };
  ollama: {
    enabled: boolean;
    url: string;
    preferred_model: string;
    fallback_model: string;
    timeout_seconds: number;
    max_records: number;
  };
  providers: {
    virustotal: { enabled: boolean; api_keys: string[]; configured_keys?: number };
    abuseipdb: { enabled: boolean; api_key: string; configured?: boolean };
    malwarebazaar: { enabled: boolean; api_key: string; configured?: boolean };
    shodan: { enabled: boolean };
  };
  analysis: {
    flow_workers: number;
    flow_max_external_ips: number;
    log_max_external_ips: number;
    flow_cache_ttl_days: number;
    threat_cache_ttl_days: number;
    log_cache_ttl_days: number;
    auto_enrich: boolean;
    model_analysis_enabled: boolean;
    learning_enabled: boolean;
    critical_threshold: number;
    high_threshold: number;
    medium_threshold: number;
  };
  uploads: {
    flowscope_max_mb: number;
    threatscope_max_mb: number;
    logscope_max_mb: number;
    xlsx_max_files: number;
    xlsx_max_uncompressed_mb: number;
    xlsx_max_compression_ratio: number;
  };
  reports: {
    organization_name: string;
    classification: string;
    analyst_title: string;
    top_findings: number;
    recommendations: number;
    include_ai_analysis: boolean;
    include_source_results: boolean;
    preview_engine: string;
  };
  storage: {
    job_retention_days: number;
    audit_retention_days: number;
    preview_retention_hours: number;
    history_page_size: number;
  };
  logging: {
    enabled: boolean;
    level: string;
    include_details: boolean;
    max_detail_length: number;
  };
  security: {
    session_hours: number;
    login_max_attempts: number;
    login_window_minutes: number;
    secure_cookie: boolean;
  };
  features: {
    flowscope_enabled: boolean;
    threatscope_enabled: boolean;
    logscope_enabled: boolean;
    report_preview: boolean;
    excel_export: boolean;
    force_refresh: boolean;
    analyst_feedback: boolean;
  };
  source_systems: Record<'flowscope' | 'threatscope' | 'logscope', { id: string; label: string; description: string }[]>;
  network: {
    frontend_port: number;
    gateway_port: number;
    analysis_port: number;
    bind_address: string;
    trusted_origins: string[];
    proxy_timeout_seconds: number;
  };
  time?: PlatformTimeConfig;
  governance?: GovernanceConfig;
  external_apis: ExternalApi[];
  ai_providers: AiProvider[];
}

export interface GovernanceConfig {
  audit_retention_days: number;
  job_retention_days: number;
  max_workers: number;
  session_timeout_minutes: number;
  auto_vacuum_enabled: boolean;
  backup_retention_copies: number;
}

export interface ConfigRevision {
  id: number;
  version: number;
  actor: string;
  timestamp: string;
  summary: string;
}

export interface PlatformTimeConfig {
  source: 'host' | 'manual' | 'ntp';
  manual_time: string;
  ntp_server: string;
  ntp_port: number;
  ntp_sync_interval_seconds: number;
  auto_sync: boolean;
}

export interface PlatformTimeStatus {
  source: 'host' | 'manual' | 'ntp';
  current_time_iso: string;
  current_timestamp: number;
  host_time_iso: string;
  host_timestamp: number;
  offset_seconds: number;
  offset_formatted: string;
  ntp: {
    server: string;
    port: number;
    stratum: number;
    delay_ms: number;
    last_sync_iso: string | null;
    last_sync_success: boolean;
    last_sync_error: string | null;
    auto_sync: boolean;
    sync_interval_seconds: number;
    next_sync_seconds: number | null;
  };
  manual: {
    configured_time_iso: string | null;
    applied_at_iso: string | null;
  };
}

export interface StorageStats {
  disk: {
    total_bytes: number;
    used_bytes: number;
    free_bytes: number;
    used_percent: number;
  };
  jobs: {
    total_count: number;
    total_bytes: number;
    flowscope: { count: number; bytes: number };
    threatscope: { count: number; bytes: number };
    logscope: { count: number; bytes: number };
  };
  audit: {
    file_count: number;
    bytes: number;
  };
  previews: {
    file_count: number;
    bytes: number;
  };
}

export interface PlatformHealth {
  status: string;
  service: string;
  engine: string;
  analysis_engine: string;
  applications: {
    flowscope: string;
    threatscope: string;
    logscope: string;
  };
}

export interface ModelStatus {
  available: boolean;
  status: string;
  models?: string[];
  active_model?: string;
  error?: string | null;
}

export type AssetCriticality = 'mission_critical' | 'high' | 'medium' | 'low';
export type AssetStatus = 'unknown' | 'active' | 'maintenance' | 'isolated' | 'decommissioned';
export type AssetType = 'server' | 'workstation' | 'domain_controller' | 'firewall' | 'database' | 'cloud_instance' | 'iot' | 'network_switch' | 'router' | 'other';

export interface DiscoverySourceRecord {
  source: string;
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface AssetAlias {
  alias_type: string;
  alias_value: string;
  created_at: string;
}

export interface AssetTimelineEvent {
  id: number;
  asset_id: string;
  event_type: string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  actor: string;
  metadata: Record<string, any>;
  timestamp: string;
}

export interface AssetContainmentAction {
  id: string;
  asset_id: string;
  action_type: string;
  provider: string;
  status: 'draft' | 'pending_approval' | 'dispatched' | 'confirmed' | 'revoked';
  dispatched_by?: string;
  playbook_commands: Record<string, any>;
  payload: Record<string, any>;
  execution_log: Array<{ action: string; timestamp: string; actor: string }>;
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  hostname: string;
  normalized_hostname: string;
  primary_ip: string;
  ip_addresses: string[];
  mac_address?: string;
  os: string;
  asset_type: AssetType;
  criticality: AssetCriticality;
  status: AssetStatus;
  environment: string;
  owner: string;
  department: string;
  risk_score: number;
  confidence_score: number;
  discovery_sources: DiscoverySourceRecord[];
  tags: string[];
  metadata: Record<string, any>;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  aliases?: AssetAlias[];
  timeline?: AssetTimelineEvent[];
  containment_actions?: AssetContainmentAction[];
  related_incidents?: Array<{
    id: string;
    title: string;
    severity: string;
    priority: string;
    status: string;
    created_at: string;
  }>;
  matched_iocs?: Array<{
    type: string;
    value: string;
    threat_type: string;
    severity: string;
    confidence: number;
  }>;
}

export interface AssetsSummary {
  total_assets: number;
  mission_critical_count: number;
  high_risk_count: number;
  isolated_count: number;
  unknown_status_count: number;
  department_distribution: Record<string, number>;
  type_distribution: Record<string, number>;
}

export interface AssetFilterParams {
  search?: string;
  criticality?: string;
  asset_type?: string;
  status?: string;
  department?: string;
  min_risk?: number;
  limit?: number;
  offset?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}


// --- Phase 6: Graph Correlation & Attack Chains ---
export type GraphNodeType = 'user' | 'host' | 'process' | 'file' | 'network';

export interface GraphNode {
  id: string;
  node_type: GraphNodeType;
  label: string;
  properties: Record<string, any>;
  first_seen: number;
  last_seen: number;
  risk_score: number;
  criticality: string;
}

export interface GraphEdge {
  id: string;
  source_id: string;
  target_id: string;
  relation_type: string;
  timestamp: number;
  weight: number;
  event_id: string;
  job_id: string;
  evidence: string[];
  metadata: Record<string, any>;
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes?: number;
  total_edges?: number;
  node_count?: number;
  edge_count?: number;
  timestamp?: number;
}

export interface AttackChainStage {
  stage_number: number;
  tactic: string;
  technique: string;
  title_ar: string;
  node_id: string;
  node_type: string;
  entity?: string;
  details: string;
  timestamp?: number;
  relation?: string;
  stage?: string;
  label?: string;
}

export interface AttackChain {
  chain_id: string;
  title: string;
  description: string;
  start_time: number;
  end_time: number;
  risk_score: number;
  confidence: number;
  depth: number;
  nodes?: GraphNode[];
  edges?: GraphEdge[];
  stages: AttackChainStage[];
  involved_entities: {
    users?: string[];
    hosts?: string[];
    processes?: string[];
    files?: string[];
    networks?: string[];
    [key: string]: any;
  };
  mitre_tactics: string[];
  status?: string;
  incident_id?: string;
}

export interface LateralMovement {
  movement_id: string;
  pivot_host: string;
  source_user: string;
  target_hosts: string[];
  start_time: number;
  end_time: number;
  hop_count: number;
  hops_count?: number;
  risk_score: number;
  protocol: string;
  evidence: string[];
  subgraph?: Record<string, any>;
  incident_id?: string;
}

export interface InsiderThreat {
  threat_id: string;
  user_id: string;
  username: string;
  anomaly_type: string;
  risk_score: number;
  start_time: number;
  end_time: number;
  accessed_assets: string[];
  evidence: string[];
  subgraph?: Record<string, any>;
  incident_id?: string;
}

export interface CorrelationSummary {
  total_nodes: number;
  total_edges: number;
  nodes_by_type: Record<string, number>;
  edges_by_type: Record<string, number>;
  active_attack_chains: number;
  active_lateral_movements: number;
  active_insider_threats: number;
  last_analysis_time: number;
}

// --- Phase 7: Security Case Export & Forensic Integrity ---
export interface CaseFileIntegrity {
  path: string;
  sha256?: string;
  expected_sha256?: string;
  actual_sha256?: string;
  size: string;
  status: 'valid' | 'tampered' | 'missing' | 'untracked';
}

export interface CaseVerificationResult {
  valid: boolean;
  case_id: string;
  title?: string;
  severity?: string;
  priority?: string;
  status?: string;
  exported_at?: string;
  exported_by?: string;
  total_files_in_manifest?: number;
  verified_files_count?: number;
  mismatches_count?: number;
  missing_count?: number;
  untracked_count?: number;
  verified_files?: CaseFileIntegrity[];
  mismatches?: CaseFileIntegrity[];
  missing?: string[];
  untracked?: string[];
  seal_valid?: boolean;
  message: string;
  error?: string;
}

// --- Phase 8: AI Security Copilot & Natural Language Investigation ---
export interface CopilotStatus {
  status: string;
  mode: 'ollama' | 'external_ai' | 'deterministic_fallback';
  active_model: string;
  available_models: string[];
  ollama_available: boolean;
  fallback_ready: boolean;
  preferred_model: string;
  timestamp: string;
}

export interface CopilotAction {
  phase: 'containment' | 'eradication' | 'recovery' | 'investigation';
  action_ar: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
}

export interface CopilotMitreItem {
  tactic: string;
  technique: string;
  relevance_ar: string;
}

export interface CopilotAttackStage {
  step_number: number;
  stage_name: string;
  tactic: string;
  technique: string;
  target_entity: string;
  description_ar: string;
}

export interface CopilotInvestigationResult {
  success: boolean;
  incident_id: string;
  intent: 'explain_severity' | 'attack_sequence' | 'recommended_actions' | 'custom_query';
  custom_query?: string;
  actor: string;
  generated_at: string;
  disclaimer_ar: string;
  investigation_title_ar: string;
  summary_ar: string;
  detailed_analysis_ar: string;
  grounded_facts: string[];
  mitre_matrix: CopilotMitreItem[];
  recommended_actions: CopilotAction[];
  attack_stages?: CopilotAttackStage[];
  risk_factors?: string[];
  soc_playbook?: string;
  confidence: number;
  engine_used: string;
  context_summary?: {
    entities_count: number;
    matched_iocs_count: number;
    affected_assets_count: number;
    severity?: string;
    priority?: string;
  };
}

// Platform Logging & Observability Types
export type PlatformLogLevel = 'TRACE' | 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';

export interface PlatformLogItem {
  id: number;
  timestamp: string;
  level: PlatformLogLevel;
  logger: string;
  component: string;
  event_type: string;
  event_code: string;
  message_ar: string;
  message_en: string;
  message: string;
  request_id: string | null;
  correlation_id: string | null;
  job_id: string | null;
  user_id: string | null;
  duration_ms: number | null;
  error_code: string | null;
  exception_type: string | null;
  technical_details: Record<string, any> | null;
  stack_trace: string | null;
  raw_json: string;
}

export interface PlatformLogsKPIs {
  total_events: number;
  errors: number;
  warnings: number;
  critical: number;
  info: number;
  components_count: number;
}

export interface PlatformLoggingMetrics {
  written_total: number;
  dropped_total: number;
  queue_depth: number;
  by_level: Record<string, number>;
  by_component: Record<string, number>;
}

export interface PlatformLogsResponse {
  logs: PlatformLogItem[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
  kpis: PlatformLogsKPIs;
  metrics: PlatformLoggingMetrics;
  current_level: PlatformLogLevel;
}

export interface CorrelationTimelineItem {
  id: number;
  timestamp: string;
  level: PlatformLogLevel;
  component: string;
  event_type: string;
  event_code: string;
  message_ar: string;
  message_en: string;
  message: string;
  request_id: string | null;
  correlation_id: string | null;
  job_id: string | null;
  duration_ms: number | null;
  error_code: string | null;
  exception_type: string | null;
  technical_details: Record<string, any> | null;
}

export interface CorrelationTimelineResponse {
  correlation_id: string;
  total: number;
  timeline: CorrelationTimelineItem[];
}

export interface PlatformHealthComponent {
  id: string;
  name_ar: string;
  name_en: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  latency_ms: number | null;
  details: Record<string, any>;
  last_checked: string;
}

export interface PlatformSystemMetrics {
  cpu_percent: number;
  ram_total_gb: number;
  ram_used_gb: number;
  ram_free_gb: number;
  ram_percent: number;
  disk_total_gb: number;
  disk_used_gb: number;
  disk_free_gb: number;
  disk_percent: number;
  process_memory_mb: number;
  active_threads: number;
  uptime_seconds: number;
  timestamp: string;
}

export interface PlatformHealthSample {
  timestamp: string;
  cpu_percent: number;
  ram_percent: number;
  disk_percent: number;
  latency_ms: number;
  status: string;
}

export interface PlatformHealthHistoryResponse {
  samples: PlatformHealthSample[];
  total: number;
}

export interface PlatformHealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  components: PlatformHealthComponent[];
  system_metrics?: PlatformSystemMetrics;
}

export interface PlatformPerformanceResponse {
  metrics: PlatformLoggingMetrics;
  kpis: PlatformLogsKPIs;
  memory_mb: number;
  active_threads: number;
}

export interface EnterpriseTaskItem {
  id: string;
  name: string;
  priority: string;
  priority_level: number;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'retrying';
  progress: number;
  step_message: string;
  cancellation_requested: boolean;
  payload: Record<string, any>;
  result?: Record<string, any> | null;
  error?: string | null;
  retries: number;
  max_retries: number;
  tenant_id: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_ms: number;
}

export interface EnterpriseTaskMetrics {
  active_workers: number;
  queued_tasks: number;
  running_tasks: number;
  completed_tasks: number;
  failed_tasks: number;
  cancelled_tasks?: number;
  total_submitted: number;
  broker: string;
}

export interface EnterpriseTasksResponse {
  tasks: EnterpriseTaskItem[];
  total: number;
  metrics: EnterpriseTaskMetrics;
}

export interface AppNotification {
  id: string;
  title: string;
  message: string;
  category: 'system' | 'security' | 'task' | 'incident' | 'audit';
  severity: 'info' | 'warning' | 'critical' | 'success';
  target_user: string;
  link?: string | null;
  is_read: boolean;
  read_at?: string | null;
  created_at: string;
  metadata?: Record<string, any>;
}

export interface NotificationsResponse {
  notifications: AppNotification[];
  unread_count: number;
  total: number;
}

export interface PlatformBackupItem {
  backup_id: string;
  filename: string;
  size_bytes: number;
  size_mb: number;
  created_at: string;
  valid: boolean;
  file_count: number;
  note?: string;
  actor?: string;
}

export interface PlatformBackupsResponse {
  backups: PlatformBackupItem[];
}

export interface GlobalSearchResultItem {
  id: string;
  entity_type: 'incident' | 'asset' | 'rule' | 'ioc' | 'task';
  title: string;
  subtitle: string;
  badge: string;
  badge_color: 'rose' | 'amber' | 'emerald' | 'cyan' | 'purple' | 'slate';
  timestamp?: string;
  url: string;
  snippet?: string;
}

export interface GlobalSearchResponse {
  query: string;
  total_matches: number;
  results: {
    incidents: GlobalSearchResultItem[];
    assets: GlobalSearchResultItem[];
    rules: GlobalSearchResultItem[];
    iocs: GlobalSearchResultItem[];
    tasks: GlobalSearchResultItem[];
  };
}

export interface InvestigationItem {
  id: string;
  investigation_id: string;
  item_type: 'incident' | 'asset' | 'ioc' | 'evidence' | 'log_snippet';
  item_id: string;
  title: string;
  metadata?: Record<string, any>;
  added_by: string;
  added_at: string;
}

export interface InvestigationNote {
  id: string;
  investigation_id: string;
  author: string;
  content: string;
  created_at: string;
}

export interface InvestigationTimelineItem {
  id: string;
  investigation_id: string;
  actor: string;
  action: string;
  details?: string;
  timestamp: string;
}

export interface InvestigationCase {
  id: string;
  title: string;
  description: string;
  status: 'open' | 'active_triage' | 'in_depth_analysis' | 'containment' | 'closed';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  lead_analyst: string;
  tags: string[];
  hypothesis?: string;
  conclusion?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
  items_count?: number;
  notes_count?: number;
  items?: InvestigationItem[];
  notes?: InvestigationNote[];
  timeline?: InvestigationTimelineItem[];
}

export interface InvestigationSummary {
  total: number;
  open: number;
  active: number;
  closed: number;
  by_priority: {
    P1: number;
    P2: number;
    P3: number;
    P4: number;
  };
  by_status: Record<string, number>;
}

export interface InvestigationsResponse {
  investigations: InvestigationCase[];
  total: number;
  limit: number;
  offset: number;
}



