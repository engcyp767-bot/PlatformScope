import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import { AUDIT_DIR } from '../config.js';

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
  correlation_id?: string;
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

export interface AuditQuery {
  page?: number;
  limit?: number;
  application?: string;
  level?: string;
  category?: string;
  outcome?: string;
  username?: string;
  search?: string;
  from?: string;
  to?: string;
}

const SECRET_KEY = /(password|passwd|secret|token|cookie|authorization|api.?key|session)/i;
const MAX_STRING = 500;

function cleanValue(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[تم اختصار التفاصيل]';
  if (typeof value === 'string') return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 30).map((item) => cleanValue(item, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).slice(0, 60).map(([key, item]) => [
        key,
        SECRET_KEY.test(key) ? '[محجوب]' : cleanValue(item, depth + 1),
      ])
    );
  }
  return String(value ?? '');
}

function eventFile(timestamp: string): string {
  return path.join(AUDIT_DIR, `audit-${timestamp.slice(0, 10)}.jsonl`);
}

function ensureDirectory(): void {
  fs.mkdirSync(AUDIT_DIR, { recursive: true });
}

export function recordAudit(input: Omit<AuditEvent, 'id' | 'timestamp'> & { timestamp?: string }): AuditEvent {
  ensureDirectory();
  const timestamp = input.timestamp || new Date().toISOString();
  const event: AuditEvent = {
    ...input,
    id: randomUUID().replace(/-/g, ''),
    timestamp,
    details: cleanValue(input.details || {}) as Record<string, unknown>,
  };
  fs.appendFileSync(eventFile(timestamp), `${JSON.stringify(event)}\n`, { encoding: 'utf8' });
  return event;
}

function readEvents(maximum = 50_000): AuditEvent[] {
  ensureDirectory();
  const files = fs.readdirSync(AUDIT_DIR)
    .filter((name) => /^(?:audit|engine)-\d{4}-\d{2}-\d{2}\.jsonl$/.test(name))
    .sort()
    .reverse();
  const events: AuditEvent[] = [];
  for (const name of files) {
    const lines = fs.readFileSync(path.join(AUDIT_DIR, name), 'utf8').split(/\r?\n/).filter(Boolean).reverse();
    for (const line of lines) {
      try {
        events.push(JSON.parse(line) as AuditEvent);
      } catch {
        // A partially written final line must not make the audit page unavailable.
      }
      if (events.length >= maximum * 2) break;
    }
    if (events.length >= maximum * 2) break;
  }
  return events.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, maximum);
}

function includesSearch(event: AuditEvent, search: string): boolean {
  if (!search) return true;
  const haystack = [event.message, event.action, event.username, event.display_name, event.job_id,
    event.path, event.source_system, JSON.stringify(event.details || {})].join(' ').toLowerCase();
  return haystack.includes(search.toLowerCase());
}

export function queryAudit(query: AuditQuery): { total: number; page: number; limit: number; events: AuditEvent[] } {
  const page = Math.max(1, Number(query.page) || 1);
  const limit = Math.min(200, Math.max(10, Number(query.limit) || 50));
  const from = query.from ? Date.parse(query.from) : Number.NaN;
  const to = query.to ? Date.parse(query.to) : Number.NaN;
  const filtered = readEvents().filter((event) => {
    const stamp = Date.parse(event.timestamp);
    return (!query.application || event.application === query.application)
      && (!query.level || event.level === query.level)
      && (!query.category || event.category === query.category)
      && (!query.outcome || event.outcome === query.outcome)
      && (!query.username || event.username === query.username)
      && (Number.isNaN(from) || stamp >= from)
      && (Number.isNaN(to) || stamp <= to)
      && includesSearch(event, query.search || '');
  });
  const offset = (page - 1) * limit;
  return { total: filtered.length, page, limit, events: filtered.slice(offset, offset + limit) };
}

export function auditSummary(): Record<string, unknown> {
  const events = readEvents();
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const recent = events.filter((event) => Date.parse(event.timestamp) >= since);
  const countBy = (field: keyof AuditEvent) => Object.fromEntries(
    [...new Set(recent.map((event) => String(event[field] || 'unknown')))].map((value) => [
      value, recent.filter((event) => String(event[field] || 'unknown') === value).length,
    ])
  );
  return {
    retained_events: events.length,
    last_24_hours: recent.length,
    failures_24h: recent.filter((event) => event.outcome !== 'success').length,
    users_24h: new Set(recent.map((event) => event.username).filter(Boolean)).size,
    by_level: countBy('level'),
    by_application: countBy('application'),
    by_category: countBy('category'),
  };
}

export function exportAudit(format: 'csv' | 'json', query: AuditQuery): { content: string; contentType: string; filename: string } {
  const { events } = queryAudit({ ...query, limit: 10000, page: 1 });
  const dateStr = new Date().toISOString().slice(0, 10);

  if (format === 'json') {
    return {
      content: JSON.stringify(events, null, 2),
      contentType: 'application/json',
      filename: `platform-audit-export-${dateStr}.json`,
    };
  }

  // CSV format
  const headers = ['Timestamp', 'Application', 'Category', 'Action', 'Outcome', 'Level', 'User', 'IP', 'Message'];
  const rows = events.map((e) => [
    e.timestamp,
    e.application,
    e.category,
    e.action,
    e.outcome,
    e.level,
    e.username || '',
    e.client_ip || '',
    `"${(e.message || '').replace(/"/g, '""')}"`,
  ]);

  const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
  return {
    content: csv,
    contentType: 'text/csv',
    filename: `platform-audit-export-${dateStr}.csv`,
  };
}

