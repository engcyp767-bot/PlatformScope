import fs from 'fs';
import path from 'path';
import { FLOWSCOPE_JOBS_DIR, LOGSCOPE_JOBS_DIR, THREATSCOPE_JOBS_DIR } from '../config.js';
import { OperationHistoryItem } from '../types/index.js';

interface CachedJobHistory {
  mtime: number;
  items: OperationHistoryItem[];
}

const historyCache = new Map<string, CachedJobHistory>();

function parseTimestamp(value: unknown, fallback: number): string {
  if (typeof value === 'string' && value.trim()) {
    return value;
  }
  return new Date(fallback).toISOString();
}

export function jobTargetUrl(app: 'flowscope' | 'threatscope' | 'logscope', jobId: string): string {
  return `/${app}/${jobId}`;
}

function extractJsonObject(text: string, key: string): any {
  const marker = `"${key}":`;
  const idx = text.indexOf(marker);
  if (idx === -1) return null;
  const startBrace = text.indexOf('{', idx + marker.length);
  if (startBrace === -1) return null;

  let depth = 0;
  let inString = false;
  let escape = false;

  for (let i = startBrace; i < text.length; i++) {
    const ch = text[i];
    if (escape) {
      escape = false;
      continue;
    }
    if (ch === '\\') {
      escape = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      continue;
    }
    if (!inString) {
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          try {
            return JSON.parse(text.slice(startBrace, i + 1));
          } catch {
            return null;
          }
        }
      }
    }
  }
  return null;
}

function readJobMeta(filePath: string, size: number): any {
  if (size < 16 * 1024 * 1024) {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch {
      return {};
    }
  }

  try {
    const fd = fs.openSync(filePath, 'r');
    const headBuf = Buffer.alloc(131072);
    const headRead = fs.readSync(fd, headBuf, 0, 131072, 0);
    const headText = headBuf.toString('utf-8', 0, headRead);

    const tailBuf = Buffer.alloc(131072);
    const tailPos = Math.max(0, size - 131072);
    const tailRead = fs.readSync(fd, tailBuf, 0, 131072, tailPos);
    fs.closeSync(fd);
    const tailText = tailBuf.toString('utf-8', 0, tailRead);

    const metadata = extractJsonObject(headText, 'metadata') || extractJsonObject(tailText, 'metadata') || {};
    const summary = extractJsonObject(headText, 'summary') || extractJsonObject(tailText, 'summary') || {};
    const analysis = extractJsonObject(headText, 'analysis') || extractJsonObject(tailText, 'analysis') || {};
    const enrichment = extractJsonObject(tailText, 'enrichment') || extractJsonObject(headText, 'enrichment') || {};

    return { metadata, summary, analysis, enrichment };
  } catch {
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch {
      return {};
    }
  }
}

export function getOperationHistory(): OperationHistoryItem[] {
  const operations: OperationHistoryItem[] = [];
  const applications = [
    { app: 'flowscope' as const, dir: FLOWSCOPE_JOBS_DIR },
    { app: 'threatscope' as const, dir: THREATSCOPE_JOBS_DIR },
    { app: 'logscope' as const, dir: LOGSCOPE_JOBS_DIR },
  ];

  for (const { app, dir } of applications) {
    if (!fs.existsSync(dir)) continue;
    try {
      const jobFolders = fs.readdirSync(dir);
      for (const folder of jobFolders) {
        if (!/^[0-9a-f]{32}$/i.test(folder)) continue;
        const analysisPath = path.join(dir, folder, 'analysis.json');
        if (!fs.existsSync(analysisPath)) continue;

        try {
          const stats = fs.statSync(analysisPath);
          const cached = historyCache.get(analysisPath);
          if (cached && cached.mtime === stats.mtimeMs) {
            operations.push(...cached.items);
            continue;
          }

          const jobOperations: OperationHistoryItem[] = [];
          const data = readJobMeta(analysisPath, stats.size);
          const metadata = data.metadata || {};
          const summary = data.summary || {};
          const analysisState = data.analysis || {};
          const analyzedAt = parseTimestamp(metadata.analyzed_at, stats.mtimeMs);
          const analysisStatus =
            analysisState.status || (data.records !== undefined || data.events !== undefined ? 'completed' : 'unknown');
          const sourceSystem = String(metadata.source_system || 'unspecified');
          const sourceSystemLabel = String(metadata.source_system_label || 'غير محدد — ملف سابق');
          const indicators = app === 'threatscope'
            ? summary.unique_hashes || 0
            : summary.unique_ips || data.unique_ips_count || 0;

          jobOperations.push({
            id: `${app}:${folder}:analysis`,
            application: app,
            job_id: folder.slice(0, 8).toUpperCase(),
            target_url: jobTargetUrl(app, folder),
            operation: 'analysis',
            status: analysisStatus,
            timestamp: analyzedAt,
            records: Number(summary.records || data.total_records || metadata.row_count || 0),
            indicators: Number(indicators),
            data_type: String(metadata.data_type || metadata.sheet || 'data'),
            source_system: sourceSystem,
            source_system_label: sourceSystemLabel,
          });

          const enrichment = data.enrichment || {};
          const enrichmentStatus = String(enrichment.status || 'not_started');
          if (enrichmentStatus !== 'not_started') {
            const forceRefresh = Boolean(enrichment.force_refresh);
            jobOperations.push({
              id: `${app}:${folder}:enrichment`,
              application: app,
              job_id: folder.slice(0, 8).toUpperCase(),
              target_url: jobTargetUrl(app, folder),
              operation: forceRefresh ? 'refresh' : 'source_scan',
              status: enrichmentStatus,
              timestamp: parseTimestamp(
                enrichment.completed_at || enrichment.started_at,
                stats.mtimeMs
              ),
              records: Number(enrichment.checked || 0),
              indicators: Number(enrichment.total || 0),
              cached: Number(enrichment.cached || 0),
              new: Number(enrichment.new || 0),
              data_type: String(metadata.data_type || metadata.sheet || 'data'),
              source_system: sourceSystem,
              source_system_label: sourceSystemLabel,
            });
          }

          historyCache.set(analysisPath, {
            mtime: stats.mtimeMs,
            items: jobOperations,
          });
          operations.push(...jobOperations);
        } catch {
          // Ignore unparseable job
        }
      }
    } catch {
      // Ignore directory read errors
    }
  }

  operations.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  return operations;
}
