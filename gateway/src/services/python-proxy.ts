import { Request, Response } from 'express';
import { PROXY_TIMEOUT_MS, PYTHON_BACKEND_URL } from '../config.js';

const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function forwardedHeaders(req: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const name of ['content-type', 'cookie', 'x-filename', 'x-source-system', 'cache-control', 'x-request-id', 'x-correlation-id', 'x-job-id']) {
    const value = req.headers[name];
    if (typeof value === 'string') headers[name] = value;
  }
  if (!headers['x-request-id'] && (req as any).requestId) {
    headers['x-request-id'] = (req as any).requestId;
  }
  if (!headers['x-correlation-id'] && (req as any).correlationId) {
    headers['x-correlation-id'] = (req as any).correlationId;
  }
  return headers;
}

export async function proxyPython(req: Request, res: Response, targetPath: string): Promise<void> {
  const queryIndex = req.originalUrl.indexOf('?');
  const query = (queryIndex >= 0 && !targetPath.includes('?')) ? req.originalUrl.slice(queryIndex) : '';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);
  try {
    const hasBody = !['GET', 'HEAD', 'DELETE'].includes(req.method);
    const body = hasBody
      ? Buffer.isBuffer(req.body) ? new Uint8Array(req.body) : JSON.stringify(req.body ?? {})
      : undefined;
    const headers = forwardedHeaders(req);
    if (hasBody && !headers['content-type']) headers['content-type'] = 'application/json';
    const upstream = await fetch(`${PYTHON_BACKEND_URL}${targetPath}${query}`, {
      method: req.method, headers, body, signal: controller.signal,
    });
    upstream.headers.forEach((value, name) => {
      if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && name.toLowerCase() !== 'content-length') {
        res.setHeader(name, value);
      }
    });
    const payload = Buffer.from(await upstream.arrayBuffer());
    res.status(upstream.status).setHeader('Content-Length', String(payload.length));
    res.send(payload);
  } catch (error: unknown) {
    const timedOut = error instanceof Error && error.name === 'AbortError';
    res.status(503).json({
      error: timedOut ? 'انتهت مهلة الاتصال بمحرك التحليل.' : 'محرك التحليل غير متاح حاليًا.',
      code: timedOut ? 'analysis_engine_timeout' : 'analysis_engine_unavailable',
    });
  } finally {
    clearTimeout(timeout);
  }
}

export async function pythonHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${PYTHON_BACKEND_URL}/api/system/health`, { signal: AbortSignal.timeout(2_000) });
    return response.ok;
  } catch {
    return false;
  }
}
