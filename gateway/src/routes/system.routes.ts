import { Router } from 'express';
import { getOperationHistory } from '../services/history.service.js';
import { AuthenticatedRequest, requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython, pythonHealth } from '../services/python-proxy.js';
import { auditSummary, queryAudit, exportAudit } from '../services/audit.service.js';
import { platformFeatures } from '../services/platform-settings.service.js';

export const systemRouter = Router();

systemRouter.get('/settings/public', (req, res) =>
  void proxyPython(req, res, '/api/settings/public'));

systemRouter.get('/health', async (req, res) => {
  const engineAvailable = await pythonHealth();
  res.status(engineAvailable ? 200 : 503).json({
    status: engineAvailable ? 'ok' : 'degraded',
    service: 'security-backend',
    engine: 'node-gateway',
    analysis_engine: engineAvailable ? 'ok' : 'unavailable',
    applications: {
      flowscope: engineAvailable ? 'ok' : 'unavailable',
      threatscope: engineAvailable ? 'ok' : 'unavailable',
      logscope: engineAvailable ? 'ok' : 'unavailable',
    },
  });
});

systemRouter.get('/services', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const features = platformFeatures();
  res.json({
    flowscope: Boolean(features.flowscope_enabled && user.permissions?.includes('flowscope.view')),
    threatscope: Boolean(features.threatscope_enabled && user.permissions?.includes('threatscope.view')),
    logscope: Boolean(features.logscope_enabled && user.permissions?.includes('logscope.view')),
  });
});

systemRouter.get('/history', requireAuth, requirePermission('history.view'), (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const allHistory = getOperationHistory();
  const filtered = allHistory.filter((item) =>
    user.permissions?.includes(`${item.application}.view` as any)
  );
  res.json({
    total: filtered.length,
    operations: filtered,
  });
});

systemRouter.get('/audit/logs', requireAuth, requirePermission('history.view'), (req, res) => {
  res.json(queryAudit({
    page: Number(req.query.page || 1),
    limit: Number(req.query.limit || 50),
    application: String(req.query.application || ''),
    level: String(req.query.level || ''),
    category: String(req.query.category || ''),
    outcome: String(req.query.outcome || ''),
    username: String(req.query.username || ''),
    search: String(req.query.search || ''),
    from: String(req.query.from || ''),
    to: String(req.query.to || ''),
  }));
});

systemRouter.get('/audit/summary', requireAuth, requirePermission('history.view'), (_req, res) => {
  res.json(auditSummary());
});

systemRouter.get('/audit/export', requireAuth, requirePermission('history.view'), (req, res) => {
  const format = String(req.query.format || 'json').toLowerCase() === 'csv' ? 'csv' : 'json';
  const exported = exportAudit(format, {
    application: String(req.query.application || ''),
    level: String(req.query.level || ''),
    category: String(req.query.category || ''),
    outcome: String(req.query.outcome || ''),
    username: String(req.query.username || ''),
    search: String(req.query.search || ''),
    from: String(req.query.from || ''),
    to: String(req.query.to || ''),
  });
  res.setHeader('Content-Type', exported.contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${exported.filename}"`);
  res.send(exported.content);
});

systemRouter.get('/audit/verify', requireAuth, requirePermission('history.view'), (req, res) =>
  void proxyPython(req, res, '/api/audit/verify'));

systemRouter.get('/learning/status', requireAuth, requirePermission('system.status'), (req, res) =>
  void proxyPython(req, res, '/api/learning/status'));

systemRouter.get('/model/status', requireAuth, requirePermission('system.status'), (req, res) =>
  void proxyPython(req, res, '/api/model/status'));

systemRouter.get('/settings', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/settings'));

systemRouter.get('/settings/storage-stats', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/settings/storage-stats'));

systemRouter.get('/settings/history', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/settings/history'));

systemRouter.post('/settings', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/settings'));

systemRouter.post('/settings/rollback', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/settings/rollback'));

systemRouter.post('/settings/test', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/settings/test'));

// Platform Logging & Observability APIs
systemRouter.get('/platform/logs', requireAuth, requirePermission('system.status'), (req, res) =>
  void proxyPython(req, res, '/api/platform/logs'));

systemRouter.get('/platform-logs', requireAuth, requirePermission('system.status'), (req, res) =>
  void proxyPython(req, res, '/api/platform/logs'));

systemRouter.get('/platform/logs/correlation/:id', requireAuth, requirePermission('system.status'), (req, res) =>
  void proxyPython(req, res, `/api/platform/logs/correlation/${encodeURIComponent(String(req.params.id))}`));

systemRouter.get('/platform/health', (req, res) =>
  void proxyPython(req, res, '/api/platform/health'));

systemRouter.get('/platform/health/history', (req, res) =>
  void proxyPython(req, res, '/api/platform/health/history'));

systemRouter.get('/platform/performance', requireAuth, requirePermission('system.status'), (req, res) =>
  void proxyPython(req, res, '/api/platform/performance'));

systemRouter.post('/platform/logs/level', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/logs/level'));

systemRouter.get('/platform/time', requireAuth, (req, res) =>
  void proxyPython(req, res, '/api/platform/time'));

systemRouter.post('/platform/time/sync', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/time/sync'));

// Enterprise Background Tasks & Jobs APIs
systemRouter.get('/enterprise/tasks', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/enterprise/tasks'));

systemRouter.post('/enterprise/tasks/:id/cancel', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, `/api/enterprise/tasks/${encodeURIComponent(String(req.params.id))}/cancel`));

systemRouter.post('/enterprise/tasks/:id/retry', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, `/api/enterprise/tasks/${encodeURIComponent(String(req.params.id))}/retry`));

// Central In-App Notifications & Alerts APIs
systemRouter.get('/notifications', requireAuth, (req, res) =>
  void proxyPython(req, res, '/api/notifications'));

systemRouter.post('/notifications/read-all', requireAuth, (req, res) =>
  void proxyPython(req, res, '/api/notifications/read-all'));

systemRouter.post('/notifications/:id/read', requireAuth, (req, res) =>
  void proxyPython(req, res, `/api/notifications/${encodeURIComponent(String(req.params.id))}/read`));

systemRouter.post('/notifications', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/notifications'));

// Platform Backup & Recovery APIs
systemRouter.get('/platform/backups', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/backups'));

systemRouter.post('/platform/backup', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/backup'));

systemRouter.post('/platform/restore', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/restore'));

systemRouter.post('/platform/backup/delete', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/backup/delete'));

systemRouter.get('/platform/backup/download', requireAuth, requirePermission('users.manage'), (req, res) =>
  void proxyPython(req, res, '/api/platform/backup/download'));

// Unified Cross-Entity Global Search
systemRouter.get('/platform/search', requireAuth, (req, res) =>
  void proxyPython(req, res, '/api/platform/search'));


