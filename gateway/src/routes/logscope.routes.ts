import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';
import { platformFeatures } from '../services/platform-settings.service.js';

export const logscopeRouter = Router();
logscopeRouter.use(requireAuth);
logscopeRouter.use((req, res, next) => {
  const features = platformFeatures();
  if (!features.logscope_enabled) return void res.status(503).json({ error: 'logscope معطل من إعدادات المنصة.' });
  if (req.path.startsWith('/preview/') && !features.report_preview) return void res.status(403).json({ error: 'معاينة التقارير معطلة من الإعدادات.' });
  if (req.path.endsWith('.xlsx') && !features.excel_export) return void res.status(403).json({ error: 'تصدير Excel معطل من الإعدادات.' });
  if (req.path.startsWith('/feedback/') && !features.analyst_feedback) return void res.status(403).json({ error: 'ملاحظات المحلل معطلة من الإعدادات.' });
  if (req.path.startsWith('/enrich/') && String(req.query.force || '') === '1' && !features.force_refresh) return void res.status(403).json({ error: 'التحديث الإجباري معطل من الإعدادات.' });
  next();
});

const JOB_ID = /^[0-9a-f]{32}$/i;
const EXPORT_FILE = /^[0-9a-f]{32}\.(docx|xlsx)$/i;
const PREVIEW_FILE = /^[0-9a-f]{32}(\.pdf)?$/i;
const param = (value: string | string[]): string => String(value);

logscopeRouter.get('/health', requirePermission('logscope.view'), (req, res) => void proxyPython(req, res, '/api/logscope/health'));
logscopeRouter.get('/config', requirePermission('logscope.view'), (req, res) => void proxyPython(req, res, '/api/logscope/config'));
logscopeRouter.post('/analyze', requirePermission('logscope.analyze'), (req, res) => void proxyPython(req, res, '/api/logscope/analyze'));

logscopeRouter.post('/enrich/:jobId', requirePermission('logscope.enrich'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/enrich/${jobId}`);
});
logscopeRouter.delete('/enrich/:jobId', requirePermission('logscope.enrich'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/enrich/${jobId}`);
});
logscopeRouter.get('/jobs/:jobId', requirePermission('logscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}`);
});
logscopeRouter.get('/jobs/:jobId/records', requirePermission('logscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}/records`);
});
logscopeRouter.get('/jobs/:jobId/incidents', requirePermission('logscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}/incidents`);
});
logscopeRouter.get('/jobs/:jobId/incidents/:incidentId', requirePermission('logscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}/incidents/${incidentId}`);
});
logscopeRouter.get('/jobs/:jobId/entities/:type/:value', requirePermission('logscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  const type = encodeURIComponent(String(req.params.type));
  const value = encodeURIComponent(String(req.params.value));
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}/entities/${type}/${value}`);
});
logscopeRouter.get('/jobs/:jobId/mitre', requirePermission('logscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}/mitre`);
});
logscopeRouter.delete('/jobs/:jobId', requirePermission('logscope.delete'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/jobs/${jobId}`);
});
logscopeRouter.post('/feedback/:jobId/:recordIndex', requirePermission('logscope.feedback'), (req, res) => {
  const jobId = param(req.params.jobId);
  const recordIndex = param(req.params.recordIndex);
  if (!JOB_ID.test(jobId) || !/^\d+$/.test(recordIndex)) {
    return void res.status(400).json({ error: 'بيانات التقييم غير صالحة.' });
  }
  void proxyPython(req, res, `/api/logscope/feedback/${jobId}/${recordIndex}`);
});
logscopeRouter.get('/export/:filename', requirePermission('logscope.export'), (req, res) => {
  const filename = param(req.params.filename);
  if (!EXPORT_FILE.test(filename)) return void res.status(400).json({ error: 'اسم ملف التصدير غير صالح.' });
  void proxyPython(req, res, `/api/logscope/export/${filename}`);
});
logscopeRouter.get('/preview/:filename', requirePermission('logscope.export'), (req, res) => {
  const filename = param(req.params.filename);
  if (!PREVIEW_FILE.test(filename)) return void res.status(400).json({ error: 'اسم ملف المعاينة غير صالح.' });
  void proxyPython(req, res, `/api/logscope/preview/${filename}`);
});
