import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';
import { platformFeatures } from '../services/platform-settings.service.js';

export const threatscopeRouter = Router();
threatscopeRouter.use(requireAuth);
threatscopeRouter.use((req, res, next) => {
  const features = platformFeatures();
  if (!features.threatscope_enabled) return void res.status(503).json({ error: 'ThreatScope معطل من إعدادات المنصة.' });
  if ((req.path.startsWith('/report/') || req.path.startsWith('/preview/')) && !features.report_preview) return void res.status(403).json({ error: 'معاينة التقارير معطلة من الإعدادات.' });
  if (req.path.endsWith('.xlsx') && !features.excel_export) return void res.status(403).json({ error: 'تصدير Excel معطل من الإعدادات.' });
  if (req.path.startsWith('/feedback/') && !features.analyst_feedback) return void res.status(403).json({ error: 'ملاحظات المحلل معطلة من الإعدادات.' });
  if (req.path.startsWith('/enrich/') && String(req.query.force || '') === '1' && !features.force_refresh) return void res.status(403).json({ error: 'التحديث الإجباري معطل من الإعدادات.' });
  next();
});

const JOB_ID = /^[0-9a-f]{32}$/i;
const EXPORT_FILE = /^[0-9a-f]{32}\.(docx|xlsx)$/i;
const PREVIEW_FILE = /^[0-9a-f]{32}(\.pdf)?$/i;
const param = (value: string | string[]): string => String(value);

threatscopeRouter.get('/health', requirePermission('threatscope.view'), (req, res) => void proxyPython(req, res, '/api/threatscope/health'));
threatscopeRouter.get('/config', requirePermission('threatscope.view'), (req, res) => void proxyPython(req, res, '/api/threatscope/config'));
threatscopeRouter.post('/analyze', requirePermission('threatscope.analyze'), (req, res) => void proxyPython(req, res, '/api/threatscope/analyze'));
threatscopeRouter.post('/enrich/:jobId', requirePermission('threatscope.enrich'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/enrich/${jobId}`);
});
threatscopeRouter.get('/jobs/:jobId', requirePermission('threatscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/jobs/${jobId}`);
});
threatscopeRouter.get('/jobs/:jobId/records', requirePermission('threatscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/jobs/${jobId}/records`);
});
threatscopeRouter.delete('/jobs/:jobId', requirePermission('threatscope.delete'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/jobs/${jobId}`);
});
threatscopeRouter.post('/feedback/:jobId/:recordIndex', requirePermission('threatscope.feedback'), (req, res) => {
  const jobId = param(req.params.jobId);
  const recordIndex = param(req.params.recordIndex);
  if (!JOB_ID.test(jobId) || !/^\d+$/.test(recordIndex)) {
    return void res.status(400).json({ error: 'بيانات التقييم غير صالحة.' });
  }
  void proxyPython(req, res, `/api/threatscope/feedback/${jobId}/${recordIndex}`);
});
threatscopeRouter.get('/export/:filename', requirePermission('threatscope.export'), (req, res) => {
  const filename = param(req.params.filename);
  if (!EXPORT_FILE.test(filename)) return void res.status(400).json({ error: 'اسم ملف التصدير غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/export/${filename}`);
});
threatscopeRouter.get('/report/:filename', requirePermission('threatscope.export'), (req, res) => {
  const jobId = param(req.params.filename).replace(/\.pdf$/i, '');
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف التقرير غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/report/${jobId}`);
});
threatscopeRouter.get('/preview/:filename', requirePermission('threatscope.export'), (req, res) => {
  const filename = param(req.params.filename);
  if (!PREVIEW_FILE.test(filename)) return void res.status(400).json({ error: 'اسم ملف المعاينة غير صالح.' });
  void proxyPython(req, res, `/api/threatscope/preview/${filename}`);
});
