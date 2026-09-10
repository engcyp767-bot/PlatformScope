import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';
import { platformFeatures } from '../services/platform-settings.service.js';

export const flowscopeRouter = Router();
flowscopeRouter.use(requireAuth);
flowscopeRouter.use((req, res, next) => {
  const features = platformFeatures();
  if (!features.flowscope_enabled) return void res.status(503).json({ error: 'FlowScope معطل من إعدادات المنصة.' });
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

flowscopeRouter.get('/health', requirePermission('flowscope.view'), (req, res) => void proxyPython(req, res, '/api/flowscope/health'));
flowscopeRouter.get('/config', requirePermission('flowscope.view'), (req, res) => void proxyPython(req, res, '/api/flowscope/config'));
flowscopeRouter.post('/analyze', requirePermission('flowscope.analyze'), (req, res) => void proxyPython(req, res, '/api/flowscope/analyze'));

flowscopeRouter.post('/enrich/:jobId', requirePermission('flowscope.enrich'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/enrich/${jobId}`);
});
flowscopeRouter.delete('/enrich/:jobId', requirePermission('flowscope.enrich'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/enrich/${jobId}`);
});
flowscopeRouter.get('/jobs/:jobId', requirePermission('flowscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/jobs/${jobId}`);
});
flowscopeRouter.get('/jobs/:jobId/records', requirePermission('flowscope.view'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/jobs/${jobId}/records`);
});
flowscopeRouter.delete('/jobs/:jobId', requirePermission('flowscope.delete'), (req, res) => {
  const jobId = param(req.params.jobId);
  if (!JOB_ID.test(jobId)) return void res.status(400).json({ error: 'معرّف المهمة غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/jobs/${jobId}`);
});
flowscopeRouter.post('/feedback/:jobId/:recordIndex', requirePermission('flowscope.feedback'), (req, res) => {
  const jobId = param(req.params.jobId);
  const recordIndex = param(req.params.recordIndex);
  if (!JOB_ID.test(jobId) || !/^\d+$/.test(recordIndex)) {
    return void res.status(400).json({ error: 'بيانات التقييم غير صالحة.' });
  }
  void proxyPython(req, res, `/api/flowscope/feedback/${jobId}/${recordIndex}`);
});
flowscopeRouter.get('/export/:filename', requirePermission('flowscope.export'), (req, res) => {
  const filename = param(req.params.filename);
  if (!EXPORT_FILE.test(filename)) return void res.status(400).json({ error: 'اسم ملف التصدير غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/export/${filename}`);
});
flowscopeRouter.get('/preview/:filename', requirePermission('flowscope.export'), (req, res) => {
  const filename = param(req.params.filename);
  if (!PREVIEW_FILE.test(filename)) return void res.status(400).json({ error: 'اسم ملف المعاينة غير صالح.' });
  void proxyPython(req, res, `/api/flowscope/preview/${filename}`);
});
