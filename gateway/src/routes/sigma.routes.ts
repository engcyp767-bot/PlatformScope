import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const sigmaRouter = Router();
sigmaRouter.use(requireAuth);

sigmaRouter.get('/rules', requirePermission('detections.view'), (req, res) => {
  const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  void proxyPython(req, res, `/api/sigma/rules${query}`);
});

sigmaRouter.get('/rules/:ruleId', requirePermission('detections.view'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/sigma/rules/${ruleId}`);
});

sigmaRouter.post('/validate', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/sigma/validate');
});

sigmaRouter.post('/analyze-compatibility', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/sigma/analyze-compatibility');
});

sigmaRouter.post('/convert', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/sigma/convert');
});

sigmaRouter.post('/import', requirePermission('detections.manage'), (req, res) => {
  void proxyPython(req, res, '/api/sigma/import');
});

sigmaRouter.post('/rules/:ruleId/test', requirePermission('detections.view'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/sigma/rules/${ruleId}/test`);
});

sigmaRouter.delete('/rules/:ruleId', requirePermission('detections.manage'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/sigma/rules/${ruleId}`);
});
