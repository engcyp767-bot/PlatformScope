import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const detectionsRouter = Router();
detectionsRouter.use(requireAuth);

detectionsRouter.get('/', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/detections');
});

detectionsRouter.get('/summary', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/detections/summary');
});

detectionsRouter.get('/export', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/detections/export');
});

detectionsRouter.get('/:ruleId', requirePermission('detections.view'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/detections/${ruleId}`);
});

detectionsRouter.post('/', requirePermission('detections.manage'), (req, res) => {
  void proxyPython(req, res, '/api/detections');
});

detectionsRouter.post('/reload', requirePermission('detections.manage'), (req, res) => {
  void proxyPython(req, res, '/api/detections/reload');
});

detectionsRouter.post('/import', requirePermission('detections.manage'), (req, res) => {
  void proxyPython(req, res, '/api/detections/import');
});

detectionsRouter.post('/test', requirePermission('detections.view'), (req, res) => {
  void proxyPython(req, res, '/api/detections/test');
});

detectionsRouter.post('/:ruleId/run-tests', requirePermission('detections.view'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/detections/${ruleId}/run-tests`);
});

detectionsRouter.patch('/:ruleId/toggle', requirePermission('detections.manage'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/detections/${ruleId}/toggle`);
});

detectionsRouter.patch('/:ruleId/lifecycle', requirePermission('detections.manage'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/detections/${ruleId}/lifecycle`);
});

detectionsRouter.patch('/:ruleId', requirePermission('detections.manage'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/detections/${ruleId}`);
});

detectionsRouter.delete('/:ruleId', requirePermission('detections.manage'), (req, res) => {
  const ruleId = encodeURIComponent(String(req.params.ruleId));
  void proxyPython(req, res, `/api/detections/${ruleId}`);
});
