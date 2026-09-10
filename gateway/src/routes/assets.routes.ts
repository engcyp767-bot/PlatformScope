import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const assetsRouter = Router();
assetsRouter.use(requireAuth);

assetsRouter.get('/', requirePermission('assets.view'), (req, res) => {
  void proxyPython(req, res, '/api/assets');
});

assetsRouter.get('/summary', requirePermission('assets.view'), (req, res) => {
  void proxyPython(req, res, '/api/assets/summary');
});

assetsRouter.get('/export', requirePermission('assets.view'), (req, res) => {
  void proxyPython(req, res, '/api/assets/export');
});

assetsRouter.get('/:assetId', requirePermission('assets.view'), (req, res) => {
  const assetId = encodeURIComponent(String(req.params.assetId));
  void proxyPython(req, res, `/api/assets/${assetId}`);
});

assetsRouter.post('/', requirePermission('assets.manage'), (req, res) => {
  void proxyPython(req, res, '/api/assets');
});

assetsRouter.post('/discover', requirePermission('assets.manage'), (req, res) => {
  void proxyPython(req, res, '/api/assets/discover');
});

assetsRouter.post('/import', requirePermission('assets.manage'), (req, res) => {
  void proxyPython(req, res, '/api/assets/import');
});

assetsRouter.post('/:assetId/containment', requirePermission('assets.isolate'), (req, res) => {
  const assetId = encodeURIComponent(String(req.params.assetId));
  void proxyPython(req, res, `/api/assets/${assetId}/containment`);
});

assetsRouter.post('/containment/:actionId/confirm', requirePermission('assets.isolate'), (req, res) => {
  const actionId = encodeURIComponent(String(req.params.actionId));
  void proxyPython(req, res, `/api/assets/containment/${actionId}/confirm`);
});

assetsRouter.post('/containment/:actionId/revoke', requirePermission('assets.isolate'), (req, res) => {
  const actionId = encodeURIComponent(String(req.params.actionId));
  void proxyPython(req, res, `/api/assets/containment/${actionId}/revoke`);
});

assetsRouter.patch('/:assetId', requirePermission('assets.manage'), (req, res) => {
  const assetId = encodeURIComponent(String(req.params.assetId));
  void proxyPython(req, res, `/api/assets/${assetId}`);
});

assetsRouter.delete('/:assetId', requirePermission('assets.manage'), (req, res) => {
  const assetId = encodeURIComponent(String(req.params.assetId));
  void proxyPython(req, res, `/api/assets/${assetId}`);
});
