import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const intelRouter = Router();
intelRouter.use(requireAuth);

intelRouter.get('/iocs', requirePermission('intel.view'), (req, res) => {
  void proxyPython(req, res, '/api/intel/iocs');
});

intelRouter.get('/summary', requirePermission('intel.view'), (req, res) => {
  void proxyPython(req, res, '/api/intel/summary');
});

intelRouter.get('/iocs/summary', requirePermission('intel.view'), (req, res) => {
  void proxyPython(req, res, '/api/intel/iocs/summary');
});

intelRouter.get('/export', requirePermission('intel.view'), (req, res) => {
  void proxyPython(req, res, '/api/intel/export');
});

intelRouter.get('/iocs/:iocId/hits', requirePermission('intel.view'), (req, res) => {
  const iocId = encodeURIComponent(String(req.params.iocId));
  void proxyPython(req, res, `/api/intel/iocs/${iocId}/hits`);
});

intelRouter.get('/iocs/:iocId', requirePermission('intel.view'), (req, res) => {
  const iocId = encodeURIComponent(String(req.params.iocId));
  void proxyPython(req, res, `/api/intel/iocs/${iocId}`);
});

intelRouter.post('/iocs', requirePermission('intel.manage'), (req, res) => {
  void proxyPython(req, res, '/api/intel/iocs');
});

intelRouter.post('/lookup', requirePermission('intel.view'), (req, res) => {
  void proxyPython(req, res, '/api/intel/lookup');
});

intelRouter.post('/import', requirePermission('intel.manage'), (req, res) => {
  void proxyPython(req, res, '/api/intel/import');
});

intelRouter.patch('/iocs/:iocId/toggle', requirePermission('intel.manage'), (req, res) => {
  const iocId = encodeURIComponent(String(req.params.iocId));
  void proxyPython(req, res, `/api/intel/iocs/${iocId}/toggle`);
});

intelRouter.patch('/iocs/:iocId', requirePermission('intel.manage'), (req, res) => {
  const iocId = encodeURIComponent(String(req.params.iocId));
  void proxyPython(req, res, `/api/intel/iocs/${iocId}`);
});

intelRouter.delete('/iocs/:iocId', requirePermission('intel.manage'), (req, res) => {
  const iocId = encodeURIComponent(String(req.params.iocId));
  void proxyPython(req, res, `/api/intel/iocs/${iocId}`);
});
