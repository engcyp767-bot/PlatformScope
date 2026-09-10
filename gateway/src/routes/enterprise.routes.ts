import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const enterpriseRouter = Router();
enterpriseRouter.use(requireAuth);

enterpriseRouter.get('/status', requirePermission('enterprise.view'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/status');
});

enterpriseRouter.get('/tenants', requirePermission('enterprise.view'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/tenants');
});

enterpriseRouter.post('/tenants', requirePermission('enterprise.manage'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/tenants');
});

enterpriseRouter.get('/tasks', requirePermission('enterprise.view'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/tasks');
});

enterpriseRouter.get('/storage', requirePermission('enterprise.view'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/storage');
});

enterpriseRouter.post('/storage/archive', requirePermission('enterprise.manage'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/storage/archive');
});

enterpriseRouter.post('/storage/vacuum', requirePermission('enterprise.manage'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/storage/vacuum');
});

enterpriseRouter.post('/storage/cleanup', requirePermission('enterprise.manage'), (req, res) => {
  void proxyPython(req, res, '/api/enterprise/storage/cleanup');
});

