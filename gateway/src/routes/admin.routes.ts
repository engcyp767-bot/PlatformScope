import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const adminRouter = Router();

adminRouter.use(requireAuth);
adminRouter.use(requirePermission('users.manage'));

adminRouter.get('/users', (req, res) => {
  void proxyPython(req, res, '/api/admin/users');
});

adminRouter.post('/users', (req, res) => {
  void proxyPython(req, res, '/api/admin/users');
});

adminRouter.post('/users/:id', (req, res) => {
  void proxyPython(req, res, `/api/admin/users/${req.params.id}`);
});

adminRouter.delete('/users/:id', (req, res) => {
  void proxyPython(req, res, `/api/admin/users/${req.params.id}`);
});
