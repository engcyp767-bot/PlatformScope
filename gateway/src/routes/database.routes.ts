import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const databaseRouter = Router();
databaseRouter.use(requireAuth);

databaseRouter.get('/status', requirePermission('database.status'), (req, res) => {
  void proxyPython(req, res, '/api/database/status');
});

