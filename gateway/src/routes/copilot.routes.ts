import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const copilotRouter = Router();
copilotRouter.use(requireAuth);

copilotRouter.get('/status', requirePermission('incidents.view'), (req, res) => {
  void proxyPython(req, res, '/api/copilot/status');
});

copilotRouter.post('/investigate', requirePermission('copilot.query'), (req, res) => {
  void proxyPython(req, res, '/api/copilot/investigate');
});

copilotRouter.post('/apply-note', requirePermission('incidents.manage'), (req, res) => {
  void proxyPython(req, res, '/api/copilot/apply-note');
});
