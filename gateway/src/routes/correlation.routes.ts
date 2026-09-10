import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const correlationRouter = Router();
correlationRouter.use(requireAuth);

correlationRouter.get('/summary', requirePermission('correlation.view'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/summary');
});

correlationRouter.get('/graph', requirePermission('correlation.view'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/graph');
});

correlationRouter.get('/attack-chains', requirePermission('correlation.view'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/attack-chains');
});

correlationRouter.get('/lateral-movements', requirePermission('correlation.view'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/lateral-movements');
});

correlationRouter.get('/insider-threats', requirePermission('correlation.view'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/insider-threats');
});

correlationRouter.post('/promote', requirePermission('correlation.manage'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/promote');
});

correlationRouter.post('/analyze', requirePermission('correlation.manage'), (req, res) => {
  void proxyPython(req, res, '/api/correlation/analyze');
});
