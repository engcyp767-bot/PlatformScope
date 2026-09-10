import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const investigationsRouter = Router();
investigationsRouter.use(requireAuth);

investigationsRouter.get('/summary', requirePermission('incidents.view'), (req, res) => {
  void proxyPython(req, res, '/api/investigations/summary');
});

investigationsRouter.get('/', requirePermission('incidents.view'), (req, res) => {
  void proxyPython(req, res, '/api/investigations');
});

investigationsRouter.post('/', requirePermission('incidents.manage'), (req, res) => {
  void proxyPython(req, res, '/api/investigations');
});

investigationsRouter.get('/:id', requirePermission('incidents.view'), (req, res) => {
  const id = encodeURIComponent(String(req.params.id));
  void proxyPython(req, res, `/api/investigations/${id}`);
});

investigationsRouter.patch('/:id', requirePermission('incidents.manage'), (req, res) => {
  const id = encodeURIComponent(String(req.params.id));
  void proxyPython(req, res, `/api/investigations/${id}`);
});

investigationsRouter.post('/:id/items', requirePermission('incidents.manage'), (req, res) => {
  const id = encodeURIComponent(String(req.params.id));
  void proxyPython(req, res, `/api/investigations/${id}/items`);
});

investigationsRouter.delete('/:id/items/:itemId', requirePermission('incidents.manage'), (req, res) => {
  const id = encodeURIComponent(String(req.params.id));
  const itemId = encodeURIComponent(String(req.params.itemId));
  void proxyPython(req, res, `/api/investigations/${id}/items/${itemId}`);
});

investigationsRouter.post('/:id/notes', requirePermission('incidents.manage'), (req, res) => {
  const id = encodeURIComponent(String(req.params.id));
  void proxyPython(req, res, `/api/investigations/${id}/notes`);
});
