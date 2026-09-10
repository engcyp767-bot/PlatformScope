import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const incidentsRouter = Router();
incidentsRouter.use(requireAuth);

incidentsRouter.get('/', requirePermission('incidents.view'), (req, res) => {
  void proxyPython(req, res, '/api/incidents');
});

incidentsRouter.get('/summary', requirePermission('incidents.view'), (req, res) => {
  void proxyPython(req, res, '/api/incidents/summary');
});

incidentsRouter.post('/sync', requirePermission('incidents.manage'), (req, res) => {
  void proxyPython(req, res, '/api/incidents/sync');
});

incidentsRouter.post('/promote', requirePermission('incidents.manage'), (req, res) => {
  void proxyPython(req, res, '/api/incidents/promote');
});

incidentsRouter.post('/', requirePermission('incidents.manage'), (req, res) => {
  void proxyPython(req, res, '/api/incidents');
});

incidentsRouter.get('/:incidentId', requirePermission('incidents.view'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}`);
});

incidentsRouter.patch('/:incidentId/status', requirePermission('incidents.manage'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/status`);
});

incidentsRouter.patch('/:incidentId/assign', requirePermission('incidents.manage'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/assign`);
});

incidentsRouter.patch('/:incidentId/priority', requirePermission('incidents.manage'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/priority`);
});

incidentsRouter.post('/:incidentId/notes', requirePermission('incidents.manage'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/notes`);
});

incidentsRouter.post('/:incidentId/evidence', requirePermission('incidents.manage'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/evidence`);
});

incidentsRouter.get('/:incidentId/evidence/:evidenceId/download', requirePermission('incidents.view'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  const evidenceId = encodeURIComponent(String(req.params.evidenceId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/evidence/${evidenceId}/download`);
});

incidentsRouter.delete('/:incidentId/evidence/:evidenceId', requirePermission('incidents.manage'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  const evidenceId = encodeURIComponent(String(req.params.evidenceId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/evidence/${evidenceId}`);
});

incidentsRouter.get('/:incidentId/case-export', requirePermission('incidents.export'), (req, res) => {
  const incidentId = encodeURIComponent(String(req.params.incidentId));
  void proxyPython(req, res, `/api/incidents/${incidentId}/case-export`);
});

incidentsRouter.post('/case-verify', requirePermission('incidents.export'), (req, res) => {
  void proxyPython(req, res, '/api/incidents/case-verify');
});
