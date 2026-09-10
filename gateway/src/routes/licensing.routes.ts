import { Router, Request, Response } from 'express';
import { proxyPython } from '../services/python-proxy.js';
import { invalidateLicenseCache } from '../services/licensing.service.js';

export const licensingRouter = Router();

licensingRouter.get('/status', async (req: Request, res: Response) => {
  await proxyPython(req, res, '/api/licensing/status');
});

licensingRouter.post('/request', async (req: Request, res: Response) => {
  await proxyPython(req, res, '/api/licensing/request');
});

licensingRouter.post('/activate', async (req: Request, res: Response) => {
  invalidateLicenseCache();
  await proxyPython(req, res, '/api/licensing/activate');
});

licensingRouter.post('/refresh', async (req: Request, res: Response) => {
  invalidateLicenseCache();
  await proxyPython(req, res, '/api/licensing/refresh');
});

