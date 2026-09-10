import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { proxyPython } from '../services/python-proxy.js';

export const authorizationRouter = Router();

authorizationRouter.use(requireAuth);

// Forward all authorization routes directly to Python backend authorization engine
authorizationRouter.all('*', (req, res) => {
  void proxyPython(req, res, req.originalUrl);
});
