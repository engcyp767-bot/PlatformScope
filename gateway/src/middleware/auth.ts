import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service.js';
import { COOKIE_NAME } from '../config.js';
import { PermissionCode, PublicUser } from '../types/index.js';

export interface AuthenticatedRequest extends Request {
  user?: PublicUser;
}

export function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = req.cookies?.[COOKIE_NAME];
  if (token) {
    const identity = authService.verifySession(token);
    if (identity) {
      req.user = identity;
    }
  }
  next();
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({
      error: 'Authentication required',
      code: 'authentication_required',
    });
    return;
  }
  next();
}

export function requirePermission(permission: PermissionCode) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'authentication_required',
      });
      return;
    }
    const hasPerm = req.user.permissions?.includes(permission) || req.user.permissions?.includes('users.manage');
    if (!hasPerm) {
      res.status(403).json({
        error: 'ليست لديك صلاحية لتنفيذ هذا الإجراء.',
        code: 'permission_denied',
        permission,
      });
      return;
    }
    next();
  };
}
