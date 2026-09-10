import { Request, Response, NextFunction } from 'express';
import { fetchLicenseStatus } from '../services/licensing.service.js';

// Public endpoints always accessible regardless of license state
const WHITELIST_PREFIXES = [
  '/api/auth',
  '/api/licensing',
  '/api/system',
  '/api/admin/audit',
  '/api/help',
];

export async function licenseEnforcementMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const path = req.path;

  // 1. Allow whitelisted routes
  for (const prefix of WHITELIST_PREFIXES) {
    if (path.startsWith(prefix)) {
      return next();
    }
  }

  // 2. Allow read-only OPTIONS requests
  if (req.method === 'OPTIONS') {
    return next();
  }

  // 3. Check License Status
  const status = await fetchLicenseStatus();
  if (!status) {
    // If backend is unreachable or not yet ready, pass through to avoid breaking startup probes
    return next();
  }

  // Valid states
  if (
    status.state === 'TRIAL_ACTIVE' ||
    status.state === 'TRIAL_EXPIRING' ||
    status.state === 'LICENSE_ACTIVE' ||
    status.state === 'LICENSE_GRACE_PERIOD' ||
    status.state === 'UNINITIALIZED'
  ) {
    return next();
  }

  // Blocked states: TRIAL_EXPIRED, LICENSE_EXPIRED, LICENSE_INVALID, LICENSE_SUSPENDED
  let errorMessage = 'انتهت صلاحية فترة التجربة (30 يوماً). يرجى تفعيل ترخيص المنصة لمتابعة الاستخدام.';
  if (status.state === 'LICENSE_EXPIRED') {
    errorMessage = 'انتهت صلاحية ترخيص المنصة. يرجى تجديد الترخيص لمتابعة عمليات التحليل.';
  } else if (status.state === 'LICENSE_SUSPENDED') {
    errorMessage = 'تم تعليق وظائف المنصة لاكتشاف تلاعب في توقيت النظام. يرجى تصحيح ساعة الجهاز.';
  } else if (status.state === 'LICENSE_INVALID') {
    errorMessage = 'ترخيص المنصة غير صالح أو تم التلاعب بملفات النظام.';
  }

  res.status(402).json({
    error: errorMessage,
    code: status.state,
    license_state: status.state,
    days_remaining: status.days_remaining,
    installation_id: status.installation_id,
  });
}

