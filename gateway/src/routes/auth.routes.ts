import { Router } from 'express';
import { authService } from '../services/auth.service.js';
import { AuthenticatedRequest, requireAuth } from '../middleware/auth.js';
import { loginRateLimiter, recordFailedLogin, clearLoginAttempts } from '../middleware/rate-limit.js';
import { COOKIE_NAME, SESSION_SECONDS, SECURE_COOKIE } from '../config.js';

export const authRouter = Router();

authRouter.get('/status', (req: AuthenticatedRequest, res) => {
  res.json({
    authenticated: Boolean(req.user),
    user: req.user || null,
  });
});

authRouter.post('/login', loginRateLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

  if (!username || !password) {
    res.status(400).json({ error: 'بيانات الدخول غير صالحة.' });
    return;
  }

  const user = authService.authenticate(String(username), String(password));
  if (!user) {
    recordFailedLogin(clientIp);
    res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
    return;
  }

  clearLoginAttempts(clientIp);
  const token = authService.createSession(user.username);

  res.cookie(COOKIE_NAME, token, {
    maxAge: SESSION_SECONDS * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: SECURE_COOKIE,
    path: '/',
  });

  res.json({
    authenticated: true,
    user,
  });
});

authRouter.post('/logout', (req, res) => {
  res.cookie(COOKIE_NAME, '', {
    maxAge: 0,
    httpOnly: true,
    sameSite: 'lax',
    secure: SECURE_COOKIE,
    path: '/',
  });
  res.json({ authenticated: false });
});

authRouter.post('/account', requireAuth, (req: AuthenticatedRequest, res) => {
  const { current_password, username, new_password, display_name } = req.body || {};
  const currentIdentity = req.user!;

  if (!current_password) {
    res.status(400).json({ error: 'كلمة المرور الحالية مطلوبة.' });
    return;
  }

  const valid = authService.authenticate(currentIdentity.username, String(current_password));
  if (!valid) {
    res.status(403).json({ error: 'كلمة المرور الحالية غير صحيحة.' });
    return;
  }

  try {
    const updated = authService.updateUser(currentIdentity.id, {
      username: username ? String(username) : undefined,
      display_name: display_name ? String(display_name) : undefined,
      password: new_password ? String(new_password) : undefined,
    });

    const token = authService.createSession(updated.username);
    res.cookie(COOKIE_NAME, token, {
      maxAge: SESSION_SECONDS * 1000,
      httpOnly: true,
      sameSite: 'lax',
      secure: SECURE_COOKIE,
      path: '/',
    });

    res.json({ user: updated });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'فشل تحديث الحساب.';
    res.status(400).json({ error: msg });
  }
});
