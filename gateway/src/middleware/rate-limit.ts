import { Request, Response, NextFunction } from 'express';

interface AttemptRecord {
  timestamps: number[];
}

const loginAttempts = new Map<string, AttemptRecord>();
const WINDOW_SECONDS = Math.max(60, Number.parseInt(process.env.SECURITY_LOGIN_WINDOW_MINUTES || '5', 10) * 60);
const MAX_ATTEMPTS = Math.max(2, Number.parseInt(process.env.SECURITY_LOGIN_MAX_ATTEMPTS || '5', 10));

export function loginRateLimiter(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now() / 1000;

  const record = loginAttempts.get(ip) || { timestamps: [] };
  record.timestamps = record.timestamps.filter((t) => now - t < WINDOW_SECONDS);
  loginAttempts.set(ip, record);

  if (record.timestamps.length >= MAX_ATTEMPTS) {
    res.status(429).json({
      error: 'محاولات كثيرة. حاول مجدداً بعد خمس دقائق.',
    });
    return;
  }

  next();
}

export function recordFailedLogin(ip: string): void {
  const now = Date.now() / 1000;
  const record = loginAttempts.get(ip) || { timestamps: [] };
  record.timestamps.push(now);
  loginAttempts.set(ip, record);
}

export function clearLoginAttempts(ip: string): void {
  loginAttempts.delete(ip);
}

const cleanupTimer = setInterval(() => {
  const now = Date.now() / 1000;
  for (const [ip, record] of loginAttempts.entries()) {
    const validTimestamps = record.timestamps.filter((t) => now - t < WINDOW_SECONDS);
    if (validTimestamps.length === 0) {
      loginAttempts.delete(ip);
    } else {
      record.timestamps = validTimestamps;
    }
  }
}, Math.max(10000, WINDOW_SECONDS * 1000));
cleanupTimer.unref();
