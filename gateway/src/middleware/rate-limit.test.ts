import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { loginRateLimiter, recordFailedLogin, clearLoginAttempts } from './rate-limit.js';

describe('Rate Limiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('allows requests within limits and removes expired attempts', () => {
    const req: any = { ip: '192.168.1.1' };
    const res: any = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();

    // Mock initial time
    vi.setSystemTime(1000000000);

    for (let i = 0; i < 5; i++) {
      recordFailedLogin(req.ip);
    }

    // Now it should reject
    loginRateLimiter(req, res, next);
    expect(res.status).toHaveBeenCalledWith(429);
    expect(next).not.toHaveBeenCalled();

    // Advance time by 6 minutes
    vi.advanceTimersByTime(360 * 1000);

    res.status.mockClear();
    next.mockClear();

    // The middleware itself cleans up expired attempts on the fly 
    // AND our setInterval cleans up memory in the background
    loginRateLimiter(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});
