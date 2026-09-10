import { describe, it, expect } from 'vitest';
import { authService, ALL_PERMISSIONS, hasActiveAdministrator } from './auth.service.js';
import { User } from '../types/index.js';

describe('AuthService', () => {
  it('loads config and initializes default admin if needed', () => {
    const config = authService.loadConfig();
    expect(config.version).toBe(2);
    expect(config.users.length).toBeGreaterThan(0);
    expect(config.session_secret).toBeDefined();
  });

  it('authenticates valid credentials and rejects wrong passwords', () => {
    const valid = authService.authenticate('admin', 'Admin@123');
    expect(valid).not.toBeNull();
    expect(valid?.username).toBe('admin');

    const invalid = authService.authenticate('admin', 'WrongPass123');
    expect(invalid).toBeNull();
  });

  it('creates and verifies valid HMAC session tokens', () => {
    const token = authService.createSession('admin');
    expect(token).toContain('.');

    const user = authService.verifySession(token);
    expect(user).not.toBeNull();
    expect(user?.username).toBe('admin');

    const tampered = token + 'tampered';
    expect(authService.verifySession(tampered)).toBeNull();
  });

  it('provides a complete permission catalog', () => {
    const catalog = authService.permissionCatalog();
    expect(catalog.groups.length).toBe(10);
    expect(catalog.presets.administrator).toEqual(ALL_PERMISSIONS);
  });

  it('detects whether an active administrator remains', () => {
    const base = {
      id: '1', username: 'user', display_name: 'User', active: true,
      password_salt: '', password_hash: '', session_version: 1,
      created_at: '', updated_at: '',
    };
    expect(hasActiveAdministrator([{ ...base, permissions: ['users.manage'] }] as User[])).toBe(true);
    expect(hasActiveAdministrator([{ ...base, active: false, permissions: ['users.manage'] }] as User[])).toBe(false);
    expect(hasActiveAdministrator([{ ...base, permissions: ['portal.access'] }] as User[])).toBe(false);
  });
});
