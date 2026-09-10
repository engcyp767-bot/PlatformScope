import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { AUTH_FILE, SESSION_SECONDS, COOKIE_NAME } from '../config.js';
import { AuthConfig, PermissionCode, PublicUser, User } from '../types/index.js';

const PERMISSION_GROUPS: Record<string, [PermissionCode, string][]> = {
  'عام': [
    ['portal.access', 'الدخول إلى البوابة'],
    ['history.view', 'عرض سجل العمليات'],
  ],
  'FlowScope': [
    ['flowscope.view', 'عرض FlowScope ونتائجه'],
    ['flowscope.analyze', 'رفع الملفات وبدء التحليل'],
    ['flowscope.enrich', 'فحص المصادر وتحديث النتائج'],
    ['flowscope.export', 'معاينة التقارير وتصديرها'],
    ['flowscope.feedback', 'إضافة تقييم المحلل'],
    ['flowscope.delete', 'حذف مهام التحليل'],
  ],
  'ThreatScope': [
    ['threatscope.view', 'عرض ThreatScope ونتائجه'],
    ['threatscope.analyze', 'رفع الملفات وبدء التحليل'],
    ['threatscope.enrich', 'فحص المصادر وتحديث النتائج'],
    ['threatscope.export', 'معاينة التقارير وتصديرها'],
    ['threatscope.feedback', 'إضافة تقييم المحلل'],
    ['threatscope.delete', 'حذف مهام التحليل'],
  ],
  'LogScope': [
    ['logscope.view', 'عرض LogScope ونتائجه'],
    ['logscope.analyze', 'رفع الملفات وبدء التحليل'],
    ['logscope.enrich', 'فحص المصادر وتحديث النتائج'],
    ['logscope.export', 'معاينة التقارير وتصديرها'],
    ['logscope.feedback', 'إضافة تقييم المحلل'],
    ['logscope.delete', 'حذف مهام التحليل'],
  ],
  'الحوادث': [
    ['incidents.view', 'عرض الحوادث وتفاصيلها'],
    ['incidents.manage', 'تحديث حالة الحادث وتعيين المحلل وإضافة الأدلة والملاحظات'],
    ['incidents.export', 'تصدير ملفات التحقيق الجنائي الرقمي والتحقق من سلامتها'],
    ['copilot.query', 'استخدام المساعد الأمني الذكي للتحقيق الجنائي وتوليد التوصيات'],
  ],
  'قواعد الكشف': [
    ['detections.view', 'عرض قواعد الكشف وتفاصيلها ومقاييس الأداء'],
    ['detections.manage', 'إنشاء وتعديل وتفعيل القواعد واختبارها واستيرادها وتصديرها'],
  ],
  'استخبارات التهديدات': [
    ['intel.view', 'عرض قاعدة مؤشرات التهديد (IOCs) وتفاصيلها'],
    ['intel.manage', 'إضافة وتعديل وحذف واستيراد وتصدير مؤشرات التهديد'],
  ],
  'الأصول الأمنية': [
    ['assets.view', 'عرض واستعراض سجل الأصول الأمنية ومقاييس الخطورة'],
    ['assets.manage', 'إضافة وتعديل وحذف واستيراد وتصدير الأصول'],
    ['assets.isolate', 'تنفيذ واعتماد خطط العزل الأمني للأصول'],
  ],
  'الترابط الجنائي': [
    ['correlation.view', 'عرض شبكة الرسم البياني الأمني وسلاسل الهجوم والتنقل الأفقي'],
    ['correlation.manage', 'إجراء التحليل المتقدم للترابط وترقية الأنماط إلى حوادث'],
  ],
  'الإدارة': [
    ['users.manage', 'إدارة المستخدمين والصلاحيات'],
    ['system.status', 'عرض حالة النموذج والخدمات'],
    ['database.status', 'عرض حالة محركات قواعد البيانات والتخزين'],
    ['enterprise.view', 'عرض حالة العناقيد والمستأجرين وطوابير المهام'],
    ['enterprise.manage', 'إدارة المستأجرين والحصص وسياسات الأرشفة المؤسسية'],
  ],
};

export const ALL_PERMISSIONS: PermissionCode[] = Object.values(PERMISSION_GROUPS).flatMap((items) =>
  items.map(([code]) => code)
);

export const PRESETS: Record<string, PermissionCode[]> = {
  administrator: [...ALL_PERMISSIONS],
  analyst: ALL_PERMISSIONS.filter((code) => code !== 'users.manage'),
  viewer: [
    'portal.access', 'history.view', 'incidents.view', 'detections.view', 'intel.view', 'assets.view', 'correlation.view', 'correlation.view',
    'flowscope.view', 'flowscope.export', 'threatscope.view', 'threatscope.export', 'logscope.view', 'logscope.export'
  ],
};

export function hasActiveAdministrator(users: User[]): boolean {
  return users.some((user) => user.active && user.permissions?.includes('users.manage'));
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64url');
}

function b64decode(str: string): Buffer {
  return Buffer.from(str, 'base64url');
}

function hashPassword(password: string, salt: Buffer): string {
  const derived = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
  return b64encode(derived);
}

class AuthService {
  private configCache: AuthConfig | null = null;
  private configMtime = 0;

  public permissionCatalog() {
    return {
      groups: Object.entries(PERMISSION_GROUPS).map(([name, entries]) => ({
        name,
        permissions: entries.map(([code, label]) => ({ code, label })),
      })),
      presets: PRESETS,
    };
  }

  public loadConfig(): AuthConfig {
    try {
      const stats = fs.statSync(AUTH_FILE);
      if (this.configCache && stats.mtimeMs === this.configMtime) {
        return this.configCache;
      }
      const raw = fs.readFileSync(AUTH_FILE, 'utf-8');
      const data = JSON.parse(raw) as AuthConfig;
      this.configCache = data;
      this.configMtime = stats.mtimeMs;
      return data;
    } catch {
      const initial = this.createInitialConfig();
      this.writeConfig(initial);
      return initial;
    }
  }

  private writeConfig(config: AuthConfig) {
    fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });
    const temp = `${AUTH_FILE}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(config, null, 2), 'utf-8');
    fs.renameSync(temp, AUTH_FILE);
    this.configCache = config;
    try {
      this.configMtime = fs.statSync(AUTH_FILE).mtimeMs;
    } catch {
      this.configMtime = Date.now();
    }
  }

  private createInitialConfig(): AuthConfig {
    const salt = crypto.randomBytes(24);
    const username = process.env.SECURITY_USERNAME || 'admin';
    const password = process.env.SECURITY_PASSWORD || 'Admin@123';
    const now = new Date().toISOString();

    const adminUser: User = {
      id: crypto.randomBytes(8).toString('hex'),
      username,
      display_name: 'مدير المنصة',
      active: true,
      permissions: [...ALL_PERMISSIONS],
      password_salt: b64encode(salt),
      password_hash: hashPassword(password, salt),
      session_version: 1,
      created_at: now,
      updated_at: now,
    };

    return {
      version: 2,
      session_secret: b64encode(crypto.randomBytes(48)),
      users: [adminUser],
    };
  }

  public toPublicUser(user: User): PublicUser {
    return {
      id: user.id,
      username: user.username,
      display_name: user.display_name || user.username,
      active: user.active,
      permissions: user.permissions || [],
      created_at: user.created_at,
      updated_at: user.updated_at,
    };
  }

  public authenticate(username: string, password: string): PublicUser | null {
    const config = this.loadConfig();
    const user = config.users.find(
      (u) => u.username.toLowerCase() === username.trim().toLowerCase()
    );
    if (!user || !user.active || !user.password_salt || !user.password_hash) {
      return null;
    }
    const salt = b64decode(user.password_salt);
    const expected = hashPassword(password, salt);
    if (crypto.timingSafeEqual(Buffer.from(user.password_hash), Buffer.from(expected))) {
      return this.toPublicUser(user);
    }
    return null;
  }

  public createSession(username: string): string {
    const config = this.loadConfig();
    const user = config.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    if (!user || !user.active) throw new Error('User is unavailable');

    const now = Math.floor(Date.now() / 1000);
    const payloadObj = {
      id: user.id,
      v: user.session_version || 1,
      iat: now,
      exp: now + SESSION_SECONDS,
      n: crypto.randomBytes(9).toString('base64url'),
    };
    const payloadStr = b64encode(Buffer.from(JSON.stringify(payloadObj)));
    const secret = b64decode(config.session_secret);
    const hmac = crypto.createHmac('sha256', secret).update(payloadStr).digest();
    const sigStr = b64encode(hmac);
    return `${payloadStr}.${sigStr}`;
  }

  public verifySession(token: string | undefined): PublicUser | null {
    if (!token || !token.includes('.')) return null;
    try {
      const [payloadStr, sigStr] = token.split('.');
      const config = this.loadConfig();
      const secret = b64decode(config.session_secret);
      const expectedHmac = crypto.createHmac('sha256', secret).update(payloadStr).digest();
      const expectedSig = b64encode(expectedHmac);

      if (!crypto.timingSafeEqual(Buffer.from(sigStr), Buffer.from(expectedSig))) {
        return null;
      }
      const data = JSON.parse(b64decode(payloadStr).toString('utf-8'));
      if (typeof data.exp !== 'number' || data.exp < Math.floor(Date.now() / 1000)) {
        return null;
      }
      const user = config.users.find((u) => u.id === data.id);
      if (!user || !user.active || (user.session_version || 1) !== data.v) {
        return null;
      }
      return this.toPublicUser(user);
    } catch {
      return null;
    }
  }

  public sessionCookie(token: string): string {
    return `${COOKIE_NAME}=${token}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; SameSite=Strict`;
  }

  public expiredCookie(): string {
    return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict`;
  }

  public listUsers(): PublicUser[] {
    const config = this.loadConfig();
    return config.users.map((u) => this.toPublicUser(u));
  }

  public createUser(payload: {
    username: string;
    password: string;
    display_name: string;
    permissions: PermissionCode[];
    active?: boolean;
  }): PublicUser {
    const config = this.loadConfig();
    const username = payload.username.trim();
    if (!/^[^\s/\\:]{3,64}$/.test(username)) {
      throw new Error('اسم المستخدم يجب أن يكون بين 3 و64 حرفاً ومن دون مسافات.');
    }
    if (config.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
      throw new Error('اسم المستخدم مستخدم بالفعل.');
    }
    if (!payload.password || payload.password.length < 8) {
      throw new Error('يجب ألا تقل كلمة المرور عن 8 أحرف.');
    }

    const salt = crypto.randomBytes(24);
    const now = new Date().toISOString();
    const newUser: User = {
      id: crypto.randomBytes(8).toString('hex'),
      username,
      display_name: payload.display_name.trim() || username,
      active: payload.active !== false,
      permissions: payload.permissions.filter((p) => ALL_PERMISSIONS.includes(p)),
      password_salt: b64encode(salt),
      password_hash: hashPassword(payload.password, salt),
      session_version: 1,
      created_at: now,
      updated_at: now,
    };
    config.users.push(newUser);
    this.writeConfig(config);
    return this.toPublicUser(newUser);
  }

  public updateUser(
    userId: string,
    payload: {
      username?: string;
      display_name?: string;
      password?: string;
      permissions?: PermissionCode[];
      active?: boolean;
    }
  ): PublicUser {
    const config = this.loadConfig();
    const user = config.users.find((u) => u.id === userId);
    if (!user) throw new Error('المستخدم غير موجود.');

    const nextPermissions = payload.permissions !== undefined
      ? payload.permissions.filter((permission) => ALL_PERMISSIONS.includes(permission))
      : user.permissions;
    const nextActive = payload.active !== undefined ? payload.active : user.active;
    const remainingUsers = config.users.map((candidate) => candidate.id === userId
      ? { ...candidate, active: nextActive, permissions: nextPermissions }
      : candidate);
    if (!hasActiveAdministrator(remainingUsers)) {
      throw new Error('يجب الإبقاء على مدير واحد نشط على الأقل بصلاحية إدارة المستخدمين.');
    }

    if (payload.username !== undefined) {
      const username = payload.username.trim();
      if (!/^[^\s/\\:]{3,64}$/.test(username)) {
        throw new Error('اسم المستخدم يجب أن يكون بين 3 و64 حرفاً ومن دون مسافات.');
      }
      const duplicate = config.users.find(
        (u) => u.id !== userId && u.username.toLowerCase() === username.toLowerCase()
      );
      if (duplicate) throw new Error('اسم المستخدم مستخدم بالفعل.');
      user.username = username;
      user.session_version = (user.session_version || 1) + 1;
    }

    if (payload.display_name !== undefined) {
      user.display_name = payload.display_name.trim();
    }

    if (payload.permissions !== undefined) {
      user.permissions = nextPermissions;
    }

    if (payload.active !== undefined) {
      user.active = payload.active;
      if (!user.active) {
        user.session_version = (user.session_version || 1) + 1;
      }
    }

    if (payload.password) {
      if (payload.password.length < 8) {
        throw new Error('يجب ألا تقل كلمة المرور عن 8 أحرف.');
      }
      const salt = crypto.randomBytes(24);
      user.password_salt = b64encode(salt);
      user.password_hash = hashPassword(payload.password, salt);
      user.session_version = (user.session_version || 1) + 1;
    }

    user.updated_at = new Date().toISOString();
    this.writeConfig(config);
    return this.toPublicUser(user);
  }

  public deleteUser(userId: string): void {
    const config = this.loadConfig();
    const index = config.users.findIndex((u) => u.id === userId);
    if (index === -1) throw new Error('المستخدم غير موجود.');
    if (!hasActiveAdministrator(config.users.filter((user) => user.id !== userId))) {
      throw new Error('لا يمكن حذف آخر مدير نشط للمنصة.');
    }
    config.users.splice(index, 1);
    this.writeConfig(config);
  }
}

export const authService = new AuthService();
