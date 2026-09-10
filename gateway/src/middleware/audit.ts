import { NextFunction, Response } from 'express';
import { randomUUID } from 'crypto';
import { AuthenticatedRequest } from './auth.js';
import { recordAudit } from '../services/audit.service.js';

function applicationFor(path: string): 'platform' | 'flowscope' | 'threatscope' | 'logscope' {
  if (path.includes('/flowscope')) return 'flowscope';
  if (path.includes('/threatscope')) return 'threatscope';
  if (path.includes('/logscope')) return 'logscope';
  return 'platform';
}

function jobFrom(path: string): string | undefined {
  return path.match(/[0-9a-f]{32}/i)?.[0];
}

function classify(method: string, path: string): { category: string; action: string; message: string } {
  if (path.includes('/auth/login')) return { category: 'authentication', action: 'login', message: 'محاولة تسجيل الدخول' };
  if (path.includes('/auth/logout')) return { category: 'authentication', action: 'logout', message: 'تسجيل الخروج من المنصة' };
  if (path.includes('/auth/account')) return { category: 'account', action: 'account_update', message: 'تحديث بيانات الحساب' };
  if (path.includes('/admin/users')) return { category: 'administration', action: method === 'DELETE' ? 'user_delete' : 'user_manage', message: 'إدارة مستخدمي المنصة وصلاحياتهم' };
  if (path.includes('/settings/test')) return { category: 'configuration', action: 'configuration_test', message: 'اختبار اتصال أحد تكاملات المنصة' };
  if (path.includes('/settings')) return { category: 'configuration', action: method === 'POST' ? 'configuration_update' : 'configuration_view', message: method === 'POST' ? 'تحديث إعدادات المنصة' : 'عرض إعدادات المنصة' };
  if (path.includes('/analyze')) return { category: 'analysis', action: 'analysis_start', message: 'رفع ملف وبدء عملية تحليل جديدة' };
  if (path.includes('/enrich')) return { category: 'enrichment', action: method === 'DELETE' ? 'enrichment_cancel' : 'enrichment_update', message: 'تشغيل أو إيقاف فحص المصادر الخارجية' };
  if (path.includes('/export/') && path.endsWith('.docx')) return { category: 'report', action: 'word_export', message: 'تصدير التقرير الرسمي بصيغة Word' };
  if (path.includes('/export/') && path.endsWith('.xlsx')) return { category: 'report', action: 'excel_export', message: 'تصدير البيانات التفصيلية بصيغة Excel' };
  if (path.includes('/preview/')) return { category: 'report', action: 'report_preview', message: 'فتح معاينة التقرير المطابقة لملف Word' };
  if (path.includes('/feedback/')) return { category: 'learning', action: 'analyst_feedback', message: 'حفظ تقييم المحلل لتطوير النموذج المحلي' };
  if (path.includes('/jobs/')) return { category: 'jobs', action: method === 'DELETE' ? 'job_delete' : 'job_view', message: method === 'DELETE' ? 'حذف مهمة تحليل' : 'قراءة نتائج مهمة تحليل' };
  if (path.includes('/history')) return { category: 'history', action: 'history_view', message: 'عرض سجل العمليات والتحليلات' };
  if (path.includes('/audit/')) return { category: 'audit', action: 'audit_view', message: 'عرض سجل التدقيق التفصيلي' };
  if (path.includes('/health') || path.includes('/services') || path.includes('/status')) return { category: 'system', action: 'status_check', message: 'التحقق من حالة إحدى خدمات المنصة' };
  return { category: 'api', action: 'api_request', message: 'طلب إلى واجهة المنصة البرمجية' };
}

function safeDetails(req: AuthenticatedRequest): Record<string, unknown> {
  const filename = req.headers['x-filename'];
  const sourceSystem = req.headers['x-source-system'];
  const body = Buffer.isBuffer(req.body)
    ? { payload_type: 'binary', payload_bytes: req.body.length }
    : (req.body && typeof req.body === 'object' ? req.body : undefined);
  return {
    filename: typeof filename === 'string' ? decodeURIComponent(filename) : undefined,
    source_system: typeof sourceSystem === 'string' ? sourceSystem : undefined,
    query: req.query,
    body,
    user_agent: req.headers['user-agent'],
    content_length: Number(req.headers['content-length'] || 0),
  };
}

export function auditMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const started = process.hrtime.bigint();
  const requestId = (req.headers['x-request-id'] as string) || `REQ-${randomUUID().replace(/-/g, '').slice(0, 10).toUpperCase()}`;
  const correlationId = (req.headers['x-correlation-id'] as string) || `CORR-${randomUUID().replace(/-/g, '').slice(0, 10).toUpperCase()}`;
  (req as any).requestId = requestId;
  (req as any).correlationId = correlationId;
  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Correlation-ID', correlationId);

  res.once('finish', () => {
    const duration = Number(process.hrtime.bigint() - started) / 1_000_000;
    const status = res.statusCode;
    const classification = classify(req.method, req.path);
    const loginName = req.path.includes('/auth/login') && req.body && typeof req.body === 'object'
      ? String((req.body as Record<string, unknown>).username || '') : undefined;
    try {
      recordAudit({
        level: status >= 500 ? 'error' : status >= 400 ? 'warning' : 'info',
        outcome: status === 401 || status === 403 ? 'denied' : status >= 400 ? 'failure' : 'success',
        ...classification,
        application: applicationFor(req.path),
        request_id: requestId,
        correlation_id: correlationId,
        user_id: req.user?.id,
        username: req.user?.username || loginName,
        display_name: req.user?.display_name,
        client_ip: req.ip || req.socket.remoteAddress,
        method: req.method,
        path: req.originalUrl,
        status_code: status,
        duration_ms: Math.round(duration * 100) / 100,
        job_id: jobFrom(req.path),
        source_system: typeof req.headers['x-source-system'] === 'string' ? req.headers['x-source-system'] : undefined,
        details: safeDetails(req),
      });
    } catch (error) {
      console.error('[Audit] failed to persist request event', error);
    }
  });
  next();
}
