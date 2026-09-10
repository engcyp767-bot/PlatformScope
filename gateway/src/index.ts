import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { HOST, PORT, ALLOWED_ORIGINS } from './config.js';
import { authMiddleware } from './middleware/auth.js';
import { authRouter } from './routes/auth.routes.js';
import { adminRouter } from './routes/admin.routes.js';
import { systemRouter } from './routes/system.routes.js';
import { flowscopeRouter } from './routes/flowscope.routes.js';
import { threatscopeRouter } from './routes/threatscope.routes.js';
import { logscopeRouter } from './routes/logscope.routes.js';
import { incidentsRouter } from './routes/incidents.routes.js';
import { detectionsRouter } from './routes/detections.routes.js';
import { sigmaRouter } from './routes/sigma.routes.js';
import { intelRouter } from './routes/intel.routes.js';
import { assetsRouter } from './routes/assets.routes.js';
import { correlationRouter } from './routes/correlation.routes.js';
import { copilotRouter } from './routes/copilot.routes.js';
import { databaseRouter } from './routes/database.routes.js';
import { enterpriseRouter } from './routes/enterprise.routes.js';
import { helpRouter } from './routes/help.routes.js';
import { authorizationRouter } from './routes/authorization.routes.js';
import { investigationsRouter } from './routes/investigations.routes.js';
import { licensingRouter } from './routes/licensing.routes.js';
import { licenseEnforcementMiddleware } from './middleware/licenseEnforcement.js';
import { auditMiddleware } from './middleware/audit.js';
import { recordAudit } from './services/audit.service.js';
import { getOperationHistory } from './services/history.service.js';

const app = express();

app.use(
  cors({
    origin: (origin, callback) => {
      callback(null, !origin || ALLOWED_ORIGINS.includes(origin));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Filename', 'X-Source-System', 'Cache-Control', 'Cookie'],
  })
);

app.use(cookieParser());
app.use('/api/flowscope/analyze', express.raw({ type: '*/*', limit: '2048mb' }));
app.use('/api/threatscope/analyze', express.raw({ type: '*/*', limit: '2048mb' }));
app.use('/api/logscope/analyze', express.raw({ type: '*/*', limit: '2048mb' }));
app.use('/api/incidents', express.json({ limit: '25mb' }));
app.use('/api/detections', express.json({ limit: '10mb' }));
app.use('/api/sigma', express.json({ limit: '10mb' }));
app.use('/api/intel', express.json({ limit: '20mb' }));
app.use('/api/assets', express.json({ limit: '10mb' }));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(authMiddleware);
app.use(auditMiddleware);
app.use(licenseEnforcementMiddleware);

app.use('/api/licensing', licensingRouter);
app.use('/api/auth', authRouter);
app.use('/api/admin', adminRouter);
app.use('/api/system', systemRouter);
app.use('/api', systemRouter);
app.use('/api/flowscope', flowscopeRouter);
app.use('/api/threatscope', threatscopeRouter);
app.use('/api/logscope', logscopeRouter);
app.use('/api/incidents', incidentsRouter);
app.use('/api/detections', detectionsRouter);
app.use('/api/sigma', sigmaRouter);
app.use('/api/intel', intelRouter);
app.use('/api/assets', assetsRouter);
app.use('/api/correlation', express.json({ limit: '10mb' }), correlationRouter);
app.use('/api/copilot', express.json({ limit: '10mb' }), copilotRouter);
app.use('/api/database', databaseRouter);
app.use('/api/enterprise', express.json({ limit: '10mb' }), enterpriseRouter);
app.use('/api/help', helpRouter);
app.use('/api/authorization', authorizationRouter);
app.use('/api/investigations', express.json({ limit: '10mb' }), investigationsRouter);

// Keep the API contract JSON even when Express rejects a body or parser input.
app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const failure = error as { status?: number; statusCode?: number; type?: string };
  const status = Number(failure.statusCode || failure.status) || 500;
  if (res.headersSent) return;
  if (status === 413 || failure.type === 'entity.too.large') {
    res.status(413).json({ error: 'حجم الملف يتجاوز الحد المسموح به في إعدادات المنصة.', code: 'upload_too_large' });
    return;
  }
  res.status(status >= 400 && status < 600 ? status : 500).json({
    error: 'تعذر معالجة طلب الرفع. لم يبدأ تحليل الملف؛ أعد المحاولة بعد التحقق من جاهزية المنصة.',
    code: 'gateway_request_error',
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, HOST, () => {
  console.log(`[SecurityBackend Node.js Gateway] running on http://${HOST}:${PORT}`);
  recordAudit({
    level: 'info', outcome: 'success', category: 'system', action: 'gateway_start',
    message: 'بدء تشغيل بوابة المنصة الموحدة', application: 'platform',
    details: { host: HOST, port: PORT, process_id: process.pid },
  });
  // Pre-warm operations history cache in the background so initial user requests are instant
  setTimeout(() => {
    try {
      getOperationHistory();
    } catch {}
  }, 100);
});
