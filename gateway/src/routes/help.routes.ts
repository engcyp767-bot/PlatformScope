import { Router } from 'express';
import fs from 'fs';
import path from 'path';
import { WORKSPACE_ROOT } from '../config.js';

export const helpRouter = Router();

const USER_GUIDE_PATH = path.join(WORKSPACE_ROOT, 'docs', 'USER_GUIDE.md');

helpRouter.get('/guide', (req, res) => {
  try {
    if (!fs.existsSync(USER_GUIDE_PATH)) {
      res.status(404).json({
        error: 'دليل الاستخدام غير موجود على الخادم.',
        code: 'guide_not_found',
      });
      return;
    }

    const stat = fs.statSync(USER_GUIDE_PATH);
    const content = fs.readFileSync(USER_GUIDE_PATH, 'utf-8');

    if (req.query.raw === 'true') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.send(content);
      return;
    }

    res.json({
      success: true,
      title: 'دليل الاستخدام الرسمي لمنصة التحليل الأمني الموحدة',
      content,
      lastModified: stat.mtime.toISOString(),
      sizeBytes: stat.size,
    });
  } catch (error: any) {
    res.status(500).json({
      error: 'تعذر قراءة دليل الاستخدام من الخادم.',
      details: error?.message,
      code: 'guide_read_error',
    });
  }
});
