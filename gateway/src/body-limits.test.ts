import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';

describe('Gateway Body Limits', () => {
  const app = express();

  // Replicate index.ts routing logic for testing
  app.use('/api/flowscope/analyze', express.raw({ type: '*/*', limit: '2048mb' }));
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));

  app.post('/api/flowscope/analyze', (req, res) => {
    res.status(200).json({ length: req.body.length || 0 });
  });

  app.post('/api/auth/login', (req, res) => {
    res.status(200).json({ ok: true });
  });

  const largeJsonString = JSON.stringify({ data: 'x'.repeat(2.5 * 1024 * 1024) });
  const smallJsonString = JSON.stringify({ data: 'hello' });
  const largeRawString = 'x'.repeat(10 * 1024 * 1024); // 10MB raw

  it('accepts normal JSON request < 2MB', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send(smallJsonString);
    expect(res.status).toBe(200);
  });

  it('rejects JSON request > 2MB on regular endpoint', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send(largeJsonString);
    expect(res.status).toBe(413); // Payload Too Large
  });

  it('accepts large valid analysis upload (raw)', async () => {
    const res = await request(app)
      .post('/api/flowscope/analyze')
      .set('Content-Type', 'application/octet-stream')
      .send(largeRawString);
    expect(res.status).toBe(200);
  });
});
