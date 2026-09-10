import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { helpRouter } from './routes/help.routes.js';

describe('Gateway Help Center Route', () => {
  const app = express();
  app.use(express.json());
  app.use('/api/help', helpRouter);

  it('serves USER_GUIDE.md as structured JSON via GET /api/help/guide', async () => {
    const res = await request(app).get('/api/help/guide');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body).toHaveProperty('title');
    expect(res.body).toHaveProperty('content');
    expect(typeof res.body.content).toBe('string');
    expect(res.body.content.length).toBeGreaterThan(500);
    expect(res.body.content).toContain('FlowScope');
    expect(res.body.content).toContain('LogScope');
    expect(res.body.content).toContain('Sigma');
    expect(res.body).toHaveProperty('lastModified');
    expect(res.body).toHaveProperty('sizeBytes');
    expect(res.body.sizeBytes).toBeGreaterThan(1000);
  });

  it('serves raw markdown when raw=true query parameter is present', async () => {
    const res = await request(app).get('/api/help/guide?raw=true');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/markdown');
    expect(res.text).toContain('FlowScope');
    expect(res.text).toContain('LogScope');
  });
});
