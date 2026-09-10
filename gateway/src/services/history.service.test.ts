import { describe, expect, it } from 'vitest';

import { jobTargetUrl } from './history.service.js';

describe('jobTargetUrl', () => {
  it('builds path-based result links for all applications', () => {
    const jobId = 'a'.repeat(32);

    expect(jobTargetUrl('flowscope', jobId)).toBe(`/flowscope/${jobId}`);
    expect(jobTargetUrl('threatscope', jobId)).toBe(`/threatscope/${jobId}`);
    expect(jobTargetUrl('logscope', jobId)).toBe(`/logscope/${jobId}`);
  });
});
