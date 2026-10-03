import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SubactIdToolServer } from '../src/validator.js';
import { audience, FakeControlPlane, issuer } from './control-plane.js';

const start = Date.UTC(2026, 8, 12, 12, 0, 0);

describe('verified claims keep the token out of logs (invariant 2)', () => {
  let plane: FakeControlPlane;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
  });

  afterEach(() => vi.useRealTimers());

  it('leaves the token out of JSON, spreads and inspect, and still hands it to introspection', async () => {
    const server = new SubactIdToolServer({ issuer, audience, fetch: plane.fetch });
    const token = plane.token();

    const claims = await server.verifyToken(token);

    expect(JSON.stringify(claims)).not.toContain(token);
    expect(JSON.stringify({ ...claims })).not.toContain(token);
    expect(inspect(claims)).not.toContain(token);
    expect(inspect(claims, { showHidden: true, depth: Infinity })).not.toContain(token);
    expect(claims.token).toBe(token);
  });
});
