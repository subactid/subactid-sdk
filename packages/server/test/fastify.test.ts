import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  subactIdFastify,
  subactIdFastifyPlugin,
  type SubactIdFastifyRequest,
} from '../src/fastify.js';
import { SubactIdToolServer, type AccessEvent } from '../src/validator.js';
import { audience, FakeControlPlane, issuer } from './control-plane.js';

const start = Date.UTC(2026, 8, 12, 12, 0, 0);

describe('the Fastify adapter', () => {
  let plane: FakeControlPlane;
  let events: AccessEvent[];
  let subactid: SubactIdToolServer;
  const handled: string[] = [];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
    events = [];
    handled.length = 0;
    subactid = new SubactIdToolServer({
      issuer,
      audience,
      requireActor: false,
      fetch: plane.fetch,
      log: (e) => events.push(e),
    });
  });

  afterEach(() => vi.useRealTimers());

  /** Routes guarded one at a time by the hook. */
  function perRoute(): FastifyInstance {
    const app = Fastify();
    app.get(
      '/issues',
      { onRequest: subactIdFastify(subactid, { scope: 'jira:read', requireActor: true }) },
      async (request) => {
        const claims = (request as SubactIdFastifyRequest).subactid;
        handled.push(`issues:${claims?.sub}`);
        return { sub: claims?.sub, act: claims?.act?.sub };
      },
    );
    app.get('/whoami', { onRequest: subactIdFastify(subactid, {}) }, async (request) => {
      handled.push('whoami');
      return { sub: (request as SubactIdFastifyRequest).subactid?.sub };
    });
    return app;
  }

  /** Every route in the scope guarded by the plugin, each with its policy in its own config. */
  async function byPlugin(): Promise<FastifyInstance> {
    const app = Fastify();
    await app.register(subactIdFastifyPlugin(subactid));
    app.get(
      '/issues',
      { config: { subactid: { scope: 'jira:read', requireActor: true } } },
      async () => {
        handled.push('issues');
        return { ok: true };
      },
    );
    app.post(
      '/comments',
      { config: { subactid: { scope: 'jira:comment', highRisk: true } } },
      async () => {
        handled.push('comment');
        return { ok: true };
      },
    );
    app.get('/forgotten', async () => {
      handled.push('forgotten');
      return { ok: true };
    });
    return app;
  }

  const auth = (token: string): { authorization: string } => ({ authorization: `Bearer ${token}` });

  it('lets an agent through and hands the route the human it acts for', async () => {
    const app = perRoute();

    const response = await app.inject({
      method: 'GET',
      url: '/issues?q=login',
      headers: auth(plane.token()),
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      act: 'agent:jira-triage',
    });
    expect(events).toMatchObject([{ route: 'GET /issues', decision: 'allow' }]);
  });

  it('rejects a token with no act claim on an agent-only route, and the handler never runs', async () => {
    const app = perRoute();

    const response = await app.inject({
      method: 'GET',
      url: '/issues',
      headers: auth(plane.token({ act: undefined })),
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
    expect(response.json()).toEqual({
      error: 'invalid_token',
      error_description:
        'the token has no act claim; only an agent acting for a human may call this route.',
    });
    expect(handled).toEqual([]);
    expect(events).toMatchObject([{ route: 'GET /issues', decision: 'deny', reason: 'no_actor' }]);
  });

  it('lets that same token through on a route that does not insist on an agent', async () => {
    const app = perRoute();

    const response = await app.inject({
      method: 'GET',
      url: '/whoami',
      headers: auth(plane.token({ act: undefined })),
    });

    expect(response.statusCode).toBe(200);
    expect(handled).toEqual(['whoami']);
  });

  it('answers 401 with a bare challenge when no token is presented', async () => {
    const response = await perRoute().inject({ method: 'GET', url: '/issues' });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe(`Bearer realm="${audience}"`);
    expect(handled).toEqual([]);
  });

  it('guards every route in the scope it is registered on, taking each policy from the route config', async () => {
    const app = await byPlugin();

    expect(
      (await app.inject({ method: 'GET', url: '/issues', headers: auth(plane.token()) }))
        .statusCode,
    ).toBe(200);
    const short = await app.inject({
      method: 'POST',
      url: '/comments',
      headers: auth(plane.token({ scope: 'jira:read' })),
    });
    expect(short.statusCode).toBe(403);
    expect(short.json()).toMatchObject({ error: 'insufficient_scope' });
    expect(handled).toEqual(['issues']);
    expect(events.map((e) => [e.route, e.decision])).toEqual([
      ['GET /issues', 'allow'],
      ['POST /comments', 'deny'],
    ]);
  });

  it('refuses a route whose policy someone forgot, and records the refusal as one', async () => {
    const app = await byPlugin();

    const response = await app.inject({
      method: 'GET',
      url: '/forgotten',
      headers: auth(plane.token()),
    });

    expect(response.statusCode).toBe(403);
    expect(response.headers['www-authenticate']).toContain('error="insufficient_scope"');
    expect(response.json()).toEqual({
      error: 'insufficient_scope',
      error_description: 'the route has no access policy, so nobody may call it.',
    });
    expect(handled).toEqual([]);
    expect(events).toMatchObject([
      { route: 'GET /forgotten', decision: 'deny', reason: 'unknown_route' },
    ]);
  });

  it('answers a path that is no route at all without letting it look like an allowed request', async () => {
    const app = await byPlugin();

    const response = await app.inject({ method: 'GET', url: '/nothing-here' });

    expect(response.statusCode).toBe(403);
    expect(events).toMatchObject([{ decision: 'deny', reason: 'unknown_route' }]);
  });

  it('leaves a route out of the guard only when it is named, and only the method named', async () => {
    const app = Fastify();
    await app.register(subactIdFastifyPlugin(subactid, { unguarded: ['GET /healthz'] }));
    app.get('/healthz', async () => {
      handled.push('healthz');
      return { status: 'ok' };
    });
    app.post('/healthz', async () => {
      handled.push('healthz:post');
      return { status: 'ok' };
    });

    expect((await app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: '/healthz' })).statusCode).toBe(403);
    expect(handled).toEqual(['healthz']);
    expect(events).toMatchObject([
      { route: 'POST /healthz', decision: 'deny', reason: 'unknown_route' },
    ]);
  });

  it('guards a route that has a policy even if its path is named unguarded', async () => {
    const app = Fastify();
    await app.register(subactIdFastifyPlugin(subactid, { unguarded: ['/issues'] }));
    app.get('/issues', { config: { subactid: { scope: 'jira:admin' } } }, async () => {
      handled.push('issues');
      return { ok: true };
    });

    const response = await app.inject({
      method: 'GET',
      url: '/issues',
      headers: auth(plane.token()),
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      error_description: 'the token lacks scope jira:admin.',
    });
    expect(handled).toEqual([]);
  });
});
