import express from 'express';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { claimsOf, subactIdExpress, type SubactIdRequest } from '../src/express.js';
import { SubactIdToolServer, type AccessEvent } from '../src/validator.js';
import { audience, FakeControlPlane, issuer } from './control-plane.js';

const start = Date.UTC(2026, 8, 12, 12, 0, 0);

describe('the Express adapter', () => {
  let plane: FakeControlPlane;
  let events: AccessEvent[];
  let subactid: SubactIdToolServer;
  let server: Server;
  let base: string;
  const handled: string[] = [];

  beforeEach(async () => {
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

    const app = express();
    // An agent-only route: a human's own token is not enough.
    app.get(
      '/issues',
      subactIdExpress(subactid, { scope: 'jira:read', requireActor: true }),
      (req, res) => {
        const claims = claimsOf(req as SubactIdRequest);
        handled.push(`issues:${claims?.sub}`);
        res.json({ sub: claims?.sub, act: claims?.act?.sub });
      },
    );
    app.post(
      '/issues/:id/comments',
      subactIdExpress(subactid, { scope: 'jira:comment', highRisk: true }),
      (req, res) => {
        handled.push(`comment:${req.params.id}`);
        res.json({ ok: true });
      },
    );
    // A route a human may call directly, as the server's own default allows.
    app.get('/whoami', subactIdExpress(subactid, {}), (req, res) => {
      handled.push('whoami');
      res.json({ sub: claimsOf(req as SubactIdRequest)?.sub });
    });
    // Loopback only: a test has no business listening on every interface of the machine it runs on.
    server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterEach(async () => {
    vi.useRealTimers();
    await new Promise((resolve) => server.close(resolve));
  });

  const get = (path: string, token?: string): Promise<Response> =>
    fetch(`${base}${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });

  it('lets an agent through and hands the route the human it acts for', async () => {
    const response = await get('/issues?q=login', plane.token());

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      act: 'agent:jira-triage',
    });
    expect(handled).toEqual(['issues:f47ac10b-58cc-4372-a567-0e02b2c3d479']);
    // The route pattern, not the query string the caller sent.
    expect(events).toMatchObject([
      { route: 'GET /issues', decision: 'allow', act: 'agent:jira-triage' },
    ]);
  });

  it('rejects a token with no act claim on an agent-only route, and the handler never runs', async () => {
    const response = await get('/issues', plane.token({ act: undefined }));

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe(
      `Bearer realm="${audience}", error="invalid_token", error_description="the token has no act claim; only an agent acting for a human may call this route."`,
    );
    expect(await response.json()).toEqual({
      error: 'invalid_token',
      error_description:
        'the token has no act claim; only an agent acting for a human may call this route.',
    });
    expect(handled).toEqual([]);
    expect(events).toMatchObject([{ route: 'GET /issues', decision: 'deny', reason: 'no_actor' }]);
  });

  it('lets that same token through on a route that does not insist on an agent', async () => {
    const response = await get('/whoami', plane.token({ act: undefined }));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' });
    expect(handled).toEqual(['whoami']);
  });

  it('answers 401 with a bare challenge when no token is presented', async () => {
    const response = await get('/issues');

    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe(`Bearer realm="${audience}"`);
    expect(handled).toEqual([]);
  });

  it('answers 403 for a token short of the route scope', async () => {
    const response = await fetch(`${base}/issues/PROJ-1/comments`, {
      method: 'POST',
      headers: { authorization: `Bearer ${plane.token({ scope: 'jira:read' })}` },
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'insufficient_scope' });
    expect(handled).toEqual([]);
    expect(events).toMatchObject([{ route: 'POST /issues/:id/comments', decision: 'deny' }]);
  });

  it('asks the control plane on a high-risk route and refuses the moment it says the token is gone', async () => {
    const token = plane.token();
    const comment = (): Promise<Response> =>
      fetch(`${base}/issues/PROJ-1/comments`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      });

    expect((await comment()).status).toBe(200);
    plane.introspection = { active: false, revocation_reason: 'operator_kill_switch' };
    const revoked = await comment();

    expect(revoked.status).toBe(401);
    expect(await revoked.json()).toMatchObject({
      error_description: 'the token is no longer active (operator_kill_switch).',
    });
    expect(plane.introspections).toEqual([token, token]);
    expect(handled).toEqual(['comment:PROJ-1']);
  });
});
