import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SubactIdClient } from '../src/client.js';
import { FakeControlPlane, issuer, tokenEndpoint } from './fake-control-plane.js';
import { ecPem } from './keys.js';

const start = Date.UTC(2026, 8, 11, 12, 0, 0);

function client(plane: { fetch: typeof fetch }, extra = {}): SubactIdClient {
  return new SubactIdClient({
    issuer,
    agentId: 'jira-triage',
    kid: 'key-1',
    privateKey: ecPem,
    algorithm: 'ES256',
    fetch: plane.fetch,
    ...extra,
  });
}

describe('attack: a control plane that answers with more than was asked for', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(start);
  });
  afterEach(() => vi.useRealTimers());

  function widening(grantedScope: string, expiresIn = 300, taskTtlMs = 1_800_000): typeof fetch {
    return (async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url.endsWith('/.well-known/openid-configuration')) {
        return new Response(
          JSON.stringify({
            issuer,
            token_endpoint: tokenEndpoint,
            introspection_endpoint: `${issuer}/oauth2/introspect`,
            revocation_endpoint: `${issuer}/oauth2/revoke`,
            jwks_uri: `${issuer}/.well-known/jwks.json`,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          access_token: 'token_1',
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: expiresIn,
          scope: grantedScope,
          refresh_token: 'task_grant_1',
          task_id: 'task_1',
          task_expires_at: new Date(Date.now() + taskTtlMs).toISOString(),
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;
  }

  it('refuses an exchange whose granted scope is wider than was requested', async () => {
    const c = client({ fetch: widening('jira:read jira:admin') });
    await expect(
      c.exchange({ subjectToken: 'user', resource: 'https://jira.internal', scope: 'jira:read' }),
    ).rejects.toThrow();
  });

  it('never stores or re-requests a scope the task was not granted', async () => {
    const c = client({ fetch: widening('jira:read jira:admin') });
    const session = await c
      .exchange({ subjectToken: 'user', resource: 'https://jira.internal', scope: 'jira:read' })
      .catch(() => undefined);
    // If the session was created at all, it must not now hold the widened scope.
    expect(session?.scope ?? 'jira:read').not.toContain('jira:admin');
  });

  it('never hands out a token past the end of the task, whatever expires_in says', async () => {
    // expires_in of an hour on a task with half an hour left: the control plane broke its own
    // rule. The session must still stop at the task, not at the token.
    const c = client({ fetch: widening('jira:read', 3600, 1_800_000) });
    const session = await c.exchange({
      subjectToken: 'user',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    expect(session.expiresAt.getTime()).toBe(session.taskExpiresAt.getTime());
    await expect(session.accessToken()).resolves.toBe('token_1');

    // Once the task is over, the token goes with it rather than living out its own hour.
    vi.setSystemTime(start + 1_800_000);
    await expect(session.accessToken()).rejects.toThrow(/task/i);
    expect(session.isEnded).toBe(true);
  });
});

describe('attack: a discovery document that points somewhere else', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(start);
  });
  afterEach(() => vi.useRealTimers());

  function discovery(document: Record<string, unknown>): typeof fetch {
    return (async () =>
      new Response(JSON.stringify(document), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;
  }

  it('refuses a token_endpoint on another origin', async () => {
    const c = client({
      fetch: discovery({
        issuer,
        token_endpoint: 'https://evil.example.com/token',
        jwks_uri: `${issuer}/.well-known/jwks.json`,
      }),
    });
    await expect(c.discover()).rejects.toThrow(/not under the issuer/);
  });

  it('refuses a revocation_endpoint on another origin', async () => {
    const c = client({
      fetch: discovery({
        issuer,
        token_endpoint: tokenEndpoint,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        revocation_endpoint: 'https://evil.example.com/revoke',
        introspection_endpoint: `${issuer}/oauth2/introspect`,
      }),
    });
    await expect(c.discover()).rejects.toThrow(/not under the issuer/);
  });

  it('refuses an introspection_endpoint on another origin', async () => {
    const c = client({
      fetch: discovery({
        issuer,
        token_endpoint: tokenEndpoint,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        revocation_endpoint: `${issuer}/oauth2/revoke`,
        introspection_endpoint: 'https://evil.example.com/introspect',
      }),
    });
    await expect(c.discover()).rejects.toThrow(/not under the issuer/);
  });
});

describe('attack: narrowing against a scope that moved under us', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(start);
  });
  afterEach(() => vi.useRealTimers());

  it('does not ask for a scope the task no longer holds', async () => {
    const plane = new FakeControlPlane(() => Date.now());
    const c = client(plane);
    const session = await c.exchange({
      subjectToken: 'user',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });

    // A refresh is in flight for the full scope, and the control plane narrows it to jira:read
    // (the agent's registration lost jira:comment while the task was running).
    const first = session.refresh('jira:read');
    // A second caller asks to narrow to jira:comment, judged against the scope held *now*.
    const second = session.refresh('jira:comment');
    await first;
    const outcome = await second.then(
      (t) => ({ ok: true as const, scope: t.scope }),
      (e: unknown) => ({ ok: false as const, error: e }),
    );
    // Whatever happens, the client must never have *sent* a scope the task no longer held.
    const asked = plane.requests.map((r) => r.form.get('scope'));
    expect(asked).not.toContain('jira:comment');
    expect(outcome.ok).toBe(false);
    expect(session.scope).toBe('jira:read');
  });
});
