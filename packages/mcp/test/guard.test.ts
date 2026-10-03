import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  InsufficientScopeError,
  InvalidTokenError,
  ServerError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { SubactIdGuard, type CallEvent } from '../src/guard.js';
import { SubactIdAuthError } from '../src/index.js';
import { audience, FakeControlPlane, issuer } from '../../server/test/control-plane.js';

const start = Date.UTC(2026, 8, 11, 12, 0, 0);

describe('SubactIdGuard token verification', () => {
  let plane: FakeControlPlane;
  let events: CallEvent[];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
    events = [];
  });

  afterEach(() => vi.useRealTimers());

  function guard(
    extra: Partial<ConstructorParameters<typeof SubactIdGuard>[0]> = {},
  ): SubactIdGuard {
    return new SubactIdGuard({
      issuer,
      audience,
      tools: {
        search_issues: { scope: 'jira:read' },
        add_comment: { scope: ['jira:read', 'jira:comment'], highRisk: true },
      },
      fetch: plane.fetch,
      log: (e) => events.push(e),
      ...extra,
    });
  }

  async function refusal(promise: Promise<unknown>): Promise<SubactIdAuthError> {
    const error = await promise.then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SubactIdAuthError);
    return error as SubactIdAuthError;
  }

  it('accepts a token the control plane signed for this audience and maps it to AuthInfo', async () => {
    const token = plane.token();

    const auth = await guard().verify(token);

    expect(auth.token).toBe(token);
    expect(auth.clientId).toBe('agent:jira-triage');
    expect(auth.scopes).toEqual(['jira:read', 'jira:comment']);
    expect(auth.expiresAt).toBe(start / 1000 + 300);
    const subactid = (
      auth.extra as {
        subactid: { sub: string; act?: { sub: string; depth: number }; taskId?: string };
      }
    ).subactid;
    expect(subactid.sub).toBe('f47ac10b-58cc-4372-a567-0e02b2c3d479');
    expect(subactid.act).toMatchObject({ sub: 'agent:jira-triage', depth: 1 });
    expect(subactid.taskId).toBe('task_01HQZX9K4M');
    expect(plane.jwksFetches).toBe(1);
  });

  it('reads the bearer token out of an Authorization header and refuses anything else', async () => {
    const g = guard();
    expect((await g.authenticate(`Bearer ${plane.token()}`)).clientId).toBe('agent:jira-triage');
    expect((await g.authenticate(`bearer ${plane.token()}`)).clientId).toBe('agent:jira-triage');
    expect((await refusal(g.authenticate(undefined))).reason).toBe('missing_token');
    expect((await refusal(g.authenticate('Bearer '))).reason).toBe('missing_token');
    expect((await refusal(g.authenticate('Basic abc'))).reason).toBe('missing_token');
    expect((await refusal(g.authenticate(['Bearer a', 'Bearer b']))).reason).toBe('missing_token');
    const refused = await refusal(g.authenticate(undefined));
    expect(refused.status).toBe(401);
    expect(refused.wwwAuthenticate('jira')).toBe('Bearer realm="jira"');
  });

  it.each([
    ['a forged signature', (p: FakeControlPlane) => p.forged(), 'invalid_signature', 401],
    [
      'another issuer',
      (p: FakeControlPlane) => p.token({ iss: 'https://other.example' }),
      'wrong_issuer',
      401,
    ],
    [
      'another audience',
      (p: FakeControlPlane) => p.token({ aud: 'https://confluence.internal' }),
      'wrong_audience',
      401,
    ],
    [
      'an audience list without this server',
      (p: FakeControlPlane) => p.token({ aud: ['https://a', 'https://b'] }),
      'wrong_audience',
      401,
    ],
    [
      'an expired token',
      (p: FakeControlPlane) => p.token({ exp: start / 1000 - 61 }),
      'expired',
      401,
    ],
    ['no exp', (p: FakeControlPlane) => p.token({ exp: undefined }), 'expired', 401],
    [
      'a token from the future',
      (p: FakeControlPlane) => p.token({ nbf: start / 1000 + 120 }),
      'not_yet_valid',
      401,
    ],
    [
      'a client assertion (typ JWT)',
      (p: FakeControlPlane) => p.token({}, { typ: 'JWT' }),
      'wrong_type',
      401,
    ],
    [
      'an RS256 header',
      (p: FakeControlPlane) => p.token({}, { alg: 'RS256' }),
      'unsupported_algorithm',
      401,
    ],
    ['an unknown kid', (p: FakeControlPlane) => p.token({}, { kid: 'nope' }), 'unknown_key', 401],
    ['no sub', (p: FakeControlPlane) => p.token({ sub: undefined }), 'no_subject', 401],
    [
      'an agent as the subject',
      (p: FakeControlPlane) => p.token({ sub: 'agent:jira-triage' }),
      'subject_is_agent',
      401,
    ],
    ['no jti', (p: FakeControlPlane) => p.token({ jti: undefined }), 'malformed_token', 401],
    ['no act', (p: FakeControlPlane) => p.token({ act: undefined }), 'no_actor', 401],
    [
      'an act whose sub is not an agent',
      (p: FakeControlPlane) => p.token({ act: { sub: 'someone', depth: 1 } }),
      'malformed_token',
      401,
    ],
    [
      'an act chain with a wrong depth',
      (p: FakeControlPlane) => p.token({ act: { sub: 'agent:a', depth: 2 } }),
      'malformed_token',
      401,
    ],
    [
      'a delegation deeper than allowed',
      (p: FakeControlPlane) =>
        p.token({ act: { sub: 'agent:b', depth: 2, act: { sub: 'agent:a', depth: 1 } } }),
      'delegation_too_deep',
      403,
    ],
    ['garbage', () => 'not.a.jwt', 'malformed_token', 401],
    ['two segments', () => 'a.b', 'malformed_token', 401],
  ])('refuses %s', async (_, make, reason, status) => {
    const refused = await refusal(guard().verify(make(plane)));
    expect(refused.reason).toBe(reason);
    expect(refused.status).toBe(status);
    expect(refused.message).not.toContain('eyJ');
  });

  it('tolerates clock skew within the configured bound', async () => {
    expect(await guard().verify(plane.token({ exp: start / 1000 - 30 }))).toBeTruthy();
    expect(await guard().verify(plane.token({ nbf: start / 1000 + 30 }))).toBeTruthy();
    expect(
      (
        await refusal(
          guard({ clockSkewSeconds: 5 }).verify(plane.token({ exp: start / 1000 - 30 })),
        )
      ).reason,
    ).toBe('expired');
  });

  it('lets a human call directly only when told to, and a deeper chain only when told to', async () => {
    const direct = plane.token({ act: undefined, client_id: undefined });
    expect((await guard({ requireActor: false }).verify(direct)).clientId).toBe(
      'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    );
    const nested = plane.token({
      client_id: 'agent:b',
      act: { sub: 'agent:b', depth: 2, act: { sub: 'agent:a', depth: 1 } },
    });
    expect((await guard({ maxDelegationDepth: 2 }).verify(nested)).clientId).toBe('agent:b');
    expect(() => guard({ maxDelegationDepth: 0 })).toThrow('maxDelegationDepth');
  });

  it('fetches the keys again for an unknown kid, at most every thirty seconds, and serves the old set while the fetch fails', async () => {
    const g = guard();
    await g.verify(plane.token());
    plane.rotate('key-2');

    // Right after a fetch, an unknown kid is refused without another fetch; thirty seconds on, it is fetched for.
    expect((await refusal(g.verify(plane.token({}, {}, 'key-2')))).reason).toBe('unknown_key');
    expect(plane.jwksFetches).toBe(1);
    vi.setSystemTime(start + 31_000);
    expect((await g.verify(plane.token({}, {}, 'key-2'))).clientId).toBe('agent:jira-triage');
    expect(plane.jwksFetches).toBe(2);

    // A stream of unknown kids is one fetch per thirty seconds, not one per token.
    for (let i = 0; i < 5; i++) {
      expect((await refusal(g.verify(plane.token({}, { kid: 'nope' })))).reason).toBe(
        'unknown_key',
      );
    }
    expect(plane.jwksFetches).toBe(2);
    vi.setSystemTime(start + 62_000);
    await refusal(g.verify(plane.token({}, { kid: 'nope' })));
    expect(plane.jwksFetches).toBe(3);

    // After the TTL the set is fetched again; a failed fetch keeps the last good set.
    vi.setSystemTime(start + 12 * 60_000);
    plane.jwksFails = true;
    expect((await g.verify(plane.token({}, {}, 'key-2'))).clientId).toBe('agent:jira-triage');
    expect(plane.jwksFetches).toBe(4);
  });

  it('throws the MCP SDK error types from verifyAccessToken, so the SDK middleware answers 401, 403 or 500', async () => {
    const g = guard();
    await expect(g.verifyAccessToken(plane.forged())).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(g.verifyAccessToken(plane.forged())).rejects.toThrow(
      'invalid_signature: The token signature does not verify.',
    );
    const nested = plane.token({
      act: { sub: 'agent:b', depth: 2, act: { sub: 'agent:a', depth: 1 } },
    });
    await expect(g.verifyAccessToken(nested)).rejects.toBeInstanceOf(InsufficientScopeError);
    plane.jwksStatus = 502;
    await expect(guard().verifyAccessToken(plane.token())).rejects.toBeInstanceOf(ServerError);
    plane.jwksStatus = 200;
    // authenticate() keeps the package's own error with its reason.
    await expect(g.authenticate('Bearer ' + plane.forged())).rejects.toBeInstanceOf(
      SubactIdAuthError,
    );
  });

  it('takes the client id from the token, and only otherwise from the actor or the subject', async () => {
    expect((await guard().verify(plane.token({ client_id: 'agent:jira-triage' }))).clientId).toBe(
      'agent:jira-triage',
    );
    expect((await guard().verify(plane.token({ client_id: undefined }))).clientId).toBe(
      'agent:jira-triage',
    );
    const direct = plane.token({ act: undefined, client_id: undefined });
    expect((await guard({ requireActor: false }).verify(direct)).clientId).toBe(
      'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    );
  });

  it('does not fetch the keys again more than once per thirty seconds while they are stale and the fetch keeps failing', async () => {
    const g = guard();
    await g.verify(plane.token());
    vi.setSystemTime(start + 12 * 60_000);
    plane.jwksFails = true;
    for (let i = 0; i < 10; i++) {
      expect((await g.verify(plane.token())).clientId).toBe('agent:jira-triage');
    }
    expect(plane.jwksFetches).toBe(2);
    vi.setSystemTime(start + 12 * 60_000 + 31_000);
    await g.verify(plane.token());
    expect(plane.jwksFetches).toBe(3);
  });

  it('keeps the last good keys when the JWKS answer is not JSON or not an object, and is a 503 before any', async () => {
    const g = guard();
    await g.verify(plane.token());
    vi.setSystemTime(start + 12 * 60_000);
    plane.jwksRaw = '<html>maintenance</html>';
    expect((await g.verify(plane.token())).clientId).toBe('agent:jira-triage');
    vi.setSystemTime(start + 13 * 60_000);
    plane.jwksRaw = 'null';
    expect((await g.verify(plane.token())).clientId).toBe('agent:jira-triage');

    plane.jwksRaw = '<html>maintenance</html>';
    const fresh = await refusal(guard().verify(plane.token()));
    expect(fresh.reason).toBe('keys_unavailable');
    expect(fresh.status).toBe(503);
  });

  it('bounds every call to the control plane with a timeout', async () => {
    const g = guard();
    const auth = await g.verify(plane.token());
    await g.decide('add_comment', auth);
    expect(plane.unsignalled).toEqual([]);
    expect(() => guard({ timeoutMs: 0 })).toThrow('timeoutMs');
  });

  it('is a 503, not a 401, when the keys have never been fetched and cannot be', async () => {
    plane.jwksStatus = 502;
    const refused = await refusal(guard().verify(plane.token()));
    expect(refused.reason).toBe('keys_unavailable');
    expect(refused.status).toBe(503);
  });

  it('ignores keys that are not P-256 signing keys', async () => {
    plane.keys.push({
      kid: 'rsa',
      privateKey: plane.keys[0]!.privateKey,
      publicJwk: { kty: 'RSA', n: 'AQAB', e: 'AQAB' },
    });
    expect((await refusal(guard().verify(plane.token({}, { kid: 'rsa' })))).reason).toBe(
      'unknown_key',
    );
  });
});

describe('SubactIdGuard decisions', () => {
  let plane: FakeControlPlane;
  let events: CallEvent[];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
    events = [];
  });

  afterEach(() => vi.useRealTimers());

  function guard(
    extra: Partial<ConstructorParameters<typeof SubactIdGuard>[0]> = {},
  ): SubactIdGuard {
    return new SubactIdGuard({
      issuer,
      audience,
      tools: {
        search_issues: { scope: 'jira:read' },
        add_comment: { scope: ['jira:read', 'jira:comment'], highRisk: true },
      },
      fetch: plane.fetch,
      log: (e) => events.push(e),
      ...extra,
    });
  }

  it('allows a listed tool whose scopes the token carries, and logs who acted for whom', async () => {
    const g = guard();
    const auth = await g.verify(plane.token());

    expect(await g.decide('search_issues', auth)).toBeUndefined();

    expect(events).toEqual([
      {
        event: 'tool.call',
        at: '2026-09-11T12:00:00.000Z',
        tool: 'search_issues',
        decision: 'allow',
        sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        act: 'agent:jira-triage',
        instance: 'pod-7f9c4b',
        depth: 1,
        task_id: 'task_01HQZX9K4M',
        jti: expect.stringMatching(/^tok_/),
      },
    ]);
    expect(JSON.stringify(events)).not.toContain(auth.token);
  });

  it('refuses a call made after the token expired, though it was verified while it was live', async () => {
    const g = guard({ clockSkewSeconds: 10 });
    const auth = await g.verify(plane.token({ exp: start / 1000 + 60 }));
    expect(await g.decide('search_issues', auth)).toBeUndefined();

    vi.setSystemTime(start + 69_000);
    expect(await g.decide('search_issues', auth)).toBeUndefined();
    vi.setSystemTime(start + 70_000);
    const refused = await g.decide('search_issues', auth);
    expect(refused?.reason).toBe('expired');
    expect(refused?.status).toBe(401);
    expect(events.at(-1)).toMatchObject({ decision: 'deny', reason: 'expired' });
  });

  it('refuses a call without a verified token, an unlisted tool, and a token short of a scope, each logged', async () => {
    const g = guard();
    const auth = await g.verify(plane.token({ scope: 'jira:read' }));

    expect((await g.decide('search_issues', undefined))?.reason).toBe('missing_token');
    expect((await g.decide('delete_project', auth))?.reason).toBe('unknown_tool');
    const short = await g.decide('add_comment', auth);
    expect(short?.reason).toBe('insufficient_scope');
    expect(short?.message).toBe('the token lacks scope jira:comment.');

    expect(events.map((e) => [e.tool, e.decision, e.reason])).toEqual([
      ['search_issues', 'deny', 'missing_token'],
      ['delete_project', 'deny', 'unknown_tool'],
      ['add_comment', 'deny', 'insufficient_scope'],
    ]);
    expect(events[0]?.sub).toBeUndefined();
    expect(events[2]?.sub).toBe('f47ac10b-58cc-4372-a567-0e02b2c3d479');
  });

  it('introspects a token the control plane marked high risk, once per call rather than twice', async () => {
    const g = guard();
    const token = plane.token({ introspect_required: true });

    // `verify` guards the transport and `decide` guards the tool. The audience-level decision
    // is settled once for the call the transport authenticated, so that call costs one round
    // trip and not one for each gate.
    const auth = await g.verify(token);
    expect(plane.introspections).toEqual([token]);

    // search_issues is not marked high risk; it needs introspecting anyway, because the token
    // says the audience does — and the transport just did it, for this call.
    expect(await g.decide('search_issues', auth)).toBeUndefined();
    expect(plane.introspections).toEqual([token]);

    // The next call is a new call. The transport's answer was spent on the last one, so this
    // one asks again: one round trip per call, never two and never none.
    expect(await g.decide('add_comment', auth)).toBeUndefined();
    expect(plane.introspections).toEqual([token, token]);
  });

  it('introspects a high-risk tool on every call and refuses a token the control plane no longer vouches for', async () => {
    const g = guard();
    const token = plane.token();
    const auth = await g.verify(token);

    expect(await g.decide('add_comment', auth)).toBeUndefined();
    expect(await g.decide('add_comment', auth)).toBeUndefined();
    expect(plane.introspections).toEqual([token, token]);
    expect(await g.decide('search_issues', auth)).toBeUndefined();
    expect(plane.introspections).toHaveLength(2);

    plane.introspection = {
      active: false,
      revoked_at: '2026-09-11T12:05:11Z',
      revocation_reason: 'operator_kill_switch',
    };
    const revoked = await g.decide('add_comment', auth);
    expect(revoked?.reason).toBe('not_active');
    expect(revoked?.message).toBe('the token is no longer active (operator_kill_switch).');

    plane.introspection = { active: true, sub: 'someone-else' };
    expect((await g.decide('add_comment', auth))?.reason).toBe('not_active');
    plane.introspection = {
      active: true,
      sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      jti: 'other',
    };
    expect((await g.decide('add_comment', auth))?.reason).toBe('not_active');
  });

  it('fails closed when introspection cannot be had', async () => {
    const g = guard();
    const auth = await g.verify(plane.token());

    plane.introspectionFails = true;
    expect((await g.decide('add_comment', auth))?.reason).toBe('introspection_unavailable');
    plane.introspectionFails = false;
    plane.introspectionStatus = 500;
    expect((await g.decide('add_comment', auth))?.reason).toBe('introspection_unavailable');
    plane.introspectionStatus = 200;
    plane.introspection = { active: 'yes' } as unknown as Record<string, unknown>;
    expect((await g.decide('add_comment', auth))?.reason).toBe('not_active');
  });

  it('refuses a tool policy with no scope, so nothing is ever open by omission', () => {
    expect(() => guard({ tools: { anything: { scope: '' } } })).toThrow('lists no scope');
    expect(() => guard({ tools: { anything: { scope: [] } } })).toThrow('lists no scope');
  });
});
