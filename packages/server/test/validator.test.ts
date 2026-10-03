import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SubactIdAuthError } from '../src/errors.js';
import { SubactIdToolServer, type AccessEvent } from '../src/validator.js';
import { audience, FakeControlPlane, issuer } from './control-plane.js';

const start = Date.UTC(2026, 8, 12, 12, 0, 0);

describe('SubactIdToolServer', () => {
  let plane: FakeControlPlane;
  let events: AccessEvent[];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
    events = [];
  });

  afterEach(() => vi.useRealTimers());

  function server(
    extra: Partial<ConstructorParameters<typeof SubactIdToolServer>[0]> = {},
  ): SubactIdToolServer {
    return new SubactIdToolServer({
      issuer,
      audience,
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

  describe('step 1: the keys', () => {
    it('reads a refusal of the keys request, and passes the interval it named to the caller', async () => {
      // The keys request shares the control plane's rate limit with everything else a busy agent
      // fleet is doing (spec section 8). A tool server that saw only the status would retry on a
      // schedule of its own and spend the next bucket too.
      plane.jwksStatus = 429;
      plane.jwksRefusal = {
        body: { error: 'slow_down', error_description: 'Too many requests.' },
        headers: { 'retry-after': '2' },
      };
      const s = server();

      const refused = await refusal(s.verifyToken(plane.token()));

      expect([refused.reason, refused.status, refused.retryAfterSeconds]).toEqual([
        'keys_unavailable',
        503,
        2,
      ]);
      expect(refused.message).toContain('rate limiting this source');
      expect(s.refusal(refused).headers['retry-after']).toBe('2');
    });

    it('reports a refusal the control plane did not name by its status alone', async () => {
      plane.jwksStatus = 502;
      const s = server();

      const refused = await refusal(s.verifyToken(plane.token()));

      expect([refused.reason, refused.status, refused.retryAfterSeconds]).toEqual([
        'keys_unavailable',
        503,
        undefined,
      ]);
      expect(s.refusal(refused).headers['retry-after']).toBeUndefined();
    });

    it('keeps serving the keys it holds when the next fetch is refused', async () => {
      const s = server();
      expect((await s.verifyToken(plane.token())).sub).toBeTypeOf('string');

      plane.jwksStatus = 429;
      plane.jwksRefusal = { body: { error: 'slow_down' }, headers: { 'retry-after': '2' } };
      vi.setSystemTime(start + 11 * 60_000);

      expect((await s.verifyToken(plane.token())).sub).toBeTypeOf('string');
      expect(plane.jwksFetches).toBe(2);
    });

    it("fetches the keys again when the answer's max-age runs out, not later", async () => {
      // The control plane sends `public, max-age=300`: a key it stops publishing must stop
      // verifying here within that, not twice that.
      const s = server();
      await s.verifyToken(plane.token());
      expect(plane.jwksFetches).toBe(1);

      vi.setSystemTime(start + 299_000);
      await s.verifyToken(plane.token());
      expect(plane.jwksFetches).toBe(1);

      vi.setSystemTime(start + 300_000);
      await s.verifyToken(plane.token());
      expect(plane.jwksFetches).toBe(2);
    });

    it.each([
      ['public, max-age=60', 60_000],
      ['max-age=0', 30_000],
      ['no-store', 30_000],
      ['public, max-age=86400', 3_600_000],
      [undefined, 300_000],
    ])('serves a set answered with Cache-Control %s for %i ms', async (header, ttl) => {
      plane.jwksCacheControl = header;
      const s = server();
      await s.verifyToken(plane.token());

      vi.setSystemTime(start + ttl - 1_000);
      await s.verifyToken(plane.token());
      expect(plane.jwksFetches).toBe(1);

      vi.setSystemTime(start + ttl);
      await s.verifyToken(plane.token());
      expect(plane.jwksFetches).toBe(2);
    });

    it('stops serving a stale set an hour after it was due, while every fetch fails', async () => {
      const s = server();
      await s.verifyToken(plane.token());
      plane.jwksFails = true;

      // Due at five minutes; served on through failed fetches for an hour after that.
      vi.setSystemTime(start + 300_000 + 3_599_000);
      expect((await s.verifyToken(plane.token())).sub).toBeTypeOf('string');
      expect(plane.jwksFetches).toBeGreaterThan(1);

      // Then no longer: a key the control plane may have withdrawn is not trusted for ever.
      vi.setSystemTime(start + 300_000 + 3_600_000);
      const refused = await refusal(s.verifyToken(plane.token()));
      expect([refused.reason, refused.status]).toEqual(['keys_unavailable', 503]);

      // Even when the rate limit keeps the next request from fetching at all.
      vi.setSystemTime(start + 300_000 + 3_601_000);
      const fetches = plane.jwksFetches;
      const again = await refusal(s.verifyToken(plane.token()));
      expect([again.reason, plane.jwksFetches]).toEqual(['keys_unavailable', fetches]);

      // And a fetch that succeeds puts things right.
      plane.jwksFails = false;
      vi.setSystemTime(start + 300_000 + 3_640_000);
      expect((await s.verifyToken(plane.token())).sub).toBeTypeOf('string');
    });
  });

  describe('step 2: the token itself', () => {
    it('accepts a token the control plane signed for this audience', async () => {
      const claims = await server().verifyToken(plane.token());

      expect(claims.sub).toBe('f47ac10b-58cc-4372-a567-0e02b2c3d479');
      expect(claims.act).toMatchObject({ sub: 'agent:jira-triage', depth: 1 });
      expect(claims.scopes).toEqual(['jira:read', 'jira:comment']);
      expect(claims.taskId).toBe('task_01HQZX9K4M');
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
        (p: FakeControlPlane) => p.token({ aud: 'https://elsewhere.internal' }),
        'wrong_audience',
        401,
      ],
      [
        'an expired token',
        (p: FakeControlPlane) => p.token({ exp: start / 1000 - 61 }),
        'expired',
        401,
      ],
      [
        'a client assertion',
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
      [
        'an agent as the subject',
        (p: FakeControlPlane) => p.token({ sub: 'agent:jira-triage' }),
        'subject_is_agent',
        401,
      ],
      [
        'a malformed act',
        (p: FakeControlPlane) => p.token({ act: { sub: 'nobody', depth: 1 } }),
        'malformed_token',
        401,
      ],
      ['garbage', () => 'not.a.jwt', 'malformed_token', 401],
    ])('refuses %s', async (_, make, reason, status) => {
      const refused = await refusal(server().verifyToken(make(plane)));
      expect([refused.reason, refused.status]).toEqual([reason, status]);
      expect(refused.message).not.toContain('eyJ');
    });

    it('canonicalises the issuer, so its case or a default port cannot make it disagree with iss', async () => {
      const s = server({ issuer: 'https://SUBACTID.internal.example.com:443/' });
      expect((await s.verifyToken(plane.token())).sub).toBeTypeOf('string');
      expect(plane.jwksFetches).toBe(1);
      for (const bad of ['subactid.internal.example.com', 'ftp://subactid.internal.example.com']) {
        expect(() => server({ issuer: bad })).toThrow(
          'issuer must be an absolute http or https URL.',
        );
      }
    });

    it('leaves the actor rules to the policy, so an actor-less token is a valid token', async () => {
      const claims = await server().verifyToken(plane.token({ act: undefined }));
      expect(claims.act).toBeUndefined();
    });

    it('reads the bearer token out of an Authorization header and refuses anything else', async () => {
      const s = server();
      expect((await s.authenticate(`Bearer ${plane.token()}`)).sub).toBeTypeOf('string');
      expect((await s.authenticate(`bearer ${plane.token()}`)).sub).toBeTypeOf('string');
      for (const header of [undefined, 'Bearer ', 'Basic abc', ['Bearer a', 'Bearer b']]) {
        expect((await refusal(s.authenticate(header))).reason).toBe('missing_token');
      }
    });
  });

  describe('steps 3, 4 and 6: what the caller may do', () => {
    it('allows a token that carries every scope the route lists', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token());

      expect(await s.authorize(claims, { scope: 'jira:read' })).toBeUndefined();
      expect(await s.authorize(claims, { scope: ['jira:read', 'jira:comment'] })).toBeUndefined();
      expect(await s.authorize(claims, {})).toBeUndefined();
    });

    it('refuses a token short of a scope, naming only what is missing', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token({ scope: 'jira:read' }));

      const denial = await s.authorize(claims, {
        scope: ['jira:read', 'jira:comment', 'jira:admin'],
      });

      expect(denial?.reason).toBe('insufficient_scope');
      expect(denial?.message).toBe('the token lacks scope jira:comment jira:admin.');
      expect(denial?.status).toBe(403);
    });

    it('rejects a token with no act claim on an agent-only route, and allows it where a human may call', async () => {
      const s = server({ requireActor: false });
      const human = await s.verifyToken(plane.token({ act: undefined }));
      const agent = await s.verifyToken(plane.token());

      // The done-when of the issue: agent-only means no act claim, no entry.
      const denial = await s.authorize(human, { scope: 'jira:read', requireActor: true });
      expect(denial?.reason).toBe('no_actor');
      expect(denial?.status).toBe(401);
      expect(denial?.message).toContain('only an agent acting for a human');

      expect(await s.authorize(human, { scope: 'jira:read' })).toBeUndefined();
      expect(await s.authorize(agent, { scope: 'jira:read', requireActor: true })).toBeUndefined();
    });

    it('is agent-only by default, and a route may open itself to a human deliberately', async () => {
      const s = server();
      const human = await s.verifyToken(plane.token({ act: undefined }));

      expect((await s.authorize(human, {}))?.reason).toBe('no_actor');
      expect(await s.authorize(human, { requireActor: false })).toBeUndefined();
    });

    it('refuses a delegation chain deeper than the route allows', async () => {
      const s = server();
      const nested = await s.verifyToken(
        plane.token({ act: { sub: 'agent:b', depth: 2, act: { sub: 'agent:a', depth: 1 } } }),
      );

      const denial = await s.authorize(nested, {});
      expect([denial?.reason, denial?.status]).toEqual(['delegation_too_deep', 403]);
      expect(await s.authorize(nested, { maxDelegationDepth: 2 })).toBeUndefined();
      expect(await server({ maxDelegationDepth: 2 }).authorize(nested, {})).toBeUndefined();
    });

    it('refuses a policy that lists an empty scope, so nothing is open by a typo', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token());

      await expect(s.authorize(claims, { scope: '' })).rejects.toThrow('empty scope');
      await expect(s.authorize(claims, { scope: ['jira:read', ''] })).rejects.toThrow(
        'empty scope',
      );
      // An empty list is a config that lost its values, not a route that asks for nothing.
      await expect(s.authorize(claims, { scope: [] })).rejects.toThrow('empty scope');
      await expect(s.authorize(claims, { maxDelegationDepth: 0 })).rejects.toThrow(
        'maxDelegationDepth',
      );
    });

    it('asks the control plane about a high-risk route on every request, and refuses what it will not vouch for', async () => {
      const s = server();
      const token = plane.token();
      const claims = await s.verifyToken(token);

      // The control plane's answer for a live token is its claims plus task_id, not a bare yes.
      const answer =
        typeof plane.introspection === 'function' ? plane.introspection(token) : undefined;
      expect(answer).toMatchObject({
        active: true,
        sub: claims.sub,
        jti: claims.jti,
        scope: 'jira:read jira:comment',
        act: { sub: 'agent:jira-triage', depth: 1 },
        task_id: 'task_01HQZX9K4M',
      });
      expect(await s.authorize(claims, { scope: 'jira:read', highRisk: true })).toBeUndefined();
      expect(await s.authorize(claims, { scope: 'jira:read', highRisk: true })).toBeUndefined();
      expect(plane.introspections).toEqual([token, token]);
      expect(await s.authorize(claims, { scope: 'jira:read' })).toBeUndefined();
      expect(plane.introspections).toHaveLength(2);

      plane.introspection = { active: false, revocation_reason: 'operator_kill_switch' };
      const revoked = await s.authorize(claims, { highRisk: true });
      expect(revoked?.reason).toBe('not_active');
      expect(revoked?.message).toBe('the token is no longer active (operator_kill_switch).');

      plane.introspection = { active: true, sub: 'someone-else' };
      expect((await s.authorize(claims, { highRisk: true }))?.reason).toBe('not_active');
      plane.introspection = { active: true, jti: 'another' };
      expect((await s.authorize(claims, { highRisk: true }))?.reason).toBe('not_active');
    });

    it('introspects a token the control plane marked high risk, whatever the route says', async () => {
      const s = server();
      const token = plane.token({ introspect_required: true });
      const claims = await s.verifyToken(token);

      // No route policy asks for it: the decision came with the token, from the agent's
      // registration, so a server nobody remembered to configure still gets it right.
      expect(await s.authorize(claims, { scope: 'jira:read' })).toBeUndefined();
      expect(plane.introspections).toEqual([token]);

      plane.introspection = { active: false, revocation_reason: 'operator_kill_switch' };
      expect((await s.authorize(claims, {}))?.reason).toBe('not_active');
    });

    it('does not introspect twice for a caller that already did', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token({ introspect_required: true }));

      expect(
        await s.authorize(claims, { scope: 'jira:read' }, { alreadyIntrospected: true }),
      ).toBeUndefined();
      expect(plane.introspections).toHaveLength(0);

      // A route that is riskier than its audience still gets its own check.
      expect(await s.authorize(claims, { highRisk: true })).toBeUndefined();
      expect(plane.introspections).toHaveLength(1);
    });

    it('fails closed when the control plane cannot be asked', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token());

      plane.introspectionFails = true;
      expect((await s.authorize(claims, { highRisk: true }))?.reason).toBe(
        'introspection_unavailable',
      );
      plane.introspectionFails = false;
      plane.introspectionStatus = 503;
      expect((await s.authorize(claims, { highRisk: true }))?.status).toBe(503);
    });

    it('passes on the interval the control plane named when it rate limits introspection', async () => {
      // The keys path already does this, and it is cached for minutes at a time. This one runs on
      // every request to a high-risk route, so it is where one rate limit upstream turns into
      // a retry storm from everything downstream if the caller is told nothing.
      const s = server();
      const claims = await s.verifyToken(plane.token());

      plane.introspectionStatus = 429;
      plane.introspectionHeaders = { 'retry-after': '2' };
      const refused = await s.authorize(claims, { highRisk: true });

      expect([refused?.reason, refused?.status, refused?.retryAfterSeconds]).toEqual([
        'introspection_unavailable',
        503,
        2,
      ]);
      expect(refused && s.refusal(refused).headers['retry-after']).toBe('2');
    });
  });

  describe('step 5: the log', () => {
    it('records the human and the agent for a request it let through', async () => {
      const s = server();

      const claims = await s.guard(
        `Bearer ${plane.token()}`,
        { scope: 'jira:read' },
        'GET /issues',
      );

      expect(claims.sub).toBe('f47ac10b-58cc-4372-a567-0e02b2c3d479');
      expect(events).toEqual([
        {
          event: 'request',
          at: '2026-09-12T12:00:00.000Z',
          route: 'GET /issues',
          decision: 'allow',
          sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
          act: 'agent:jira-triage',
          instance: 'pod-7f9c4b',
          depth: 1,
          task_id: 'task_01HQZX9K4M',
          jti: expect.stringMatching(/^tok_/),
        },
      ]);
    });

    it('records a refusal with its reason, and never the token', async () => {
      const s = server();
      const token = plane.token({ scope: 'jira:read' });

      await refusal(s.guard(`Bearer ${token}`, { scope: 'jira:comment' }, 'POST /comments'));
      await refusal(s.guard(undefined, { scope: 'jira:read' }, 'GET /issues'));
      await refusal(s.guard(`Bearer ${plane.forged()}`, {}, 'GET /issues'));

      expect(events.map((e) => [e.route, e.decision, e.reason])).toEqual([
        ['POST /comments', 'deny', 'insufficient_scope'],
        ['GET /issues', 'deny', 'missing_token'],
        ['GET /issues', 'deny', 'invalid_signature'],
      ]);
      expect(events[0]?.sub).toBe('f47ac10b-58cc-4372-a567-0e02b2c3d479');
      expect(events[1]?.sub).toBeUndefined();
      expect(JSON.stringify(events)).not.toContain(token);
    });

    it('lets an unexpected failure through rather than logging it as a decision', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token());
      void claims;

      await expect(
        s.guard(`Bearer ${plane.token()}`, { scope: '' }, 'GET /issues'),
      ).rejects.toThrow('empty scope');
      expect(events).toEqual([]);
    });
  });

  describe('the wire form of a refusal', () => {
    it('is the status, the challenge and a body naming the reason', () => {
      const s = server({ realm: 'jira' });

      expect(s.refusal(new SubactIdAuthError(401, 'expired', 'the token has expired.'))).toEqual({
        status: 401,
        headers: {
          'content-type': 'application/json',
          'www-authenticate':
            'Bearer realm="jira", error="invalid_token", error_description="the token has expired."',
        },
        body: { error: 'invalid_token', error_description: 'the token has expired.' },
      });
      expect(
        s.refusal(new SubactIdAuthError(401, 'missing_token', 'A bearer token is required.'))
          .headers['www-authenticate'],
      ).toBe('Bearer realm="jira"');
      expect(s.refusal(new SubactIdAuthError(403, 'insufficient_scope', 'no.')).body.error).toBe(
        'insufficient_scope',
      );
      const unavailable = s.refusal(new SubactIdAuthError(503, 'keys_unavailable', 'later.'));
      expect(unavailable.body.error).toBe('temporarily_unavailable');
      expect(unavailable.headers['www-authenticate']).toBeUndefined();
    });

    it('says nothing about a failure that is not a refusal', () => {
      expect(server().refusal(new Error('the database is on fire'))).toEqual({
        status: 500,
        headers: { 'content-type': 'application/json' },
        body: { error: 'server_error', error_description: 'The request could not be handled.' },
      });
    });
  });

  describe('the control plane it talks to', () => {
    it('finds the keys and introspection through discovery, once, and follows no redirect', async () => {
      const s = server();
      const claims = await s.verifyToken(plane.token());
      expect(await s.authorize(claims, { highRisk: true })).toBeUndefined();
      expect(await s.authorize(claims, { highRisk: true })).toBeUndefined();

      expect(plane.discoveryFetches).toBe(1);
      expect(plane.introspections).toHaveLength(2);
      // Every request refuses a redirect: a token is sent to introspection, and the keys decide
      // what is trusted, so neither goes wherever a 307 points.
      expect(plane.followed).toEqual([]);
    });

    it('uses the introspection endpoint the discovery document names', async () => {
      plane.discovery = {
        ...plane.discovery,
        introspection_endpoint: `${issuer}/elsewhere/introspect`,
      };
      const s = server();
      const claims = await s.verifyToken(plane.token());

      // The fake control plane answers only at its usual path, so a refusal shows the named one was asked.
      const refused = await s.authorize(claims, { highRisk: true });

      expect([refused?.reason, refused?.status]).toEqual(['introspection_unavailable', 503]);
      expect(plane.introspections).toEqual([]);
    });

    it.each([
      ['names another issuer', { issuer: 'https://attacker.example' }],
      ['puts the keys on another origin', { jwks_uri: 'https://attacker.example/jwks.json' }],
      ['has no keys', { jwks_uri: undefined }],
    ])('trusts no key when the discovery document %s', async (_, change) => {
      plane.discovery = { ...plane.discovery, ...change };
      const s = server();

      const refused = await refusal(s.verifyToken(plane.token()));

      expect([refused.reason, refused.status]).toEqual(['keys_unavailable', 503]);
      expect(plane.jwksFetches).toBe(0);
    });

    it('sends no token to an introspection endpoint on another origin', async () => {
      plane.discovery = {
        ...plane.discovery,
        introspection_endpoint: 'https://attacker.example/introspect',
      };
      const s = server();

      // The keys come through the same document, so it is refused as a whole.
      const refused = await refusal(s.verifyToken(plane.token()));

      expect(refused.reason).toBe('keys_unavailable');
      expect(plane.introspections).toEqual([]);
    });

    it('repeats only its own words when discovery cannot be reached, never what fetch said', async () => {
      const s = server({
        fetch: (input, init) =>
          String(input).includes('openid-configuration')
            ? Promise.reject(new TypeError('connect ECONNREFUSED https://user:hunter2@internal'))
            : plane.fetch(input, init),
      });
      const refused = await refusal(s.verifyToken(plane.token()));
      expect(refused.status).toBe(503);
      expect(refused.message).toBe(
        "the control plane's discovery document could not be used: it could not be reached.",
      );
      expect(refused.message).not.toContain('hunter2');
    });

    it('asks for the discovery document again after it could not be had', async () => {
      plane.discoveryStatus = 503;
      const s = server();
      await refusal(s.verifyToken(plane.token()));

      // Past the key cache's pause between failed fetches, so the next request asks again.
      plane.discoveryStatus = 200;
      vi.setSystemTime(start + 60_000);
      await expect(s.verifyToken(plane.token())).resolves.toBeDefined();
      expect(plane.discoveryFetches).toBe(2);
    });

    it.each([
      ['http://localhost:5100', true],
      ['http://127.0.0.1:5100', true],
      ['http://[::1]:5100', true],
      ['http://subactid.internal.example.com', false],
      ['http://10.0.0.5:5100', false],
    ])('accepts the http issuer %s only on a loopback host', (url, accepted) => {
      const make = () =>
        new SubactIdToolServer({ issuer: url, audience, fetch: plane.fetch, log: () => {} });
      if (accepted) {
        expect(make).not.toThrow();
      } else {
        expect(make).toThrow(/https/);
      }
    });

    it('refuses an issuer with a user name or password in it', () => {
      for (const url of ['https://user@subactid.example.com', 'https://u:p@subactid.example.com']) {
        expect(
          () =>
            new SubactIdToolServer({ issuer: url, audience, fetch: plane.fetch, log: () => {} }),
        ).toThrow('issuer must not contain a user name or password.');
      }
    });

    it.each([[-1], [301], [1.5], [Number.NaN]])('refuses a clockSkewSeconds of %s', (skew) => {
      expect(() => server({ clockSkewSeconds: skew })).toThrow(
        'clockSkewSeconds must be a whole number from 0 to 300.',
      );
    });

    it.each([[0], [-5], [Number.POSITIVE_INFINITY], [Number.NaN]])(
      'refuses a timeoutMs of %s',
      (timeoutMs) => {
        expect(() => server({ timeoutMs })).toThrow('timeoutMs');
      },
    );

    it('accepts any http issuer when allowInsecureHttp says so', () => {
      expect(
        () =>
          new SubactIdToolServer({
            issuer: 'http://subactid.internal.example.com',
            audience,
            fetch: plane.fetch,
            allowInsecureHttp: true,
            log: () => {},
          }),
      ).not.toThrow();
    });
  });

  it('calls the global fetch with the global object as this, as browsers and Workers require', async () => {
    const seen: unknown[] = [];
    vi.stubGlobal('fetch', function (this: unknown, input: RequestInfo | URL, init?: RequestInit) {
      seen.push(this);
      return plane.fetch(input, init);
    });
    try {
      // No fetch option: the tool server falls back to the global one.
      const s = new SubactIdToolServer({ issuer, audience, log: () => {} });
      await s.verifyToken(plane.token());
    } finally {
      vi.unstubAllGlobals();
    }

    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((self) => self === globalThis)).toBe(true);
  });
});
