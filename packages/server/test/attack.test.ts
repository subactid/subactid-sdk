import { describe, expect, it, vi } from 'vitest';
import { createPrivateKey, generateKeyPairSync, sign, createHmac } from 'node:crypto';
import { SubactIdToolServer, SubactIdAuthError } from '../src/index.js';
import { audience, FakeControlPlane, issuer } from './control-plane.js';

const b64 = (bytes: Buffer | string): string => Buffer.from(bytes).toString('base64url');

function makeServer(cp: FakeControlPlane, now: () => number, extra: Record<string, unknown> = {}) {
  return new SubactIdToolServer({
    issuer,
    audience,
    fetch: cp.fetch,
    now,
    log: () => undefined,
    ...extra,
  });
}

describe('attack: algorithm and header', () => {
  it('rejects alg=none', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const h = b64(JSON.stringify({ alg: 'none', typ: 'at+jwt', kid: 'key-1' }));
    const c = b64(JSON.stringify({ iss: issuer, sub: 'human', aud: audience, exp: 9e9, jti: 'x' }));
    await expect(s.verifyToken(`${h}.${c}.AA`)).rejects.toMatchObject({
      reason: 'unsupported_algorithm',
    });
  });

  it('rejects HS256 signed with the public key as HMAC secret', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const h = b64(JSON.stringify({ alg: 'HS256', typ: 'at+jwt', kid: 'key-1' }));
    const c = b64(JSON.stringify({ iss: issuer, sub: 'human', aud: audience, exp: 9e9, jti: 'x' }));
    const sig = createHmac('sha256', JSON.stringify(cp.keys[0]!.publicJwk))
      .update(`${h}.${c}`)
      .digest('base64url');
    await expect(s.verifyToken(`${h}.${c}.${sig}`)).rejects.toMatchObject({
      reason: 'unsupported_algorithm',
    });
  });

  it('rejects a token with no typ, and one typed JWT', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(
      s.verifyToken(cp.token({}, { typ: undefined as unknown as string })),
    ).rejects.toMatchObject({ reason: 'wrong_type' });
    await expect(s.verifyToken(cp.token({}, { typ: 'JWT' }))).rejects.toMatchObject({
      reason: 'wrong_type',
    });
  });

  it('rejects a token carrying crit, whatever it names, even when its signature verifies', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(s.verifyToken(cp.token())).resolves.toBeTruthy();
    for (const crit of [['exp'], ['b64'], [], 'exp']) {
      await expect(s.verifyToken(cp.token({}, { crit, b64: true, exp: 1 }))).rejects.toMatchObject({
        reason: 'malformed_token',
        status: 401,
      });
    }
  });

  it('rejects a DER-encoded signature even when it verifies', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const key = cp.keys[0]!;
    const h = b64(JSON.stringify({ alg: 'ES256', typ: 'at+jwt', kid: key.kid }));
    const c = b64(JSON.stringify({ iss: issuer, sub: 'human', aud: audience, exp: 9e9, jti: 'x' }));
    const der = sign('sha256', Buffer.from(`${h}.${c}`), { key: createPrivateKey(key.privateKey) });
    await expect(s.verifyToken(`${h}.${c}.${b64(der)}`)).rejects.toMatchObject({
      reason: 'invalid_signature',
    });
  });

  it('rejects a token signed by a key the control plane never published', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(s.verifyToken(cp.forged())).rejects.toMatchObject({ reason: 'invalid_signature' });
  });
});

describe('attack: subject and actor', () => {
  it('refuses an agent in sub', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(s.verifyToken(cp.token({ sub: 'agent:evil' }))).rejects.toMatchObject({
      reason: 'subject_is_agent',
    });
  });

  it('refuses an agent in sub written in another case', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(s.verifyToken(cp.token({ sub: 'Agent:evil' }))).rejects.toMatchObject({
      reason: 'subject_is_agent',
    });
    await expect(s.verifyToken(cp.token({ sub: 'AGENT:evil' }))).rejects.toMatchObject({
      reason: 'subject_is_agent',
    });
  });

  it('refuses a depth that does not match the chain', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(
      s.verifyToken(cp.token({ act: { sub: 'agent:a', depth: 5 } })),
    ).rejects.toMatchObject({ reason: 'malformed_token' });
    await expect(
      s.verifyToken(
        cp.token({ act: { sub: 'agent:a', depth: 1, act: { sub: 'agent:b', depth: 1 } } }),
      ),
    ).rejects.toMatchObject({ reason: 'malformed_token' });
  });

  it('refuses a chain deeper than the route allows', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const deep = cp.token({ act: { sub: 'agent:b', depth: 2, act: { sub: 'agent:a', depth: 1 } } });
    const claims = await s.verifyToken(deep);
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'delegation_too_deep',
    });
  });
});

describe('attack: scope', () => {
  it('does not treat a prefix as the scope', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const claims = await s.verifyToken(cp.token({ scope: 'jira:readonly' }));
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'insufficient_scope',
    });
  });

  it('refuses a token with no scope at all on a scoped route', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const claims = await s.verifyToken(cp.token({ scope: undefined }));
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'insufficient_scope',
    });
  });

  it('refuses a scope claim that is not a string', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const claims = await s.verifyToken(cp.token({ scope: ['jira:read'] }));
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'insufficient_scope',
    });
  });
});

describe('attack: audience and issuer', () => {
  it('refuses a lookalike audience', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(s.verifyToken(cp.token({ aud: `${audience}.evil.com` }))).rejects.toMatchObject({
      reason: 'wrong_audience',
    });
  });

  it('refuses a lookalike issuer', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await expect(s.verifyToken(cp.token({ iss: `${issuer}/../evil` }))).rejects.toMatchObject({
      reason: 'wrong_issuer',
    });
  });
});

describe('attack: introspection answers', () => {
  it('refuses when introspection names a different sub or jti', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const claims = await s.verifyToken(cp.token({ introspect_required: true }));
    cp.introspection = { active: true, sub: 'somebody-else' };
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'not_active',
    });
    cp.introspection = { active: true, jti: 'another' };
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'not_active',
    });
  });

  it('refuses when introspection says active with a string, not a boolean', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const claims = await s.verifyToken(cp.token({ introspect_required: true }));
    cp.introspection = { active: 'true' };
    expect(await s.authorize(claims, { scope: 'jira:read' })).toMatchObject({
      reason: 'not_active',
    });
  });

  it('survives a revocation_reason carrying CRLF without corrupting the header', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const claims = await s.verifyToken(cp.token({ introspect_required: true }));
    cp.introspection = { active: false, revocation_reason: 'x"\r\nX-Injected: yes' };
    const denial = await s.authorize(claims, { scope: 'jira:read' });
    expect(denial).toBeInstanceOf(SubactIdAuthError);
    const { headers } = s.refusal(denial);
    expect(headers['www-authenticate'] ?? '').not.toMatch(/[\r\n]/);
  });
});

describe('attack: keys', () => {
  it('will not import a key of the wrong curve or type', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    cp.jwksRaw = JSON.stringify({
      keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'key-1', alg: 'ES256', use: 'sig' }],
    });
    await expect(s.verifyToken(cp.token())).rejects.toMatchObject({ status: 503 });
  });

  it('does not serve a key whose kid was reassigned to another key', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    const good = cp.token();
    await s.verifyToken(good);
    // The control plane replaces key-1 with a different key under the same kid.
    const stranger = new FakeControlPlane(now);
    cp.keys = [{ ...stranger.keys[0]!, kid: 'key-1' }];
    // Cache still holds the old key until the TTL is up: the old token still verifies.
    await expect(s.verifyToken(good)).resolves.toBeTruthy();
  });
});

describe('attack: guard logging', () => {
  it('never logs the token itself', async () => {
    const now = () => 1_757_426_220_000;
    const cp = new FakeControlPlane(now);
    const lines: unknown[] = [];
    const s = makeServer(cp, now, { log: (e: unknown) => lines.push(e) });
    const token = cp.token();
    await s.guard(`Bearer ${token}`, { scope: 'jira:read' }, 'GET /issues');
    await s
      .guard(`Bearer ${cp.forged()}`, { scope: 'jira:read' }, 'GET /issues')
      .catch(() => undefined);
    const text = JSON.stringify(lines);
    expect(text).not.toContain(token);
    expect(text).not.toContain(token.split('.')[2]);
  });
});

describe('attack: a signing key rotation', () => {
  it('does not turn away requests that arrive while the new keys are already being fetched', async () => {
    let clock = 1_757_426_220_000;
    const now = () => clock;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);

    // Warm the cache on the original key. That fetch starts the unknown-kid rate limit.
    await s.verifyToken(cp.token());
    expect(cp.jwksFetches).toBe(1);

    // The control plane rotates, and enough time passes that a refresh is allowed again.
    cp.rotate('key-2');
    clock += 31_000;

    // Ten requests carrying the new kid arrive together. One starts the fetch; the other nine
    // must wait for it, not be refused by the rate limit that first one just tripped.
    const tokens = Array.from({ length: 10 }, () => cp.token({}, {}, 'key-2'));
    const outcomes = await Promise.all(
      tokens.map((t) =>
        s.verifyToken(t).then(
          () => 'ok',
          (e: { reason: string }) => e.reason,
        ),
      ),
    );

    expect(outcomes).toEqual(Array.from({ length: 10 }, () => 'ok'));
    // And they shared one fetch, so the rate limit still does its job.
    expect(cp.jwksFetches).toBe(2);
  });

  it('still refuses a kid the control plane does not publish, without a fetch per request', async () => {
    let clock = 1_757_426_220_000;
    const now = () => clock;
    const cp = new FakeControlPlane(now);
    const s = makeServer(cp, now);
    await s.verifyToken(cp.token());
    clock += 31_000;
    const before = cp.jwksFetches;

    const stranger = new FakeControlPlane(now);
    stranger.rotate('never-published');
    const outcomes = await Promise.all(
      Array.from({ length: 10 }, () =>
        s.verifyToken(stranger.token({}, {}, 'never-published')).then(
          () => 'ok',
          (e: { reason: string }) => e.reason,
        ),
      ),
    );

    expect(outcomes.every((o) => o === 'unknown_key')).toBe(true);
    expect(cp.jwksFetches - before).toBe(1);
  });
});
