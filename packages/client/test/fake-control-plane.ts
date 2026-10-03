import { expect } from 'vitest';
import { base64UrlDecode, base64UrlEncode, fromUtf8, utf8 } from '../src/encoding.js';

export const issuer = 'https://subactid.internal.example.com';
export const tokenEndpoint = `${issuer}/oauth2/token`;
export const revocationEndpoint = `${issuer}/oauth2/revoke`;

export interface Issued {
  taskId: string;
  grant: string;
  /** The agent the task was issued to; its grant is not found for any other. */
  agentId: string;
  /** What the grant holds now: the exchange's scope, narrowed by every refresh since. */
  scope: string;
  resource: string;
  taskExpiresAt: number;
  revoked: boolean;
}

/** Clock skew the control plane allows on an assertion's times, as `ClientAssertionAuthenticator` does. */
const assertionSkewSeconds = 60;
/** The longest an assertion may claim to live. */
const maxAssertionLifetimeSeconds = 300;
/** A task with less than this left gets no token: `access_denied`, `task_ending`. */
const minimumTokenLifetimeMs = 5_000;

/**
 * The control plane as the client sees it, modelling the real one only in what follows:
 * discovery; an exchange that issues a task; a refresh that checks the agent's assertion and
 * then, in the server's order, a disabled agent, the grant, a revoked task, an expired one, one with too little
 * left, the audience and the scope, answers with the same grant (it never rotates), keeps a
 * narrowed scope on the grant, and bounds the token by the task; and a revocation that ends the
 * task a grant belongs to. Every request is recorded so tests can look at what was sent.
 *
 * It does not model everything the real one does. There is no sponsor check, so it never answers
 * `503` because the provider's answer about the human is unavailable, and a refresh's scope is
 * checked only against the grant, not intersected with the agent's current registration. A test
 * that needs either answer sets it with `nextFailure`.
 */
export class FakeControlPlane {
  requests: { url: string; form: URLSearchParams }[] = [];
  discoveryCalls = 0;
  tokenTtlSeconds = 300;
  taskTtlSeconds = 1800;
  now: () => number;
  /**
   * When set, access tokens are compact JWS carrying `exp`, as the control plane issues them,
   * rather than opaque strings. The signature is not a real one: the client never verifies it.
   */
  jwtTokens = false;
  /** When set, the next token request answers with this instead. */
  nextFailure:
    { status: number; body: unknown; headers?: Record<string, string> } | Error | undefined;
  /**
   * When set, the next discovery fetch answers with this instead. Discovery is refetched
   * whenever the cached one failed, so this is how a test puts something in front of the
   * control plane — a gateway, a proxy — on a request a live task depends on.
   */
  nextDiscoveryFailure:
    { status: number; body: unknown; headers?: Record<string, string> } | undefined;
  /** When set, every token request fails with this. */
  alwaysFail: Error | undefined;
  /**
   * Agents the control plane holds disabled. A refresh by one is refused `access_denied` with
   * `reason` `agent_disabled`, as the server's client authentication does, before the grant is
   * looked at; the task stays alive, so it can be refreshed again once the agent is enabled.
   */
  disabledAgents = new Set<string>();
  /** When each token request arrived, by the fake's clock. */
  tokenRequestTimes: number[] = [];
  /** Every token presented for revocation, in order. */
  revocations: string[] = [];
  private tasks = new Map<string, Issued>();
  private seenJtis = new Set<string>();
  private counter = 0;

  constructor(now: () => number) {
    this.now = now;
  }

  /** The task as the control plane holds it now. */
  task(taskId: string): Issued | undefined {
    const task = [...this.tasks.values()].find((t) => t.taskId === taskId);
    return task === undefined ? undefined : { ...task };
  }

  /** Revokes a task as an operator or a block of its human would, without the agent asking. */
  revokeTask(taskId: string): void {
    const task = [...this.tasks.values()].find((t) => t.taskId === taskId);
    if (task !== undefined) task.revoked = true;
  }

  /** Requests that would have followed a redirect rather than refusing one. */
  followed: string[] = [];
  /** Changes the next successful token answer before it is sent, to test what the client accepts. */
  nextTokenChange: ((body: Record<string, unknown>) => Record<string, unknown>) | undefined;

  fetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (init?.redirect !== 'error') this.followed.push(url);
    if (url === `${issuer}/.well-known/openid-configuration`) {
      this.discoveryCalls++;
      if (this.nextDiscoveryFailure) {
        const failure = this.nextDiscoveryFailure;
        this.nextDiscoveryFailure = undefined;
        return json(failure.status, failure.body, failure.headers);
      }
      return json(200, {
        issuer,
        token_endpoint: tokenEndpoint,
        introspection_endpoint: `${issuer}/oauth2/introspect`,
        revocation_endpoint: `${issuer}/oauth2/revoke`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
      });
    }
    if (url !== tokenEndpoint && url !== revocationEndpoint) {
      return json(404, {});
    }
    expect(init?.method).toBe('POST');
    expect(new Headers(init?.headers).get('content-type')).toBe(
      'application/x-www-form-urlencoded',
    );
    const form = new URLSearchParams(String(init?.body));
    this.requests.push({ url, form });
    if (url === tokenEndpoint) this.tokenRequestTimes.push(this.now());
    if (this.alwaysFail) {
      throw this.alwaysFail;
    }
    if (this.nextFailure) {
      const failure = this.nextFailure;
      this.nextFailure = undefined;
      if (failure instanceof Error) throw failure;
      return json(failure.status, failure.body, failure.headers);
    }
    if (url === revocationEndpoint) {
      return this.revoke(form);
    }
    const grantType = form.get('grant_type');
    if (grantType === 'urn:ietf:params:oauth:grant-type:token-exchange') {
      return this.exchange(form);
    }
    if (grantType === 'refresh_token') {
      return this.refresh(form);
    }
    return json(400, { error: 'unsupported_grant_type', error_description: 'No.' });
  };

  /** The claims of the assertion sent with request `index`. */
  assertionClaims(
    index: number,
    field: 'actor_token' | 'client_assertion',
  ): Record<string, unknown> {
    const assertion = this.requests[index]?.form.get(field);
    expect(assertion).toBeTypeOf('string');
    const parts = (assertion as string).split('.');
    expect(parts).toHaveLength(3);
    return JSON.parse(fromUtf8(base64UrlDecode(parts[1] as string))) as Record<string, unknown>;
  }

  /**
   * The agent an assertion proves, or `undefined` when the control plane would refuse it as
   * `invalid_client`. The signature is not checked — the fake holds no agent keys — but every
   * claim the control plane checks is: `iss` and `sub` the same agent, `aud` its issuer or token
   * endpoint, an `exp` no more than 300 seconds off, `iat` and `nbf` not in the future, a `jti`
   * not seen before, and a `kid`, each with the control plane's 60 seconds of skew.
   */
  private authenticate(assertion: string | null): string | undefined {
    const parts = (assertion ?? '').split('.');
    if (parts.length !== 3 || parts.some((p) => p.length === 0)) return undefined;
    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;
    try {
      header = JSON.parse(fromUtf8(base64UrlDecode(parts[0] as string))) as Record<string, unknown>;
      claims = JSON.parse(fromUtf8(base64UrlDecode(parts[1] as string))) as Record<string, unknown>;
    } catch {
      return undefined;
    }
    if (typeof header['kid'] !== 'string' || header['kid'] === '') return undefined;
    if (!['RS256', 'PS256', 'ES256'].includes(header['alg'] as string)) return undefined;
    const { iss, sub, aud, exp, jti } = claims;
    if (typeof iss !== 'string' || iss === '' || sub !== iss) return undefined;
    const audiences = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud : [];
    if (!audiences.some((a) => a === issuer || a === tokenEndpoint)) return undefined;
    const nowSeconds = this.now() / 1000;
    if (typeof exp !== 'number') return undefined;
    if (nowSeconds >= exp + assertionSkewSeconds) return undefined;
    if (exp > nowSeconds + maxAssertionLifetimeSeconds + assertionSkewSeconds) return undefined;
    for (const name of ['iat', 'nbf']) {
      const time = claims[name];
      if (
        time !== undefined &&
        (typeof time !== 'number' || time > nowSeconds + assertionSkewSeconds)
      ) {
        return undefined;
      }
    }
    if (typeof jti !== 'string' || jti === '') return undefined;
    if (this.seenJtis.has(`${iss} ${jti}`)) return undefined;
    this.seenJtis.add(`${iss} ${jti}`);
    return iss;
  }

  private exchange(form: URLSearchParams): Response {
    const agentId = this.authenticate(form.get('actor_token'));
    if (agentId === undefined) return invalidClient();
    const scope = form.get('scope') ?? '';
    const resource = form.get('resource') ?? '';
    const task: Issued = {
      taskId: `task_${++this.counter}`,
      grant: `task_grant_${this.counter}`,
      agentId,
      scope,
      resource,
      taskExpiresAt: this.now() + this.taskTtlSeconds * 1000,
      revoked: false,
    };
    this.tasks.set(task.grant, task);
    return this.token(task);
  }

  /** In `TokenRefreshService`'s order: agent, disabled agent, grant, revoked, expired, ending, audience, scope. */
  private refresh(form: URLSearchParams): Response {
    const agentId = this.authenticate(form.get('client_assertion'));
    if (agentId === undefined) return invalidClient();
    if (this.disabledAgents.has(agentId)) {
      return accessDenied('The agent is disabled.', 'agent_disabled');
    }
    const task = this.tasks.get(form.get('refresh_token') ?? '');
    // A grant presented by another agent is one that does not exist.
    if (!task || task.agentId !== agentId) {
      return json(400, {
        error: 'invalid_grant',
        error_description: 'The refresh token is unknown, revoked or expired.',
      });
    }
    if (task.revoked) {
      return accessDenied('The task has been revoked.', 'task_revoked');
    }
    if (this.now() >= task.taskExpiresAt) {
      return accessDenied('The task has expired.', 'task_expired');
    }
    if (task.taskExpiresAt - this.now() < minimumTokenLifetimeMs) {
      return accessDenied('The task has too little left to issue a token for.', 'task_ending');
    }
    if (form.get('resource') !== task.resource) {
      return json(400, {
        error: 'invalid_target',
        error_description: "The resource is not the task's audience.",
      });
    }
    const held = new Set(task.scope.split(' '));
    const wanted = (form.get('scope') ?? '').split(' ').filter(Boolean);
    if (wanted.length === 0 || wanted.some((s) => !held.has(s))) {
      return json(400, {
        error: 'invalid_scope',
        error_description: 'The requested scope is wider than the grant.',
      });
    }
    // The grant keeps what this refresh narrowed it to, and is answered back unchanged.
    task.scope = wanted.join(' ');
    return this.token(task);
  }

  /** RFC 7009: a grant ends its task; anything else gets the same empty 200, so nothing can be probed. */
  private revoke(form: URLSearchParams): Response {
    const token = form.get('token') ?? '';
    this.revocations.push(token);
    const agentId = this.authenticate(form.get('client_assertion'));
    if (agentId === undefined) return invalidClient();
    const task = this.tasks.get(token);
    if (task !== undefined && task.agentId === agentId) {
      task.revoked = true;
    }
    return new Response(null, { status: 200 });
  }

  /** A token as the control plane issues one: its lifetime cut to the task, `expires_in` in whole seconds of `exp`. */
  private token(task: Issued): Response {
    const now = this.now();
    const lifetimeMs = Math.min(this.tokenTtlSeconds * 1000, task.taskExpiresAt - now);
    const exp = Math.floor((now + lifetimeMs) / 1000);
    const id = `token_${task.taskId}_${++this.counter}`;
    const change = this.nextTokenChange ?? ((body: Record<string, unknown>) => body);
    this.nextTokenChange = undefined;
    return json(
      200,
      change({
        access_token: this.jwtTokens ? jws({ jti: id, exp, iat: Math.floor(now / 1000) }) : id,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        token_type: 'Bearer',
        expires_in: exp - Math.floor(now / 1000),
        scope: task.scope,
        refresh_token: task.grant,
        task_id: task.taskId,
        task_expires_at: new Date(task.taskExpiresAt).toISOString(),
      }),
    );
  }
}

function jws(claims: Record<string, unknown>): string {
  const part = (value: unknown) => base64UrlEncode(utf8(JSON.stringify(value)));
  return `${part({ alg: 'RS256', typ: 'JWT', kid: 'cp' })}.${part(claims)}.c2ln`;
}

function invalidClient(): Response {
  return json(401, {
    error: 'invalid_client',
    error_description: 'The client assertion is invalid.',
  });
}

/** An `access_denied` answer carrying the machine-readable `reason` its audit record uses. */
function accessDenied(description: string, reason: string): Response {
  return json(400, { error: 'access_denied', error_description: description, reason });
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}
