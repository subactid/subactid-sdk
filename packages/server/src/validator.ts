import { SubactIdAuthError, type DenialReason } from './errors.js';
import { JwksCache, retryAfterSeconds } from './jwks.js';
import { verifyTaskToken, type TaskToken } from './token.js';

/** What a route requires of a caller. */
export interface RoutePolicy {
  /** Scope, or scopes, the token must carry; every one listed. Omitted means any verified token. */
  scope?: string | string[];
  /**
   * Ask the control plane on every request whether the token is still active, instead of
   * trusting the local check until it expires. Slower, and revocation is felt at once.
   *
   * A token whose audience the agent's registration marks high risk carries
   * `introspect_required` and is introspected whether or not this is set, so this is the
   * lever for a route that is riskier than its audience as a whole.
   */
  highRisk?: boolean;
  /** Only an agent acting for a human may call this route. Defaults to the server's setting. */
  requireActor?: boolean;
  /** Longest `act` chain this route accepts. Defaults to the server's setting. */
  maxDelegationDepth?: number;
}

export interface AuthorizeOptions {
  /**
   * That this token has already been introspected once for this call, so the check is not
   * repeated. A caller that guards at two levels — a transport and then each tool — uses
   * this so an audience the control plane marked high risk costs one round trip, not two.
   */
  alreadyIntrospected?: boolean;
}

export interface SubactIdToolServerOptions {
  /**
   * The control plane's issuer URL, as in its discovery document. `https`, or `http` on a
   * loopback host (`localhost`, `127.0.0.0/8`, `::1`) for local development.
   */
  issuer: string;
  /**
   * Accept an `http` issuer that is not on a loopback host. Every token, and on a high-risk route
   * every introspection, then travels in the clear: for a demo or a network you trust, never for
   * production. Default false.
   */
  allowInsecureHttp?: boolean;
  /** The audience this server is: the `aud` a token must carry. */
  audience: string;
  /** Default for <see cref="RoutePolicy.requireActor" />: only agents acting for a human. Default true. */
  requireActor?: boolean;
  /** Default longest `act` chain accepted; default 1, direct agents only. Raise it deliberately. */
  maxDelegationDepth?: number;
  /** Clock skew tolerated, in seconds; default 60. */
  clockSkewSeconds?: number;
  /** How long a call to the control plane (keys, introspection) may take, in milliseconds; default 10000. */
  timeoutMs?: number;
  /** Realm named in `WWW-Authenticate`; defaults to the audience. */
  realm?: string;
  /** Where every request is logged; defaults to one JSON line on stdout. */
  log?: (event: AccessEvent) => void;
  fetch?: typeof fetch;
  now?: () => number;
}

/** Step 5 of the tool-server contract: one of these per request, allowed or not. Never a token. */
export interface AccessEvent {
  event: 'request';
  at: string;
  /** What was asked for, for example `GET /issues`. Never a query string. */
  route: string;
  decision: 'allow' | 'deny';
  reason?: DenialReason;
  /** The human the action was taken on behalf of. */
  sub?: string;
  /** The agent that acted, `agent:<id>`. */
  act?: string;
  /** Which copy of the agent, when it said so: the token's `act.instance`, the agent's own claim about itself, never verified. */
  instance?: string;
  depth?: number;
  task_id?: string;
  jti?: string;
}

/** How a refusal goes on the wire. */
export interface Refusal {
  status: 401 | 403 | 500 | 503;
  headers: Record<string, string>;
  body: { error: string; error_description: string };
}

/** The most clock skew a tool server may allow, in seconds: five minutes. */
const MaxClockSkewSeconds = 300;

/**
 * The tool-server contract of spec section 9, without a framework: fetch and cache the control
 * plane's keys, validate the token, enforce the route's scope, introspect a high-risk route,
 * log the human and the agent on every request, and refuse a delegation chain deeper than this
 * server allows. The Express and Fastify adapters are this class with the plumbing of one
 * framework around it; anything else can call `guard()` directly.
 */
export class SubactIdToolServer {
  private readonly issuer: string;
  private readonly audience: string;
  private readonly requireActor: boolean;
  private readonly maxDelegationDepth: number;
  private readonly clockSkewSeconds: number;
  private readonly timeoutMs: number;
  private readonly realm: string;
  private readonly logEvent: (event: AccessEvent) => void;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly keys: JwksCache;
  private discovery: Promise<ToolServerEndpoints> | undefined;

  constructor(options: SubactIdToolServerOptions) {
    if (!options.issuer) throw new Error('issuer is required.');
    if (!options.audience) throw new Error('audience is required.');
    this.issuer = canonicalIssuer(options.issuer, options.allowInsecureHttp === true);
    this.audience = options.audience;
    this.requireActor = options.requireActor ?? true;
    this.maxDelegationDepth = options.maxDelegationDepth ?? 1;
    if (!(Number.isInteger(this.maxDelegationDepth) && this.maxDelegationDepth >= 1)) {
      throw new Error('maxDelegationDepth must be a whole number of at least 1.');
    }
    this.clockSkewSeconds = options.clockSkewSeconds ?? 60;
    // Bounded, because a skew of Infinity, NaN, a millisecond count or a string would let an
    // expired token through: it is added to exp and compared with now.
    if (!(
      Number.isInteger(this.clockSkewSeconds) &&
      this.clockSkewSeconds >= 0 &&
      this.clockSkewSeconds <= MaxClockSkewSeconds
    )) {
      throw new Error(`clockSkewSeconds must be a whole number from 0 to ${MaxClockSkewSeconds}.`);
    }
    this.timeoutMs = options.timeoutMs ?? 10_000;
    if (!(Number.isFinite(this.timeoutMs) && this.timeoutMs > 0)) {
      throw new Error('timeoutMs must be a positive, finite number.');
    }
    this.realm = options.realm ?? options.audience;
    this.logEvent = options.log ?? ((event) => console.log(JSON.stringify(event)));
    // Bound: called as a method of this object, the global fetch throws "Illegal invocation" in
    // browsers and Workers, which require it to be called with the global object as `this`.
    this.fetchImpl = options.fetch ?? fetch.bind(globalThis);
    this.now = options.now ?? Date.now;
    this.keys = new JwksCache({
      jwksUri: async () => (await this.endpoints('keys_unavailable')).jwksUri,
      fetch: this.fetchImpl,
      now: this.now,
      timeoutMs: this.timeoutMs,
    });
  }

  /**
   * Steps 1 and 2: the token's own validity, against the control plane's published keys. Says
   * nothing about what the caller may do; `authorize` decides that.
   */
  verifyToken(token: string): Promise<TaskToken> {
    return verifyTaskToken(token, {
      issuer: this.issuer,
      audience: this.audience,
      keys: this.keys,
      now: this.now,
      clockSkewSeconds: this.clockSkewSeconds,
    });
  }

  /** The same, from an `Authorization` header. */
  authenticate(authorization: string | string[] | undefined): Promise<TaskToken> {
    const header = Array.isArray(authorization) ? undefined : authorization;
    if (header === undefined || !/^Bearer /i.test(header) || header.slice(7).trim().length === 0) {
      return Promise.reject(
        new SubactIdAuthError(401, 'missing_token', 'A bearer token is required.'),
      );
    }
    return this.verifyToken(header.slice(7).trim());
  }

  /**
   * Steps 3, 4 and 6: the actor rules, the route's scope, and, for a high-risk route, the
   * control plane's own word on whether the token is still active. Returns the refusal, or
   * `undefined` when the caller may proceed. Does not log; `guard` does.
   */
  async authorize(
    claims: TaskToken,
    policy: RoutePolicy,
    options?: AuthorizeOptions,
  ): Promise<SubactIdAuthError | undefined> {
    // A route that asks for nothing says so by omitting `scope`; an empty one is a config that
    // lost its values on the way in, and serving it would be serving whatever is left.
    if (
      policy.scope === '' ||
      (Array.isArray(policy.scope) && (policy.scope.length === 0 || policy.scope.some((s) => !s)))
    ) {
      throw new Error('A route policy must not list an empty scope; omit scope to require none.');
    }
    const requireActor = policy.requireActor ?? this.requireActor;
    const maxDepth = policy.maxDelegationDepth ?? this.maxDelegationDepth;
    if (!(Number.isInteger(maxDepth) && maxDepth >= 1)) {
      throw new Error('maxDelegationDepth must be a whole number of at least 1.');
    }
    if (claims.act === undefined && requireActor) {
      return new SubactIdAuthError(
        401,
        'no_actor',
        'the token has no act claim; only an agent acting for a human may call this route.',
      );
    }
    if (claims.act !== undefined && claims.act.depth > maxDepth) {
      return new SubactIdAuthError(
        403,
        'delegation_too_deep',
        `the delegation chain is deeper than this route allows (${maxDepth}).`,
      );
    }
    const required =
      policy.scope === undefined ? [] : Array.isArray(policy.scope) ? policy.scope : [policy.scope];
    const missing = required.filter((scope) => !claims.scopes.includes(scope));
    if (missing.length > 0) {
      return new SubactIdAuthError(
        403,
        'insufficient_scope',
        `the token lacks scope ${missing.join(' ')}.`,
      );
    }
    // Either the route asked for it, or the control plane said this audience needs it.
    // `introspect_required` carries the operator's registration decision with the token,
    // so a server whose configuration was never updated to match still gets it right.
    const needed = policy.highRisk === true || claims.claims['introspect_required'] === true;
    if (needed && options?.alreadyIntrospected !== true) {
      return this.introspect(claims);
    }
    return undefined;
  }

  /**
   * The whole contract for one request: authenticate, authorize, log either way. Returns the
   * verified claims, or throws the `SubactIdAuthError` the caller should answer with.
   */
  async guard(
    authorization: string | string[] | undefined,
    policy: RoutePolicy,
    route: string,
  ): Promise<TaskToken> {
    let claims: TaskToken | undefined;
    let denial: SubactIdAuthError | undefined;
    try {
      claims = await this.authenticate(authorization);
      denial = await this.authorize(claims, policy);
    } catch (error) {
      if (!(error instanceof SubactIdAuthError)) throw error;
      denial = error;
    }
    this.log(route, claims, denial);
    if (denial) throw denial;
    return claims as TaskToken;
  }

  /** Step 5, on its own, for a caller that decides for itself. */
  log(route: string, claims: TaskToken | undefined, denial?: SubactIdAuthError | undefined): void {
    const event: AccessEvent = {
      event: 'request',
      at: new Date(this.now()).toISOString(),
      route,
      decision: denial ? 'deny' : 'allow',
    };
    if (denial) event.reason = denial.reason;
    if (claims) {
      event.sub = claims.sub;
      if (claims.act) {
        event.act = claims.act.sub;
        if (claims.act.instance !== undefined) event.instance = claims.act.instance;
        event.depth = claims.act.depth;
      }
      if (claims.taskId !== undefined) event.task_id = claims.taskId;
      event.jti = claims.jti;
    }
    this.logEvent(event);
  }

  /** How to answer a refusal: the status, the headers and the body. Anything unrecognised is a bare 500. */
  refusal(error: unknown): Refusal {
    if (!(error instanceof SubactIdAuthError)) {
      return {
        status: 500,
        headers: { 'content-type': 'application/json' },
        body: { error: 'server_error', error_description: 'The request could not be handled.' },
      };
    }
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (error.status !== 503) headers['www-authenticate'] = error.wwwAuthenticate(this.realm);
    // The control plane asked this server to wait; asking its caller to wait the same is what
    // stops one rate limit upstream from becoming a retry storm from everything downstream.
    if (error.retryAfterSeconds !== undefined) {
      headers['retry-after'] = String(error.retryAfterSeconds);
    }
    return {
      status: error.status,
      headers,
      body: {
        error:
          error.status === 403
            ? 'insufficient_scope'
            : error.status === 503
              ? 'temporarily_unavailable'
              : 'invalid_token',
        error_description: error.message,
      },
    };
  }

  /**
   * Where the control plane publishes its keys and answers introspection, from its discovery
   * document, fetched once. The document must be this issuer's, and both endpoints on its
   * origin: a token is sent to the introspection endpoint, and the keys decide what is trusted.
   * A failure is not cached, so the next request asks again; it is reported as `failure`, in the
   * terms of whichever step needed the document.
   */
  private async endpoints(
    failure: 'keys_unavailable' | 'introspection_unavailable',
  ): Promise<ToolServerEndpoints> {
    this.discovery ??= this.fetchDiscovery().catch((error: unknown) => {
      this.discovery = undefined;
      throw error;
    });
    try {
      return await this.discovery;
    } catch (cause) {
      throw new SubactIdAuthError(
        503,
        failure,
        // Only this package's own words go to the caller. What fetch or a network layer said can
        // name the URL it was given, and anything else it carries is not for an unauthenticated
        // caller either.
        `the control plane's discovery document could not be used: ${cause instanceof SubactIdAuthError || cause instanceof DiscoveryRefusal ? cause.message : 'it could not be reached.'}`,
        cause instanceof SubactIdAuthError ? cause.retryAfterSeconds : undefined,
      );
    }
  }

  private async fetchDiscovery(): Promise<ToolServerEndpoints> {
    const response = await this.fetchImpl(`${this.issuer}/.well-known/openid-configuration`, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(this.timeoutMs),
      redirect: 'error',
    });
    if (!response.ok) {
      throw new SubactIdAuthError(
        503,
        'keys_unavailable',
        `it answered ${response.status}.`,
        retryAfterSeconds(response),
      );
    }
    const document: unknown = await response.json().catch(() => undefined);
    const fields =
      typeof document === 'object' && document !== null
        ? (document as Record<string, unknown>)
        : {};
    if (typeof fields['issuer'] !== 'string' || !sameIssuer(fields['issuer'], this.issuer)) {
      throw new DiscoveryRefusal('it names a different issuer.');
    }
    const jwksUri = fields['jwks_uri'];
    if (typeof jwksUri !== 'string' || !sameOrigin(jwksUri, this.issuer)) {
      throw new DiscoveryRefusal('its jwks_uri is missing or not under the issuer.');
    }
    const introspection = fields['introspection_endpoint'];
    if (
      introspection !== undefined &&
      (typeof introspection !== 'string' || !sameOrigin(introspection, this.issuer))
    ) {
      throw new DiscoveryRefusal('its introspection_endpoint is not under the issuer.');
    }
    return {
      jwksUri,
      ...(typeof introspection === 'string' ? { introspectionEndpoint: introspection } : {}),
    };
  }

  /** Step 4: the control plane's own word on this very token. Anything but a clear "active" for it is a refusal. */
  private async introspect(claims: TaskToken): Promise<SubactIdAuthError | undefined> {
    let endpoint: string | undefined;
    try {
      endpoint = (await this.endpoints('introspection_unavailable')).introspectionEndpoint;
    } catch (error) {
      return error as SubactIdAuthError;
    }
    if (endpoint === undefined) {
      return new SubactIdAuthError(
        503,
        'introspection_unavailable',
        'the control plane publishes no introspection endpoint.',
      );
    }
    let response: Response;
    try {
      response = await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({ token: claims.token }).toString(),
        signal: AbortSignal.timeout(this.timeoutMs),
        // The token is sent to the issuer's own endpoint and nowhere a redirect points.
        redirect: 'error',
      });
    } catch {
      return new SubactIdAuthError(
        503,
        'introspection_unavailable',
        'the control plane could not be asked whether the token is still active.',
      );
    }
    if (!response.ok) {
      // The interval travels, as it does on the keys path. This is the path that needs it more:
      // the key set is cached for minutes at a time, while a high-risk route is introspected on every
      // request, so this is where one rate limit upstream turns into a storm from everything
      // downstream if the caller is told nothing.
      return new SubactIdAuthError(
        503,
        'introspection_unavailable',
        `the control plane answered ${response.status} to introspection.`,
        retryAfterSeconds(response),
      );
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return new SubactIdAuthError(
        503,
        'introspection_unavailable',
        'the control plane answered introspection without a JSON body.',
      );
    }
    const record =
      typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : {};
    if (
      record['active'] !== true ||
      (record['sub'] !== undefined && record['sub'] !== claims.sub) ||
      (record['jti'] !== undefined && record['jti'] !== claims.jti)
    ) {
      const reason =
        typeof record['revocation_reason'] === 'string' ? ` (${record['revocation_reason']})` : '';
      return new SubactIdAuthError(401, 'not_active', `the token is no longer active${reason}.`);
    }
    return undefined;
  }
}

/** The two endpoints a tool server calls, from the discovery document. */
interface ToolServerEndpoints {
  jwksUri: string;
  introspectionEndpoint?: string;
}

/** A discovery document this package refuses, in its own words: safe to pass to a caller. */
class DiscoveryRefusal extends Error {}

/**
 * The issuer as the control plane writes it into every token's `iss`: the URL in its canonical
 * form, so the host's case or a default port cannot make two spellings of one issuer disagree,
 * without a trailing slash. Anything that is not an absolute https URL is refused, because no
 * token matches it, except `http` on a loopback host, or anywhere when `allowInsecureHttp` says so.
 */
function canonicalIssuer(issuer: string, allowInsecureHttp = false): string {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new Error('issuer must be an absolute http or https URL.');
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.search || url.hash) {
    throw new Error('issuer must be an absolute http or https URL.');
  }
  if (url.username || url.password) {
    // Never sent anywhere, and an error naming the URL would carry them.
    throw new Error('issuer must not contain a user name or password.');
  }
  if (url.protocol === 'http:' && !allowInsecureHttp && !isLoopback(url.hostname)) {
    throw new Error(
      'issuer must use https unless it is on a loopback host; set allowInsecureHttp to accept plain http elsewhere.',
    );
  }
  return url.href.replace(/\/+$/, '');
}

/** `localhost`, an address in `127.0.0.0/8`, or `::1`: a host that never leaves this machine. */
function isLoopback(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '[::1]' ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
  );
}

function sameIssuer(claimed: string, issuer: string): boolean {
  try {
    return canonicalIssuer(claimed, true) === issuer;
  } catch {
    return false;
  }
}

function sameOrigin(url: string, issuer: string): boolean {
  try {
    return new URL(url).origin === new URL(issuer).origin;
  } catch {
    return false;
  }
}
