import { AssertionSigner, type AssertionSignerOptions } from './assertion.js';
import {
  isTaskOver,
  oauthError,
  type OAuthError,
  SubactIdError,
  TransportError,
} from './errors.js';
import { TaskSession } from './session.js';
import { MemoryTaskGrantStore, type StoredTaskGrant, type TaskGrantStore } from './store.js';
import type { Discovery, ExchangeRequest, TokenResponse } from './types.js';

const tokenExchangeGrant = 'urn:ietf:params:oauth:grant-type:token-exchange';
const accessTokenType = 'urn:ietf:params:oauth:token-type:access_token';
const jwtTokenType = 'urn:ietf:params:oauth:token-type:jwt';
const jwtBearerAssertion = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export interface SubactIdClientOptions extends AssertionSignerOptions {
  /**
   * The control plane's issuer URL, as in its discovery document. `https`, or `http` on a
   * loopback host (`localhost`, `127.0.0.0/8`, `::1`) for local development.
   */
  issuer: string;
  /**
   * Accept an `http` issuer that is not on a loopback host. The user's token, the task grant and
   * every signed assertion then travel in the clear: for a demo or a network you trust, never
   * for production. Default false.
   */
  allowInsecureHttp?: boolean;
  /** Where task grants live; defaults to memory. */
  grantStore?: TaskGrantStore;
  /** The fetch to use; defaults to the global one. */
  fetch?: typeof fetch;
  /** Called after every successful refresh of any session. */
  onRefresh?: (session: TaskSession, token: TokenResponse) => void;
  /** Called when a refresh of any session fails. */
  onRefreshError?: (session: TaskSession, error: unknown) => void;
  /** Whether refresh timers keep the process alive; defaults to no. */
  keepAlive?: boolean;
  /**
   * Time limit in milliseconds for each request to the control plane, answer included. A request
   * that runs over is a `TransportError`, retried like any other. Default 10000.
   */
  timeoutMs?: number;
}

/**
 * The agent's side of the control plane: exchanges a user's token for a task, and keeps the
 * task's token fresh through a `TaskSession`. One client per agent; any number of tasks.
 */
export class SubactIdClient {
  private readonly issuer: string;
  private readonly signer: AssertionSigner;
  private readonly store: TaskGrantStore;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  readonly #options: SubactIdClientOptions;
  private discovery: Promise<Discovery> | undefined;

  constructor(options: SubactIdClientOptions) {
    if (!options.issuer) throw new SubactIdError('issuer is required.');
    this.#options = options;
    this.issuer = canonicalIssuer(options.issuer, options.allowInsecureHttp === true);
    this.signer = new AssertionSigner(options);
    this.store = options.grantStore ?? new MemoryTaskGrantStore();
    // Bound: called as a method of this object, the global fetch throws "Illegal invocation" in
    // browsers and Workers, which require it to be called with the global object as `this`.
    this.fetchImpl = options.fetch ?? fetch.bind(globalThis);
    this.now = options.now ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    // AbortSignal.timeout takes a whole number of milliseconds, and a timer set past 2^31 - 1
    // fires at once, so anything outside that range would fail every request.
    if (!(
      Number.isInteger(this.timeoutMs) &&
      this.timeoutMs > 0 &&
      this.timeoutMs <= 2_147_483_647
    )) {
      throw new SubactIdError('timeoutMs must be a whole number from 1 to 2147483647.');
    }
  }

  /** The control plane's discovery document, fetched once. */
  discover(): Promise<Discovery> {
    this.discovery ??= this.fetchDiscovery().catch((error: unknown) => {
      this.discovery = undefined;
      throw error;
    });
    return this.discovery;
  }

  /** Exchanges a user's token for a task and starts keeping its token fresh. */
  async exchange(request: ExchangeRequest): Promise<TaskSession> {
    if (!request.subjectToken) throw new SubactIdError('subjectToken is required.');
    if (!request.resource) throw new SubactIdError('resource is required.');
    if (!request.scope) throw new SubactIdError('scope is required.');
    const { token_endpoint, issuer } = await this.discover();
    const requestedAt = this.now();
    const token = await this.postToken(
      token_endpoint,
      {
        grant_type: tokenExchangeGrant,
        subject_token: request.subjectToken,
        subject_token_type: accessTokenType,
        // Addressed to the issuer, exactly as published, which the control plane accepts at every
        // endpoint that takes an assertion (spec section 1).
        actor_token: await this.signer.sign(issuer),
        actor_token_type: jwtTokenType,
        requested_token_type: accessTokenType,
        resource: request.resource,
        scope: request.scope,
      },
      request.scope,
      'exchange',
    );
    // Stored before the session exists, so a store that fails leaves no session refreshing on its own.
    await this.store.save(stored(token, request.resource));
    return this.session(token, request.resource, requestedAt);
  }

  /**
   * Picks a task up again from the grant store, refreshing it at once; `undefined` when the
   * store has no such task or the task has already expired. A task the control plane says is
   * over (`isTaskOver`) is removed from the store before the error is thrown; one refused for a
   * reason that can be lifted, such as a disabled agent, is kept, to be resumed once it is.
   */
  async resume(taskId: string): Promise<TaskSession | undefined> {
    const record = await this.store.load(taskId);
    if (!record) {
      return undefined;
    }
    if (!(new Date(record.taskExpiresAt).getTime() > this.now())) {
      await this.store.remove(taskId);
      return undefined;
    }
    const requestedAt = this.now();
    let token: TokenResponse;
    try {
      token = await this.refresh(record.grant, record.resource, record.scope);
    } catch (error) {
      if (isTaskOver(error)) {
        await this.store.remove(taskId);
      }
      throw error;
    }
    // A grant renews its own task. An answer for another task is not this one's, and saving it
    // would file one task's grant under another's id.
    if (token.task_id !== taskId) {
      throw new TransportError('The refresh answered for a different task.');
    }
    await this.store.save(stored(token, record.resource));
    return this.session(token, record.resource, requestedAt);
  }

  /**
   * Revokes a task token or a task grant at the control plane (spec section 6, RFC 7009). A
   * grant revokes its task and every token under it; a token is revoked by its `jti`. Only the
   * agent a token was issued to can revoke it, and the control plane answers the same empty
   * `200` to anything else, a token that does not exist included, so a return says the request
   * was accepted and nothing about whether anything changed. A session revokes its own task
   * through `TaskSession.revoke()`. `hint` is sent as `token_type_hint`; Subact ID v0.1 ignores
   * it, and a hint it does not know is not refused.
   */
  async revoke(token: string, hint?: 'access_token' | 'refresh_token'): Promise<void> {
    if (!token) throw new SubactIdError('token is required.');
    const { revocation_endpoint, issuer } = await this.discover();
    if (typeof revocation_endpoint !== 'string') {
      throw new TransportError('The discovery document has no revocation_endpoint.');
    }
    const response = await this.postForm(revocation_endpoint, 'revocation', {
      token,
      ...(hint === undefined ? {} : { token_type_hint: hint }),
      client_assertion_type: jwtBearerAssertion,
      client_assertion: await this.signer.sign(issuer),
    });
    if (!response.ok) {
      throw await refusal(response);
    }
  }

  /** One refresh (spec section 5), as the sessions call it. `scope` must never be wider than the task holds. */
  async refresh(grant: string, resource: string, scope: string): Promise<TokenResponse> {
    const { token_endpoint, issuer } = await this.discover();
    return this.postToken(
      token_endpoint,
      {
        grant_type: 'refresh_token',
        refresh_token: grant,
        resource,
        scope,
        client_assertion_type: jwtBearerAssertion,
        client_assertion: await this.signer.sign(issuer),
      },
      scope,
      'refresh',
    );
  }

  private session(token: TokenResponse, resource: string, requestedAt: number): TaskSession {
    const session: TaskSession = new TaskSession(token, resource, requestedAt, {
      refresh: (grant, res, scope) => this.refresh(grant, res, scope),
      revoke: (grant) => this.revoke(grant, 'refresh_token'),
      store: this.store,
      now: this.now,
      onRefresh: this.#options.onRefresh ? (t) => this.#options.onRefresh?.(session, t) : undefined,
      onError: this.#options.onRefreshError
        ? (e) => this.#options.onRefreshError?.(session, e)
        : undefined,
      keepAlive: this.#options.keepAlive,
    });
    return session;
  }

  private async fetchDiscovery(): Promise<Discovery> {
    const url = `${this.issuer}/.well-known/openid-configuration`;
    let response: Response;
    try {
      // No redirect is followed: the document says where credentials go, so it must be the issuer's.
      response = await this.fetchImpl(url, {
        headers: { accept: 'application/json' },
        redirect: 'error',
        // A stalled connection would otherwise hold every caller waiting on this client.
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (cause) {
      throw new TransportError('The control plane could not be reached for discovery.', { cause });
    }
    if (!response.ok) {
      // Discovery is the first thing a cold client fetches, and it is admission-controlled like
      // every other endpoint: a 429 `slow_down` or a 503 `temporarily_unavailable` here is the
      // control plane asking for time, with its `Retry-After`, and saying so is what lets a
      // caller wait the interval it asked for. Everything else is a transport failure, however
      // OAuth-shaped the body looks — see `retryLater`.
      throw (
        (await retryLater(response)) ?? new TransportError(`Discovery answered ${response.status}.`)
      );
    }
    const document = (await parseJson(response)) as Partial<Discovery>;
    for (const field of ['issuer', 'token_endpoint', 'jwks_uri'] as const) {
      if (typeof document[field] !== 'string') {
        throw new TransportError(`The discovery document has no ${field}.`);
      }
    }
    // OpenID Connect Discovery 4.3: the document must be the configured issuer's, and its
    // endpoints must be its own, or a user's token and a signed assertion go somewhere else.
    if (!sameIssuer(document.issuer!, this.issuer)) {
      throw new TransportError('The discovery document names a different issuer.');
    }
    // Every endpoint, not only the two this client posts to: `revocation_endpoint` takes a task
    // grant and `introspection_endpoint` takes a token, both with the agent's signed assertion,
    // and both are handed to callers from `discover()`. An endpoint that is not the issuer's own
    // is a credential sent somewhere else.
    for (const field of [
      'token_endpoint',
      'jwks_uri',
      'introspection_endpoint',
      'revocation_endpoint',
    ] as const) {
      const value = document[field];
      if (value !== undefined && !sameOrigin(value, this.issuer)) {
        throw new TransportError(`The discovery document's ${field} is not under the issuer.`);
      }
    }
    return document as Discovery;
  }

  /**
   * One request to the token endpoint. `requestedScope` is what was asked for: the answer's
   * scope must be within it, or the answer is not one this client acts on.
   */
  private async postToken(
    endpoint: string,
    form: Record<string, string>,
    requestedScope: string,
    kind: 'exchange' | 'refresh',
  ): Promise<TokenResponse> {
    const response = await this.postForm(endpoint, 'token', form);
    if (!response.ok) {
      throw await refusal(response);
    }
    const body = await parseJson(response);
    for (const field of [
      'access_token',
      'refresh_token',
      'task_id',
      'task_expires_at',
      'scope',
    ] as const) {
      if (typeof body[field] !== 'string') {
        throw new TransportError(`The token response has no ${field}.`);
      }
    }
    if (typeof body['expires_in'] !== 'number' || !(body['expires_in'] > 0)) {
      throw new TransportError('The token response has no usable expires_in.');
    }
    // A bearer token is what every caller of this client presents (RFC 6750); anything else is
    // not a token it knows how to use.
    if (typeof body['token_type'] !== 'string' || body['token_type'].toLowerCase() !== 'bearer') {
      throw new TransportError('The token response is not a Bearer token.');
    }
    // RFC 8693 section 2.2.1: an exchange says what it issued, and this client asked for an
    // access token. A refresh need not say, but one that does must say the same.
    const issuedType = body['issued_token_type'];
    if ((kind === 'exchange' || issuedType !== undefined) && issuedType !== accessTokenType) {
      throw new TransportError('The token response did not issue an access token.');
    }
    const taskExpiresAt = new Date(body['task_expires_at'] as string).getTime();
    if (Number.isNaN(taskExpiresAt)) {
      throw new TransportError('The token response has no usable task_expires_at.');
    }
    // Scope only narrows (spec section 3): the effective scope is an intersection that includes
    // what was requested, so it can never hold a scope that was not asked for. One that does is
    // an answer this client cannot act on — keeping it would put the widened scope in the store
    // and on the next refresh's wire, and this client never asks for more than it was granted.
    const granted = (body['scope'] as string).split(' ').filter(Boolean);
    // A task always holds at least one scope; an empty grant would put `scope=` on the next
    // refresh's wire.
    if (granted.length === 0) {
      throw new TransportError('The token response grants no scope.');
    }
    const asked = new Set(requestedScope.split(' ').filter(Boolean));
    const extra = granted.filter((scope) => !asked.has(scope));
    if (extra.length > 0) {
      throw new TransportError(
        `The token response grants scope that was not requested: ${extra.join(' ')}.`,
      );
    }
    return body as unknown as TokenResponse;
  }

  /** One form post to an OAuth endpoint (RFC 6749 section 4.5); only reaching it is judged here. */
  private async postForm(
    endpoint: string,
    name: string,
    form: Record<string, string>,
  ): Promise<Response> {
    try {
      return await this.fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams(form).toString(),
        // A redirect would resend the user's token, a grant or a signed assertion to wherever it
        // points, undoing the origin check discovery makes.
        redirect: 'error',
        // A stalled connection would otherwise hold a shared refresh, and every caller waiting on
        // it, until the platform gives up.
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (cause) {
      throw new TransportError(`The ${name} endpoint could not be reached.`, { cause });
    }
  }
}

/** The typed error for an answer that is not a success; a `TransportError` is thrown when the body is not an OAuth error. */
async function refusal(response: Response): Promise<OAuthError> {
  return typedError(await parseJson(response), response);
}

/**
 * The `slow_down` a rate-limited answer names, or the `temporarily_unavailable` of a control
 * plane at capacity or without its database, and nothing else.
 *
 * Discovery carries no credential, so nothing it answers is a decision about this agent or the
 * human it acts for. A `401 {"error":"invalid_client"}` or a `403 {"error":"access_denied"}` on
 * it did not come from the control plane — it came from something standing in front of one: a
 * gateway, a proxy, a WAF that speaks OAuth. `resume` drops a task's grant on a terminal
 * refusal, so those are not typed as the control plane's refusal: a proxy's bad minute during a
 * restart, which is exactly when discovery is fetched cold, leaves the grant of a task the
 * control plane still holds in place and does not report the human as blocked.
 *
 * Being asked for time is the one thing worth reading here, because spec section 8 gives it a
 * shape nothing else has — `429` with `slow_down`, or `503` with `temporarily_unavailable`, and a
 * `Retry-After` — and a caller told the interval is one that does not spend the next bucket
 * too. Both are retryable and neither is terminal, so reading one that a proxy wrote in the
 * control plane's words can only make a caller wait, never drop a grant.
 */
async function retryLater(response: Response): Promise<OAuthError | undefined> {
  const expected =
    response.status === 429
      ? 'slow_down'
      : response.status === 503
        ? 'temporarily_unavailable'
        : undefined;
  if (expected === undefined) return undefined;
  const body = await parseJson(response).catch(() => undefined);
  return body?.['error'] === expected ? typedError(body, response) : undefined;
}

/** The typed error an OAuth error body names, carrying the answer's `Retry-After` where it had one. */
function typedError(body: Record<string, unknown>, response: Response): OAuthError {
  const error = typeof body['error'] === 'string' ? body['error'] : 'unknown';
  const description =
    typeof body['error_description'] === 'string' ? body['error_description'] : 'No description.';
  const reason = typeof body['reason'] === 'string' ? body['reason'] : undefined;
  return oauthError(error, description, response.status, retryAfterSeconds(response), reason);
}

/**
 * The issuer as the control plane writes it into `iss` and its discovery document: the URL in
 * its canonical form, so the host's case or a default port cannot make two spellings of one
 * issuer disagree, without a trailing slash. Anything that is not an absolute https URL is
 * refused, because nothing the control plane writes matches it, except `http` on a loopback
 * host, or anywhere when `allowInsecureHttp` says so.
 */
function canonicalIssuer(issuer: string, allowInsecureHttp = false): string {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new SubactIdError('issuer must be an absolute http or https URL.');
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.search || url.hash) {
    throw new SubactIdError('issuer must be an absolute http or https URL.');
  }
  if (url.username || url.password) {
    // Never sent anywhere, and an error naming the URL would carry them.
    throw new SubactIdError('issuer must not contain a user name or password.');
  }
  if (url.protocol === 'http:' && !allowInsecureHttp && !isLoopback(url.hostname)) {
    throw new SubactIdError(
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

async function parseJson(response: Response): Promise<Record<string, unknown>> {
  let body: unknown;
  try {
    body = await response.json();
  } catch (cause) {
    const timedOut =
      cause instanceof Error && (cause.name === 'TimeoutError' || cause.name === 'AbortError');
    throw new TransportError(
      timedOut
        ? `The control plane's ${response.status} answer could not be read in time.`
        : `The control plane answered ${response.status} without a JSON body.`,
      { cause },
    );
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new TransportError(
      `The control plane answered ${response.status} with a body that is not an object.`,
    );
  }
  return body as Record<string, unknown>;
}

function stored(token: TokenResponse, resource: string): StoredTaskGrant {
  return {
    taskId: token.task_id,
    grant: token.refresh_token,
    resource,
    scope: token.scope,
    taskExpiresAt: token.task_expires_at,
  };
}

/**
 * The answer's `Retry-After` as whole seconds, which is how the control plane writes it on a
 * `slow_down` and a `temporarily_unavailable`. The HTTP-date form is not read: it needs the
 * server's clock to mean anything, and the control plane never sends it.
 */
function retryAfterSeconds(response: Response): number | undefined {
  const value = response.headers.get('retry-after')?.trim();
  return value !== undefined && /^\d{1,9}$/.test(value) ? Number(value) : undefined;
}

function sameOrigin(url: string, issuer: string): boolean {
  try {
    return new URL(url).origin === new URL(issuer).origin;
  } catch {
    return false;
  }
}
