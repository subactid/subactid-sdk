import { base64UrlDecode } from './base64url.js';
import { SubactIdAuthError } from './errors.js';

/** A published P-256 key, imported for verification. */
export interface VerificationKey {
  kid: string;
  key: CryptoKey;
}

export interface JwksCacheOptions {
  /**
   * Where the control plane publishes its keys, or how to find out: a function is called before
   * each fetch, so the address can come from a discovery document fetched on first use.
   */
  jwksUri: string | (() => Promise<string>);
  fetch: typeof fetch;
  now: () => number;
  /**
   * How long a fetched set is served before it is fetched again when the answer names no
   * `max-age`; default five minutes. An answer's `max-age` wins. Either is held between thirty
   * seconds and an hour.
   */
  ttlMs?: number;
  /**
   * How long the last good set may still be used, once it is due to be fetched again, while
   * every fetch fails; default one hour. After that no key is served until a fetch succeeds.
   */
  maxStaleMs?: number;
  /** Least time between fetches forced by an unknown `kid`; default thirty seconds. */
  minRefreshMs?: number;
  /** How long one fetch may take; default ten seconds. */
  timeoutMs?: number;
}

/** The shortest and longest a set is served for, whatever the answer's `max-age` says. */
const minTtlMs = 30_000;
const maxTtlMs = 60 * 60_000;

/**
 * Step 1 of the tool-server contract: the control plane's JWKS, fetched over https, cached for
 * as long as the answer's `Cache-Control: max-age` says, and fetched again when a token names a
 * `kid` the cache does not know, at most every so often so a stream of bad tokens cannot turn
 * into a stream of fetches. Only P-256 keys are kept, because ES256 is what task tokens are
 * signed with.
 *
 * A fetch that fails leaves the last good set in use, because its keys are still the control
 * plane's keys — but not for ever. A key the control plane stopped publishing (a disclosed one,
 * `docs/keys.md` step 3) must stop verifying tokens here too, so once the set has been due for
 * `maxStaleMs` it is dropped and every token is refused as `keys_unavailable` until a fetch
 * succeeds.
 */
export class JwksCache {
  private readonly options: Required<JwksCacheOptions>;
  private keys = new Map<string, CryptoKey>();
  /** When the set in hand is due to be fetched again. */
  private expiresAt = Number.NEGATIVE_INFINITY;
  private lastAttempt = Number.NEGATIVE_INFINITY;
  private inFlight: Promise<void> | undefined;

  constructor(options: JwksCacheOptions) {
    this.options = {
      ttlMs: 5 * 60_000,
      maxStaleMs: 60 * 60_000,
      minRefreshMs: 30_000,
      timeoutMs: 10_000,
      ...options,
    };
  }

  /** The key for `kid`, fetching the set first when it is stale or the `kid` is new. */
  async get(kid: string): Promise<CryptoKey> {
    // Both the stale set and an unknown kid fetch again, never more often than the rate limit allows.
    const now = this.options.now();
    this.rebaseOnClockStep(now);
    if (now >= this.expiresAt && now - this.lastAttempt >= this.options.minRefreshMs) {
      await this.refresh();
    }
    this.dropIfTooStale();
    let key = this.keys.get(kid);
    if (key === undefined) {
      // A fetch already running is the answer this caller is waiting for, so join it rather than
      // be turned away by a rate limit the caller that started it already paid. Without this, a
      // signing key rotation costs every request that arrives during the first fetch a spurious
      // `unknown_key`, for as long as the rate limit lasts, even though the keys are on the way.
      if (this.inFlight !== undefined) {
        await this.inFlight.catch(() => undefined);
      } else if (this.options.now() - this.lastAttempt >= this.options.minRefreshMs) {
        await this.refresh();
      }
      this.dropIfTooStale();
      key = this.keys.get(kid);
    }
    if (key === undefined) {
      if (this.keys.size === 0) {
        throw unavailable();
      }
      throw new SubactIdAuthError(
        401,
        'unknown_key',
        'The token is signed with a key the control plane does not publish.',
      );
    }
    return key;
  }

  /**
   * Both times are absolute, so a clock stepped backwards puts them in the future. An attempt in
   * the future is forgotten, so it neither rate limits an unknown `kid` nor holds back the next
   * fetch. No answer is served for longer than `maxTtlMs`, so an expiry further off than that is
   * due now, and `maxStaleMs` counts from here rather than from an expiry the clock has not
   * reached.
   */
  private rebaseOnClockStep(now: number): void {
    if (now < this.lastAttempt) {
      this.lastAttempt = Number.NEGATIVE_INFINITY;
    }
    if (this.expiresAt - now > maxTtlMs) {
      this.expiresAt = now;
    }
  }

  /** Forgets a set that has been due for longer than `maxStaleMs`: its keys may not be the control plane's any more. */
  private dropIfTooStale(): void {
    if (this.keys.size > 0 && this.options.now() - this.expiresAt >= this.options.maxStaleMs) {
      this.keys = new Map();
    }
  }

  private refresh(): Promise<void> {
    this.inFlight ??= this.doRefresh().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  private async doRefresh(): Promise<void> {
    this.lastAttempt = this.options.now();
    let answer: { document: unknown; ttlMs: number };
    try {
      answer = await this.fetchKeys();
    } catch (cause) {
      // Keep serving the last good set, within its bound; its keys are still the control plane's keys.
      if (this.usable()) return;
      throw cause instanceof SubactIdAuthError ? cause : unavailable();
    }
    const { document } = answer;
    const keys =
      typeof document === 'object' && document !== null
        ? (document as { keys?: unknown }).keys
        : undefined;
    const imported = new Map<string, CryptoKey>();
    for (const jwk of Array.isArray(keys) ? keys : []) {
      const key = await importP256(jwk);
      if (key) imported.set(key.kid, key.key);
    }
    if (imported.size === 0) {
      // A document with no usable key is a broken answer, not a control plane with no keys.
      if (this.usable()) return;
      throw new SubactIdAuthError(
        503,
        'keys_unavailable',
        "The control plane's keys could not be read.",
      );
    }
    this.keys = imported;
    this.expiresAt = this.options.now() + answer.ttlMs;
  }

  /** Whether the set in hand may still be served after a failed fetch. */
  private usable(): boolean {
    this.dropIfTooStale();
    return this.keys.size > 0;
  }

  /** The published document, or the refusal the control plane gave instead of it. */
  private async fetchKeys(): Promise<{ document: unknown; ttlMs: number }> {
    const uri =
      typeof this.options.jwksUri === 'string'
        ? this.options.jwksUri
        : await this.options.jwksUri();
    const response = await this.options.fetch(uri, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(this.options.timeoutMs),
      // The keys are the issuer's own; an answer that sends them elsewhere is not followed.
      redirect: 'error',
    });
    if (!response.ok) throw await keysRefused(response);
    return {
      document: await response.json(),
      ttlMs: cacheLifetimeMs(response.headers.get('cache-control'), this.options.ttlMs),
    };
  }
}

function unavailable(): SubactIdAuthError {
  return new SubactIdAuthError(
    503,
    'keys_unavailable',
    "The control plane's keys could not be fetched.",
  );
}

/**
 * How long an answer may be served for: its `max-age`, held between thirty seconds and an hour,
 * or `fallbackMs` when it names none. The control plane sends `public, max-age=300`. A
 * `no-store` or `no-cache` is served for the shortest time rather than refetched per request,
 * so not every request becomes a fetch.
 */
export function cacheLifetimeMs(cacheControl: string | null, fallbackMs: number): number {
  const directives = (cacheControl ?? '')
    .toLowerCase()
    .split(',')
    .map((d) => d.trim());
  const maxAge = directives
    .map((d) => /^max-age\s*=\s*"?(\d+)"?$/.exec(d)?.[1])
    .find((v) => v !== undefined);
  let ttl: number;
  if (directives.includes('no-store') || directives.includes('no-cache')) {
    ttl = minTtlMs;
  } else if (maxAge !== undefined) {
    // Any number of digits is a max-age; one too long to read is simply longer than the cap.
    const seconds = Number(maxAge);
    ttl = Number.isFinite(seconds) ? seconds * 1000 : maxTtlMs;
  } else {
    ttl = fallbackMs;
  }
  return Math.min(Math.max(ttl, minTtlMs), maxTtlMs);
}

/**
 * Why the keys were refused, read from the answer rather than from its status alone. The keys
 * request is rate limited like every other (spec section 8), and the control plane says so as
 * `slow_down` with a `Retry-After`: a tool server that keeps that interval is one the control
 * plane does not have to refuse again, and one whose caller can be told the same. Nothing the
 * answer says is repeated in the message — the status and the reason are this server's own.
 */
async function keysRefused(response: Response): Promise<SubactIdAuthError> {
  const body: unknown = await response.json().catch(() => undefined);
  const error =
    typeof body === 'object' && body !== null
      ? (body as Record<string, unknown>)['error']
      : undefined;
  const why =
    error === 'slow_down'
      ? 'the control plane is rate limiting this source'
      : `the control plane answered ${response.status}`;
  return new SubactIdAuthError(
    503,
    'keys_unavailable',
    `The control plane's keys could not be fetched: ${why}.`,
    retryAfterSeconds(response),
  );
}

/**
 * The answer's `Retry-After` as whole seconds, which is how the control plane writes it. The
 * HTTP-date form is not read: it needs the server's clock to mean anything, and the control
 * plane never sends it.
 *
 * Exported because the keys path is not the only one the control plane rate limits: the
 * introspection path reads it too, and one reader is one place for the two to agree.
 */
export function retryAfterSeconds(response: Response): number | undefined {
  const value = response.headers.get('retry-after')?.trim();
  return value !== undefined && /^\d{1,9}$/.test(value) ? Number(value) : undefined;
}

/** One published JWK imported for verification, or nothing when it is not a P-256 signing key. */
export async function importP256(jwk: unknown): Promise<VerificationKey | undefined> {
  if (typeof jwk !== 'object' || jwk === null) return undefined;
  const { kty, crv, kid, x, y, use, alg } = jwk as Record<string, unknown>;
  if (
    kty !== 'EC' ||
    crv !== 'P-256' ||
    typeof kid !== 'string' ||
    typeof x !== 'string' ||
    typeof y !== 'string'
  ) {
    return undefined;
  }
  if ((use !== undefined && use !== 'sig') || (alg !== undefined && alg !== 'ES256')) {
    return undefined;
  }
  try {
    base64UrlDecode(x);
    base64UrlDecode(y);
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty, crv, x, y },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return { kid, key };
  } catch {
    return undefined;
  }
}
