import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AuditCheckpoint, AuditProof, AuditRecord } from '../src/audit.js';

export const issuer = 'https://subactid.internal.example.com';
export const audience = 'https://jira.internal';

/**
 * A ledger captured from a running control plane: the answers of `GET /audit`,
 * `GET /audit/checkpoints`, `GET /audit/records/{seq}/proof` and its JWKS, as it gave them. It is
 * what the audit endpoints below serve, so a test that verifies a proof here is verifying one
 * the server really produced rather than one written to pass.
 */
export const ledger = JSON.parse(
  readFileSync(new URL('./fixtures/ledger.json', import.meta.url), 'utf8'),
) as {
  records: AuditRecord[];
  checkpoints: AuditCheckpoint[];
  proofs: Record<string, AuditProof>;
  jwks: { keys: unknown[] };
};

const b64 = (bytes: Buffer | string): string => Buffer.from(bytes).toString('base64url');

/** A signing key the fake control plane publishes, and the tokens it mints. */
export class FakeControlPlane {
  keys: { kid: string; privateKey: string; publicJwk: JsonWebKey }[] = [];
  jwksFetches = 0;
  jwksStatus = 200;
  jwksFails = false;
  /** The JWKS answer's `Cache-Control`, as the control plane sends it; `undefined` sends none. */
  jwksCacheControl: string | undefined = 'public, max-age=300';
  /** When set, served as the JWKS body verbatim. */
  jwksRaw: string | undefined;
  /** When set with a non-200 `jwksStatus`, the refusal the control plane answers the keys request with. */
  jwksRefusal: { body: unknown; headers?: Record<string, string> } | undefined;
  /** Requests that carried no abort signal. */
  unsignalled: string[] = [];
  introspections: string[] = [];
  /**
   * The introspection answer. By default the control plane's own (spec section 6): an active
   * token of this control plane answers its claims plus `task_id`, anything else `active: false`.
   */
  introspection: Record<string, unknown> | ((token: string) => Record<string, unknown>) = (token) =>
    this.introspect(token);
  /** The claims of every token this control plane minted, by the token. */
  private minted = new Map<string, Record<string, unknown>>();
  introspectionStatus = 200;
  /** Headers on a non-200 introspection answer; a rate limit names its interval here. */
  introspectionHeaders: Record<string, string> | undefined;
  introspectionFails = false;
  /** Discovery requests seen, and what the document says; tests change it to misdirect. */
  discoveryFetches = 0;
  discovery: Record<string, unknown> = {
    issuer,
    token_endpoint: `${issuer}/oauth2/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    introspection_endpoint: `${issuer}/oauth2/introspect`,
    revocation_endpoint: `${issuer}/oauth2/revoke`,
  };
  discoveryStatus = 200;
  /** Requests that would have followed a redirect rather than refusing one. */
  followed: string[] = [];
  now: () => number;

  constructor(now: () => number) {
    this.now = now;
    this.rotate('key-1');
  }

  rotate(kid: string): void {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.keys.push({
      kid,
      privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
      publicJwk: publicKey.export({ format: 'jwk' }),
    });
  }

  /** A task token as the control plane would issue it; `overrides` replace claims, `header` replaces header fields. */
  token(
    overrides: Record<string, unknown> = {},
    header: Record<string, unknown> = {},
    kid = this.keys.at(-1)!.kid,
  ): string {
    const nowSeconds = Math.floor(this.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: issuer,
      sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      aud: audience,
      exp: nowSeconds + 300,
      iat: nowSeconds,
      jti: `tok_${Math.random().toString(36).slice(2)}`,
      scope: 'jira:read jira:comment',
      client_id: 'agent:jira-triage',
      act: { sub: 'agent:jira-triage', instance: 'pod-7f9c4b', depth: 1 },
      task: {
        id: 'task_01HQZX9K4M',
        exp: nowSeconds + 1800,
        sponsor: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
      },
      ...overrides,
    };
    for (const [name, value] of Object.entries(overrides)) {
      if (value === undefined) delete claims[name];
    }
    const h = b64(JSON.stringify({ alg: 'ES256', typ: 'at+jwt', kid, ...header }));
    const c = b64(JSON.stringify(claims));
    const key = this.keys.find((k) => k.kid === kid) ?? this.keys.at(-1)!;
    const signature = sign('sha256', Buffer.from(`${h}.${c}`), {
      key: createPrivateKey(key.privateKey),
      dsaEncoding: 'ieee-p1363',
    });
    const token = `${h}.${c}.${b64(signature)}`;
    this.minted.set(token, claims);
    return token;
  }

  /** Answered from what was minted, as the control plane answers from storage: live, or plain inactive. */
  private introspect(token: string): Record<string, unknown> {
    const claims = this.minted.get(token);
    const exp = claims?.['exp'];
    if (claims === undefined || typeof exp !== 'number' || exp <= Math.floor(this.now() / 1000)) {
      return { active: false };
    }
    const task = claims['task'];
    const taskId =
      typeof task === 'object' && task !== null
        ? (task as Record<string, unknown>)['id']
        : undefined;
    return { active: true, ...claims, ...(taskId === undefined ? {} : { task_id: taskId }) };
  }

  /** A token signed by a key the control plane never published. */
  forged(): string {
    const stranger = new FakeControlPlane(this.now);
    return stranger.token({}, {}, 'key-1');
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!(init?.signal instanceof AbortSignal)) this.unsignalled.push(url);
    if (init?.redirect !== 'error') this.followed.push(url);
    if (url === `${issuer}/.well-known/openid-configuration`) {
      this.discoveryFetches++;
      return this.discoveryStatus === 200
        ? json(this.discovery)
        : new Response('no', { status: this.discoveryStatus });
    }
    if (url === `${issuer}/.well-known/jwks.json`) {
      this.jwksFetches++;
      if (this.jwksFails) throw new TypeError('fetch failed');
      if (this.jwksStatus !== 200) {
        return this.jwksRefusal === undefined
          ? new Response('no', { status: this.jwksStatus })
          : new Response(JSON.stringify(this.jwksRefusal.body), {
              status: this.jwksStatus,
              headers: { 'content-type': 'application/json', ...this.jwksRefusal.headers },
            });
      }
      const cache: Record<string, string> =
        this.jwksCacheControl === undefined ? {} : { 'cache-control': this.jwksCacheControl };
      if (this.jwksRaw !== undefined) {
        return new Response(this.jwksRaw, { status: 200, headers: cache });
      }
      return json(
        {
          keys: this.keys.map((k) => ({ ...k.publicJwk, kid: k.kid, alg: 'ES256', use: 'sig' })),
        },
        cache,
      );
    }
    // The two endpoints of spec section 7.1, answering out of the captured ledger. The page is
    // whatever `after` and `limit` ask for, so a caller that walks the pages is exercised.
    if (url.startsWith(`${issuer}/audit/checkpoints`)) {
      const query = new URL(url).searchParams;
      const after = Number(query.get('after') ?? 0);
      const limit = Math.min(Number(query.get('limit') ?? 100), 1000);
      const remaining = ledger.checkpoints.filter((c) => c.checkpoint_id > after);
      const page = remaining.slice(0, limit);
      return json({
        checkpoints: page,
        next_after: remaining.length > limit ? (page.at(-1)?.checkpoint_id ?? null) : null,
      });
    }
    const proof = /\/audit\/records\/(\d+)\/proof$/.exec(url);
    if (proof !== null && url.startsWith(issuer)) {
      // A record that does not exist, or that the sealing pass has not reached, has no proof.
      const found = ledger.proofs[proof[1] as string];
      return found === undefined ? new Response('not found', { status: 404 }) : json(found);
    }
    if (url === `${issuer}/oauth2/introspect`) {
      const token = new URLSearchParams(String(init?.body)).get('token') ?? '';
      this.introspections.push(token);
      if (this.introspectionFails) throw new TypeError('fetch failed');
      if (this.introspectionStatus !== 200)
        return new Response('no', {
          status: this.introspectionStatus,
          headers: this.introspectionHeaders,
        });
      return json(
        typeof this.introspection === 'function' ? this.introspection(token) : this.introspection,
      );
    }
    return new Response('not found', { status: 404 });
  };
}

export function publicKeyOf(pem: string): JsonWebKey {
  return createPublicKey(pem).export({ format: 'jwk' });
}

function json(body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json', ...headers },
  });
}
