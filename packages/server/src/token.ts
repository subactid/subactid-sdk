import { base64UrlDecode, decodeJson, utf8 } from './base64url.js';
import { SubactIdAuthError } from './errors.js';
import type { JwksCache } from './jwks.js';

/** The `act` claim: who is acting, nested from the outermost actor inward. */
export interface Actor {
  sub: string;
  depth: number;
  instance?: string;
  act?: Actor;
}

/** A verified task token's claims, the ones a tool server acts on. */
export interface TaskToken {
  /** The human the action is taken on behalf of. Never an agent. */
  sub: string;
  /** The agent, when one is acting; absent when the human called directly. */
  act?: Actor;
  /** Scopes the token carries. */
  scopes: string[];
  audience: string;
  jti: string;
  /** The task, when the token belongs to one. */
  taskId?: string;
  /** Seconds since the epoch. */
  exp: number;
  /** Every claim, for anything above not covered. */
  claims: Record<string, unknown>;
  /**
   * The token itself, for introspection. A credential: never log it. Non-enumerable, so
   * serialising or spreading these claims leaves it out.
   */
  readonly token: string;
}

export interface VerifyOptions {
  issuer: string;
  audience: string;
  keys: JwksCache;
  now: () => number;
  /** Clock skew tolerated on `exp`, `nbf` and `iat`, in seconds. */
  clockSkewSeconds: number;
}

/**
 * Step 2 of the tool-server contract, and the invariant behind step 5: signature, `typ`, no
 * `crit`, `iss`, `aud`, `exp`, then the shape of `sub` and `act`. A token whose `sub` is an agent is
 * refused outright; the agent is the actor, never the subject. Whether an actor is required
 * at all, and how deep its chain may go, is a policy question and belongs to the caller.
 */
export async function verifyTaskToken(token: string, options: VerifyOptions): Promise<TaskToken> {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new SubactIdAuthError(401, 'malformed_token', 'The token is not a compact JWS.');
  }
  const [encodedHeader, encodedClaims, encodedSignature] = parts as [string, string, string];
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = asObject(decodeJson(encodedHeader));
    claims = asObject(decodeJson(encodedClaims));
  } catch {
    throw new SubactIdAuthError(401, 'malformed_token', 'The token is not a compact JWS.');
  }
  if (header['alg'] !== 'ES256') {
    throw new SubactIdAuthError(
      401,
      'unsupported_algorithm',
      'The token is not signed with ES256.',
    );
  }
  // RFC 9068: an access token says so. A client assertion or an ID token is not one, whoever signed it.
  if (header['typ'] !== 'at+jwt') {
    throw new SubactIdAuthError(401, 'wrong_type', 'The token is not an access token.');
  }
  // RFC 7515 section 4.1.11: a verifier that does not understand an extension named in `crit`
  // must refuse the token. None is understood here, and the control plane never sets one, so any
  // `crit` at all — an empty one included — is a token this verifier cannot honour.
  if ('crit' in header) {
    throw new SubactIdAuthError(
      401,
      'malformed_token',
      'The token names a critical header extension this verifier does not understand.',
    );
  }
  if (typeof header['kid'] !== 'string') {
    throw new SubactIdAuthError(401, 'unknown_key', 'The token names no signing key.');
  }

  const key = await options.keys.get(header['kid']);
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = base64UrlDecode(encodedSignature);
  } catch {
    throw new SubactIdAuthError(401, 'malformed_token', 'The token is not a compact JWS.');
  }
  const valid =
    signature.length === 64 &&
    (await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature,
      utf8(`${encodedHeader}.${encodedClaims}`),
    ));
  if (!valid) {
    throw new SubactIdAuthError(401, 'invalid_signature', 'The token signature does not verify.');
  }

  if (claims['iss'] !== options.issuer) {
    throw new SubactIdAuthError(401, 'wrong_issuer', 'The token is not from this control plane.');
  }
  const aud = claims['aud'];
  const audiences = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud : [];
  if (!audiences.includes(options.audience)) {
    throw new SubactIdAuthError(401, 'wrong_audience', 'The token is not for this server.');
  }
  const nowSeconds = Math.floor(options.now() / 1000);
  const exp = claims['exp'];
  if (typeof exp !== 'number' || !(exp + options.clockSkewSeconds > nowSeconds)) {
    throw new SubactIdAuthError(401, 'expired', 'The token has expired.');
  }
  for (const name of ['nbf', 'iat'] as const) {
    const value = claims[name];
    if (
      value !== undefined &&
      (typeof value !== 'number' || value - options.clockSkewSeconds > nowSeconds)
    ) {
      throw new SubactIdAuthError(401, 'not_yet_valid', 'The token is not valid yet.');
    }
  }
  const sub = claims['sub'];
  if (typeof sub !== 'string' || sub.length === 0) {
    throw new SubactIdAuthError(401, 'no_subject', 'The token names no subject.');
  }
  // Case-insensitively: the check is worth nothing if `Agent:` walks past it.
  if (/^agent:/i.test(sub)) {
    throw new SubactIdAuthError(
      401,
      'subject_is_agent',
      'The token puts an agent in sub; the agent is the actor, never the subject.',
    );
  }
  const jti = claims['jti'];
  if (typeof jti !== 'string' || jti.length === 0) {
    throw new SubactIdAuthError(401, 'malformed_token', 'The token has no jti.');
  }

  const act = claims['act'] === undefined ? undefined : readActor(claims['act']);

  const scope = claims['scope'];
  const task = claims['task'];
  const taskId =
    typeof task === 'object' &&
    task !== null &&
    typeof (task as Record<string, unknown>)['id'] === 'string'
      ? ((task as Record<string, unknown>)['id'] as string)
      : undefined;
  const verified = {
    sub,
    ...(act === undefined ? {} : { act }),
    scopes: typeof scope === 'string' ? scope.split(' ').filter(Boolean) : [],
    audience: options.audience,
    jti,
    ...(taskId === undefined ? {} : { taskId }),
    exp,
    claims,
  } as TaskToken;
  // The token rides along for introspection only. As a non-enumerable getter it is left out of
  // `JSON.stringify`, spreads and `util.inspect`, so a request logger that dumps the claims
  // does not write a credential.
  Object.defineProperty(verified, 'token', { get: () => token, enumerable: false });
  return verified;
}

function readActor(value: unknown): Actor {
  const bad = (): never => {
    throw new SubactIdAuthError(401, 'malformed_token', 'The act claim is malformed.');
  };
  if (typeof value !== 'object' || value === null) return bad();
  const record = value as Record<string, unknown>;
  const sub = record['sub'];
  const depth = record['depth'];
  if (
    typeof sub !== 'string' ||
    !sub.startsWith('agent:') ||
    typeof depth !== 'number' ||
    !Number.isInteger(depth) ||
    depth < 1
  ) {
    return bad();
  }
  const actor: Actor = { sub, depth };
  if (typeof record['instance'] === 'string') actor.instance = record['instance'];
  if (record['act'] !== undefined) {
    const inner = readActor(record['act']);
    if (inner.depth !== depth - 1) return bad();
    actor.act = inner;
  } else if (depth !== 1) {
    return bad();
  }
  return actor;
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('not an object');
  }
  return value as Record<string, unknown>;
}
