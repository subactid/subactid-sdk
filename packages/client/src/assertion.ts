import { base64UrlDecode, base64UrlEncode, utf8 } from './encoding.js';
import { SubactIdError } from './errors.js';

/** The JWS algorithms an agent may sign its assertions with; the three the control plane accepts. */
export type AssertionAlgorithm = 'RS256' | 'PS256' | 'ES256';

/** An agent's signing key: a PKCS#8 PEM, or a WebCrypto key already imported for signing. */
export type AgentPrivateKey = string | CryptoKey;

export interface AssertionSignerOptions {
  /** The agent's registered id; goes in `iss` and `sub`. */
  agentId: string;
  /** The `kid` of the key in the agent's published JWKS. */
  kid: string;
  /** The private key matching that `kid`. */
  privateKey: AgentPrivateKey;
  /**
   * Inferred from the key when omitted: RS256 for an RSA key, ES256 for an EC P-256 key (what
   * `subactid agent init` writes). Set it to sign an RSA key with PS256. It must be the `alg` the
   * key was registered with.
   */
  algorithm?: AssertionAlgorithm;
  /**
   * Which copy of this agent is running: a pod name, a container id, whatever identifies one
   * instance to you. It is copied into the task token's `act.instance`, so the ledger and every
   * tool server can tell one instance from another. The agent's own claim about itself, signed
   * by its key and never checked against anything; at most 128 characters.
   */
  instance?: string;
  /** Milliseconds since the epoch; defaults to the system clock. */
  now?: () => number;
  /** Lifetime of each assertion in seconds; at most the 300 the control plane accepts. Defaults to 60. */
  lifetimeSeconds?: number;
}

const maxLifetimeSeconds = 300;
const maxInstanceLength = 128;

/**
 * Mints the `private_key_jwt` assertions (RFC 7523) that authenticate an agent to the control
 * plane: a fresh, short-lived, single-use JWT per request, signed with the agent's own key. The
 * key never leaves this process; the control plane only ever sees the public half via the JWKS
 * the agent publishes.
 */
export class AssertionSigner {
  private readonly agentId: string;
  private readonly kid: string;
  private readonly algorithm: AssertionAlgorithm;
  private readonly instance: string | undefined;
  private readonly now: () => number;
  private readonly lifetimeSeconds: number;
  #key: Promise<CryptoKey> | undefined;
  /** The key as given, until it is imported; a PEM is dropped then, and only the non-extractable `CryptoKey` kept. */
  #privateKey: AgentPrivateKey | undefined;

  constructor(options: AssertionSignerOptions) {
    if (!options.agentId) throw new SubactIdError('agentId is required.');
    if (!options.kid) throw new SubactIdError('kid is required.');
    if (!options.privateKey) throw new SubactIdError('privateKey is required.');
    const lifetime = options.lifetimeSeconds ?? 60;
    // Whole seconds: `exp` is a NumericDate the control plane reads as an integer.
    if (!(Number.isInteger(lifetime) && lifetime >= 1 && lifetime <= maxLifetimeSeconds)) {
      throw new SubactIdError(
        `lifetimeSeconds must be a whole number between 1 and ${maxLifetimeSeconds}.`,
      );
    }
    this.agentId = options.agentId;
    this.kid = options.kid;
    this.#privateKey = options.privateKey;
    if (options.instance !== undefined && options.instance.length > maxInstanceLength) {
      throw new SubactIdError(`instance must be at most ${maxInstanceLength} characters.`);
    }
    this.algorithm = options.algorithm ?? inferAlgorithm(options.privateKey) ?? 'RS256';
    // A blank instance — an unset `POD_NAME` read straight into the options — says nothing, so
    // it is not asserted. The control plane drops it too; this keeps the assertion honest.
    this.instance = options.instance?.trim() === '' ? undefined : options.instance;
    this.now = options.now ?? Date.now;
    this.lifetimeSeconds = lifetime;
  }

  /** A new assertion for `audience`: the control plane's issuer, exactly as its discovery document publishes it. */
  async sign(audience: string): Promise<string> {
    const key = await this.importedKey();
    const nowSeconds = Math.floor(this.now() / 1000);
    const header = { alg: this.algorithm, typ: 'JWT', kid: this.kid };
    const claims = {
      iss: this.agentId,
      sub: this.agentId,
      aud: audience,
      iat: nowSeconds,
      exp: nowSeconds + this.lifetimeSeconds,
      jti: crypto.randomUUID(),
      ...(this.instance === undefined ? {} : { instance: this.instance }),
    };
    const signingInput = `${base64UrlEncode(utf8(JSON.stringify(header)))}.${base64UrlEncode(utf8(JSON.stringify(claims)))}`;
    let signature: ArrayBuffer;
    try {
      signature = await crypto.subtle.sign(signParams(this.algorithm), key, utf8(signingInput));
    } catch (cause) {
      throw new SubactIdError(
        `The private key cannot sign ${this.algorithm}; check the key type and its usages.`,
        { cause },
      );
    }
    return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
  }

  private importedKey(): Promise<CryptoKey> {
    if (this.#key === undefined) {
      const privateKey = this.#privateKey as AgentPrivateKey;
      this.#privateKey = undefined;
      this.#key = importPrivateKey(privateKey, this.algorithm);
    }
    return this.#key;
  }
}

/**
 * The algorithm a key signs with, read from the key itself: a `CryptoKey`'s own algorithm, or
 * the algorithm identifier of a PKCS#8 PEM. `undefined` when the key says nothing this client
 * recognises; importing it then fails with the usual message.
 */
function inferAlgorithm(key: AgentPrivateKey): AssertionAlgorithm | undefined {
  if (typeof key !== 'string') {
    const algorithm = key.algorithm as { name?: string; namedCurve?: string };
    if (algorithm.name === 'RSASSA-PKCS1-v1_5') return 'RS256';
    if (algorithm.name === 'RSA-PSS') return 'PS256';
    if (algorithm.name === 'ECDSA' && algorithm.namedCurve === 'P-256') return 'ES256';
    return undefined;
  }
  const der = pkcs8Der(key);
  if (der === undefined) return undefined;
  // PrivateKeyInfo ::= SEQUENCE { version INTEGER, privateKeyAlgorithm AlgorithmIdentifier, ... }
  // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
  const outer = derElement(der, 0, 0x30);
  const version = outer && derElement(der, outer.contentStart, 0x02);
  const identifier = version && derElement(der, version.end, 0x30);
  const oid = identifier && derElement(der, identifier.contentStart, 0x06);
  if (oid === undefined) return undefined;
  const value = toHex(der.subarray(oid.contentStart, oid.end));
  // A key carrying the RSA-PSS identifier is not one WebCrypto imports, so it is not read as PS256:
  // PS256 signs with an ordinary RSA key, and is asked for by name.
  if (value === rsaEncryption) return 'RS256';
  if (value === ecPublicKey) {
    const curve = derElement(der, oid.end, 0x06);
    return curve !== undefined && toHex(der.subarray(curve.contentStart, curve.end)) === prime256v1
      ? 'ES256'
      : undefined;
  }
  return undefined;
}

// Object identifiers, as the hex of their DER content.
const rsaEncryption = '2a864886f70d010101'; // 1.2.840.113549.1.1.1
const ecPublicKey = '2a8648ce3d0201'; // 1.2.840.10045.2.1
const prime256v1 = '2a8648ce3d030107'; // 1.2.840.10045.3.1.7

const pemBegin = '-----BEGIN PRIVATE KEY-----';
const pemEnd = '-----END PRIVATE KEY-----';

/** The DER inside a PKCS#8 PEM, or `undefined` when it is not one. */
function pkcs8Der(pem: string): Uint8Array<ArrayBuffer> | undefined {
  // The markers are found by position, not by a regular expression: a lazy match for the body
  // between them rescans from every later `BEGIN` when there is no `END`, which is quadratic in
  // the length of the string (CodeQL js/polynomial-redos).
  const begin = pem.indexOf(pemBegin);
  if (begin === -1) return undefined;
  const bodyStart = begin + pemBegin.length;
  const end = pem.indexOf(pemEnd, bodyStart);
  if (end === -1) return undefined;
  const body = pem.slice(bodyStart, end).replace(/\s+/g, '');
  if (body === '') return undefined;
  try {
    return base64UrlDecode(body.replace(/\+/g, '-').replace(/\//g, '_'));
  } catch {
    return undefined;
  }
}

/** One DER element with tag `tag` at `offset`: where its content starts and where it ends. */
function derElement(
  der: Uint8Array,
  offset: number,
  tag: number,
): { contentStart: number; end: number } | undefined {
  if (der[offset] !== tag) return undefined;
  const first = der[offset + 1];
  if (first === undefined) return undefined;
  let length = first;
  let contentStart = offset + 2;
  if (first & 0x80) {
    const octets = first & 0x7f;
    if (octets < 1 || octets > 3) return undefined;
    length = 0;
    for (let i = 0; i < octets; i++) {
      const byte = der[offset + 2 + i];
      if (byte === undefined) return undefined;
      length = length * 256 + byte;
    }
    contentStart += octets;
  }
  const end = contentStart + length;
  return end <= der.length ? { contentStart, end } : undefined;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function signParams(
  algorithm: AssertionAlgorithm,
): AlgorithmIdentifier | EcdsaParams | RsaPssParams {
  switch (algorithm) {
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256' };
    // PSS needs a salt the length of the digest, which is what RFC 7518 specifies for PS256.
    case 'PS256':
      return { name: 'RSA-PSS', saltLength: 32 };
    default:
      return { name: 'RSASSA-PKCS1-v1_5' };
  }
}

function importParams(algorithm: AssertionAlgorithm): RsaHashedImportParams | EcKeyImportParams {
  switch (algorithm) {
    case 'ES256':
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'PS256':
      return { name: 'RSA-PSS', hash: 'SHA-256' };
    default:
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  }
}

async function importPrivateKey(
  key: AgentPrivateKey,
  algorithm: AssertionAlgorithm,
): Promise<CryptoKey> {
  if (typeof key !== 'string') {
    return key;
  }
  const der = pkcs8Der(key);
  if (der === undefined) {
    throw new SubactIdError(
      'privateKey must be a PKCS#8 PEM ("BEGIN PRIVATE KEY") or a CryptoKey.',
    );
  }
  try {
    return await crypto.subtle.importKey('pkcs8', der, importParams(algorithm), false, ['sign']);
  } catch (cause) {
    throw new SubactIdError(`privateKey could not be imported for ${algorithm}.`, { cause });
  }
}
