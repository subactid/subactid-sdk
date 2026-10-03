/**
 * The one choice `index.ts` and `registration.ts` have to agree on: which JWS algorithm the
 * agent signs its assertions with. The client's `algorithm` option signs with it, and the
 * registration's JWKS names it as the key's `alg`, so both take it from here.
 *
 * It follows the key: an EC P-256 key signs with ES256, and an RSA key with RS256, or PS256 when
 * SUBACTID_AGENT_ALG says so. SUBACTID_AGENT_ALG may be left unset; set to anything the key
 * cannot sign with, it is refused rather than ignored.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';
import type { AssertionAlgorithm } from '@subactid/client';

/** The algorithm `key` (a PEM private or public key) signs with, and its public half. */
export function signingKey(pem: string): { algorithm: AssertionAlgorithm; publicKey: KeyObject } {
  // A private key yields its public half; `export` then carries public members only.
  const publicKey = createPublicKey(pem);
  const asked = process.env['SUBACTID_AGENT_ALG'] || undefined;
  let algorithm: AssertionAlgorithm;
  if (publicKey.asymmetricKeyType === 'rsa') {
    algorithm =
      asked === undefined || asked === 'RS256'
        ? 'RS256'
        : asked === 'PS256'
          ? 'PS256'
          : fail(asked, 'an RSA key signs with RS256 or PS256');
  } else if (
    publicKey.asymmetricKeyType === 'ec' &&
    publicKey.asymmetricKeyDetails?.namedCurve === 'prime256v1'
  ) {
    algorithm =
      asked === undefined || asked === 'ES256'
        ? 'ES256'
        : fail(asked, 'an EC P-256 key signs with ES256');
  } else {
    throw new Error('The agent key must be RSA (RS256 or PS256) or EC P-256 (ES256).');
  }
  return { algorithm, publicKey };
}

function fail(asked: string, why: string): never {
  throw new Error(`SUBACTID_AGENT_ALG is ${asked}, but ${why}.`);
}
