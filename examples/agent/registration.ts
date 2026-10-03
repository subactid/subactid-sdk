/**
 * Prints the body of `POST /admin/agents` (spec section 2) that registers this agent for the
 * example next to it, with the public half of its key inline as `jwks`. The control plane then
 * serves that key itself and fetches nothing, so the agent needs no https endpoint of its own.
 * Only the public members are printed; the private key never leaves this process.
 *
 *   SUBACTID_AGENT_ID        the agent's id
 *   SUBACTID_AGENT_KID       the kid to register the key under
 *   SUBACTID_AGENT_KEY_FILE  path to its PKCS#8 private key (PEM): RSA, or EC on P-256
 *   SUBACTID_AGENT_ALG       RS256 (the default) or PS256 for an RSA key; ES256, the only
 *                            choice, for an EC key. The key's `alg` in the printed JWKS, and the
 *                            client's `algorithm` in index.ts, which reads the same variable
 *   JIRA_AUDIENCE            the audience it may ask for; https://jira.internal by default
 *
 * For example, against the quickstart:
 *
 *   pnpm --silent registration > agent.json
 *   curl -X POST -H "authorization: Bearer $ADMIN_KEY" -H 'content-type: application/json' \
 *     --data @agent.json http://subactid:5100/admin/agents
 */
import { readFileSync } from 'node:fs';
import { signingKey } from './algorithm.js';

const env = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set.`);
  return value;
};

const { algorithm, publicKey } = signingKey(readFileSync(env('SUBACTID_AGENT_KEY_FILE'), 'utf8'));
const jwk = publicKey.export({ format: 'jwk' });
// Only the public members, named one by one, so nothing else the export carries is printed.
const members =
  jwk.kty === 'EC'
    ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }
    : { kty: jwk.kty, n: jwk.n, e: jwk.e };

console.log(
  JSON.stringify(
    {
      agent_id: env('SUBACTID_AGENT_ID'),
      display_name: 'Example triage agent',
      sponsor_required: true,
      allowed_scopes: ['jira:read', 'jira:comment'],
      allowed_audiences: [process.env['JIRA_AUDIENCE'] ?? 'https://jira.internal'],
      max_delegation_depth: 1,
      jwks: {
        keys: [{ ...members, kid: env('SUBACTID_AGENT_KID'), alg: algorithm, use: 'sig' }],
      },
    },
    null,
    2,
  ),
);
