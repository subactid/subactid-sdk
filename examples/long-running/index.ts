/**
 * A task that outlives its tokens. The agent exchanges the user's token once, then calls a tool
 * server every few seconds for half an hour on five-minute tokens. `@subactid/client` refreshes at
 * 60% of each token's life, so the tool server never sees an expired token and never answers 401.
 *
 * The tool server here is a stand-in: it only checks that a bearer token is present and unexpired.
 * A real one validates the signature and the claims; see `@subactid/server`.
 *
 * Configuration, all environment variables:
 *   SUBACTID_ISSUER          the control plane's issuer, exactly as it is configured there
 *                            (`SubactId:Issuer`); http://subactid:5100 for the quickstart, with
 *                            `127.0.0.1 subactid keycloak` in /etc/hosts
 *   SUBACTID_ALLOW_INSECURE_HTTP  `true` to accept a plain http issuer that is not on a loopback
 *                            host, as the quickstart's is. Never against a real control plane
 *   SUBACTID_AGENT_ID        the agent's registered id
 *   SUBACTID_AGENT_KID       the kid of its key in its registered JWKS
 *   SUBACTID_AGENT_KEY_FILE  path to its PKCS#8 private key (PEM): RSA, or EC on P-256
 *   SUBACTID_AGENT_ALG       RS256 (the default) or PS256 for an RSA key; ES256, the only
 *                            choice, for an EC key. It must be the `alg` the key was registered
 *                            with, as in examples/agent
 *   SUBACTID_SUBJECT_TOKEN   the user's access token from the identity provider
 *   SUBACTID_RESOURCE        the audience, e.g. https://jira.internal
 *   SUBACTID_SCOPE           the scopes, e.g. "jira:read jira:comment"
 *   DURATION_MINUTES     how long to run; 30 by default
 *   CALL_INTERVAL_SECONDS how often to call the tool; 10 by default
 *
 * The agent has to be registered first, with its key's public half and the resource among its
 * audiences; examples/agent/registration.ts prints such a registration. The root README walks
 * through a run against the quickstart.
 *
 * Exit codes: 0 all tool calls answered 200; 1 the tool answered 401 at least once; 2 a setting
 * is missing or wrong; 3 the exchange was refused and retrying it cannot help; 4 the exchange was refused
 * for a reason that may pass, or the control plane could not be reached, so a supervisor
 * restarting this is right to.
 */
import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import {
  AccessDeniedError,
  type AssertionAlgorithm,
  decodeJwtPayload,
  isRetryable,
  OAuthError,
  SubactIdClient,
  type TaskSession,
  TransportError,
} from '@subactid/client';

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`${name} is not set.`);
    process.exit(2);
  }
  return value;
}

/**
 * The algorithm the key signs with, as examples/agent chooses it: ES256 for an EC P-256 key, and
 * RS256 for an RSA key, or PS256 when SUBACTID_AGENT_ALG says so. Anything else is a setting this
 * example cannot run with, so it exits 2 before any request is sent.
 */
function signingAlgorithm(pem: string): AssertionAlgorithm {
  const asked = process.env['SUBACTID_AGENT_ALG'] || undefined;
  let key;
  try {
    key = createPublicKey(pem);
  } catch {
    return settingError('SUBACTID_AGENT_KEY_FILE is not a PEM key.');
  }
  if (key.asymmetricKeyType === 'rsa' && (asked === undefined || asked === 'RS256')) return 'RS256';
  if (key.asymmetricKeyType === 'rsa' && asked === 'PS256') return 'PS256';
  if (
    key.asymmetricKeyType === 'ec' &&
    key.asymmetricKeyDetails?.namedCurve === 'prime256v1' &&
    (asked === undefined || asked === 'ES256')
  ) {
    return 'ES256';
  }
  return settingError(
    'The agent key must be RSA (RS256 or PS256) or EC P-256 (ES256), and SUBACTID_AGENT_ALG must match it.',
  );
}

function settingError(message: string): never {
  console.error(message);
  process.exit(2);
}

const durationMinutes = Number(process.env['DURATION_MINUTES'] ?? '30');
const intervalSeconds = Number(process.env['CALL_INTERVAL_SECONDS'] ?? '10');

// The stand-in tool server: 401 for a missing or expired bearer token, 200 otherwise.
const tool = createServer((request, response) => {
  const header = request.headers.authorization ?? '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
  let status = 401;
  try {
    const exp = Number(decodeJwtPayload(token)['exp']);
    if (exp * 1000 > Date.now()) status = 200;
  } catch {
    status = 401;
  }
  response.writeHead(status).end();
});
await new Promise<void>((resolve) => tool.listen(0, '127.0.0.1', resolve));
const address = tool.address();
const toolUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}/`;

const privateKey = readFileSync(required('SUBACTID_AGENT_KEY_FILE'), 'utf8');
const algorithm = signingAlgorithm(privateKey);

const client = new SubactIdClient({
  issuer: required('SUBACTID_ISSUER'),
  // The quickstart's issuer is plain http on a name that is not loopback; say so to use it.
  allowInsecureHttp: process.env['SUBACTID_ALLOW_INSECURE_HTTP'] === 'true',
  agentId: required('SUBACTID_AGENT_ID'),
  kid: required('SUBACTID_AGENT_KID'),
  privateKey,
  algorithm,
  onRefresh: (session, token) =>
    console.log(`${stamp()} refreshed ${session.taskId}: next token lives ${token.expires_in}s`),
  onRefreshError: (session, error) =>
    console.error(`${stamp()} refresh of ${session.taskId} failed: ${String(error)}`),
});

// The exchange is refused for the human as well as for this agent or this request: the subject
// token verifying says who it is for, not that the control plane still acts for them. Nothing is
// created either way, so there is nothing to clean up — only something to say clearly.
let session: TaskSession;
try {
  session = await client.exchange({
    subjectToken: required('SUBACTID_SUBJECT_TOKEN'),
    resource: required('SUBACTID_RESOURCE'),
    scope: required('SUBACTID_SCOPE'),
  });
} catch (error) {
  // A control plane that could not be reached is worth trying again, exactly like a refusal
  // that may pass, so it leaves by the same door. Letting it fall out of here instead would
  // exit 1 — the code the table above gives to the tool server answering 401 — and tell a
  // supervisor the opposite of what happened. Anything else is this example being wrong rather
  // than the control plane, so it is rethrown with its stack, once the socket is closed.
  if (!(error instanceof OAuthError) && !(error instanceof TransportError)) {
    tool.close();
    throw error;
  }
  console.error(
    error instanceof OAuthError
      ? `${stamp()} the exchange was refused: ${error.error} — ${error.errorDescription}`
      : `${stamp()} the control plane could not be reached: ${error.message}`,
  );
  if (error instanceof AccessDeniedError) {
    console.error(
      'The control plane will not act for the human this subject token is for: blocked, disabled or gone. A fresh token for the same person would be refused the same way.',
    );
  }
  tool.close();
  process.exit(isRetryable(error) ? 4 : 3);
}
console.log(
  `${stamp()} task ${session.taskId} runs until ${session.taskExpiresAt.toISOString()}; first token lives until ${session.expiresAt.toISOString()}`,
);

const statuses = new Map<number, number>();
const end = Date.now() + durationMinutes * 60_000;
while (Date.now() < end) {
  const response = await fetch(toolUrl, {
    headers: { authorization: `Bearer ${await session.accessToken()}` },
  });
  statuses.set(response.status, (statuses.get(response.status) ?? 0) + 1);
  if (response.status !== 200) {
    console.error(`${stamp()} tool answered ${response.status}`);
  }
  await new Promise((resolve) => setTimeout(resolve, intervalSeconds * 1000));
}

session.stop();
tool.close();
const summary = [...statuses.entries()].map(([status, count]) => `${status}: ${count}`).join(', ');
console.log(`${stamp()} done after ${durationMinutes} minutes; tool answers: ${summary}`);
process.exit(statuses.get(401) ? 1 : 0);

function stamp(): string {
  return new Date().toISOString();
}
