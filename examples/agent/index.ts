/**
 * A triage agent: it reads a user's Jira issues, and comments on them only while it needs to.
 * It shows the parts of `@subactid/client` an agent uses: the exchange, refresh callbacks, narrowing
 * a task mid-way, a grant store that survives a restart, and what to do with each kind of error.
 *
 * Configuration, all environment variables:
 *   SUBACTID_ISSUER          the control plane's issuer, exactly as it is configured there
 *                            (`SubactId:Issuer`); http://subactid:5100 for the quickstart
 *   SUBACTID_ALLOW_INSECURE_HTTP  `true` to accept a plain http issuer that is not on a loopback
 *                            host, as the quickstart's is. Never against a real control plane
 *   SUBACTID_AGENT_ID        the agent's registered id
 *   SUBACTID_AGENT_KID       the kid of its key in its registered JWKS
 *   SUBACTID_AGENT_KEY_FILE  path to its PKCS#8 private key (PEM): RSA, or EC on P-256
 *   SUBACTID_AGENT_ALG       the client's `algorithm`: RS256 (the default) or PS256 for an RSA
 *                            key; ES256, the only choice, for an EC key. It must be the `alg`
 *                            the key was registered with, so registration.ts reads it too
 *   SUBACTID_SUBJECT_TOKEN   the user's access token, for a new task
 *   SUBACTID_TASK_ID         a task to pick up again instead of starting one
 *   GRANT_DIR                where task grants are kept; ./grants by default
 *   JIRA_AUDIENCE            the audience the task is for; https://jira.internal by default
 *   JIRA_URL                 where that tool server listens; http://127.0.0.1:4000 by default,
 *                            which is examples/tool-server
 *
 * The issuer is compared with the one in the control plane's discovery document, and every
 * endpoint the client calls comes from that document, so this host has to reach the control
 * plane by that name. For the quickstart, whose issuer is http://subactid:5100, add
 * `127.0.0.1 subactid keycloak` to /etc/hosts.
 *
 * The agent has to be registered first (`POST /admin/agents`, spec section 2) with this key's
 * public half, `https://jira.internal` among its audiences and the two scopes below.
 * `pnpm registration` in this directory prints that request's body. The root README walks
 * through the whole run.
 */
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { signingKey } from './algorithm.js';
import {
  InvalidScopeError,
  isRetryable,
  isTerminal,
  SubactIdClient,
  type StoredTaskGrant,
  type TaskGrantStore,
  type TaskSession,
} from '@subactid/client';

const env = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set.`);
  return value;
};
// What the task is for, and where to call it: the audience is a name, not an address.
const audience = process.env['JIRA_AUDIENCE'] ?? 'https://jira.internal';
const jira = process.env['JIRA_URL'] ?? 'http://127.0.0.1:4000';

/** Task grants as files, one per task. A grant is a credential, so the files are owner-only. */
class FileGrantStore implements TaskGrantStore {
  constructor(private readonly dir: string) {}

  async save(record: StoredTaskGrant): Promise<void> {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    await writeFile(this.path(record.taskId), JSON.stringify(record), { mode: 0o600 });
  }

  async load(taskId: string): Promise<StoredTaskGrant | undefined> {
    try {
      return JSON.parse(await readFile(this.path(taskId), 'utf8')) as StoredTaskGrant;
    } catch {
      return undefined;
    }
  }

  async remove(taskId: string): Promise<void> {
    await rm(this.path(taskId), { force: true });
  }

  private path(taskId: string): string {
    return join(this.dir, `${encodeURIComponent(taskId)}.json`);
  }
}

const privateKey = readFileSync(env('SUBACTID_AGENT_KEY_FILE'), 'utf8');

const client = new SubactIdClient({
  issuer: env('SUBACTID_ISSUER'),
  // The quickstart's issuer is plain http on a name that is not loopback; say so to use it.
  allowInsecureHttp: process.env['SUBACTID_ALLOW_INSECURE_HTTP'] === 'true',
  agentId: env('SUBACTID_AGENT_ID'),
  kid: env('SUBACTID_AGENT_KID'),
  privateKey,
  algorithm: signingKey(privateKey).algorithm,
  instance: process.env['HOSTNAME'] ?? 'local',
  grantStore: new FileGrantStore(process.env['GRANT_DIR'] ?? './grants'),
  onRefresh: (session, token) =>
    console.log(`${session.taskId}: next token lives ${token.expires_in}s`),
  onRefreshError: (session, error) => console.error(`${session.taskId}: ${String(error)}`),
});

const session = await start();

const response = await fetch(`${jira}/issues?q=login`, {
  headers: { authorization: `Bearer ${await session.accessToken()}` },
});
console.log(`search answered ${response.status}`);

// Nothing here needs a comment. Give that scope up for the rest of the task.
await session.refresh('jira:read');

session.stop();

/** Picks up the task named by SUBACTID_TASK_ID if there is one, or starts a new one. */
async function start(): Promise<TaskSession> {
  const taskId = process.env['SUBACTID_TASK_ID'];
  if (taskId) {
    const session = await client.resume(taskId);
    if (session) {
      return session; // still alive, scope and expiry intact
    }
    console.log(`task ${taskId} is gone; starting a new one`);
  }

  try {
    return await client.exchange({
      subjectToken: env('SUBACTID_SUBJECT_TOKEN'),
      resource: audience,
      scope: 'jira:read jira:comment',
    });
  } catch (error) {
    if (error instanceof InvalidScopeError) {
      // The intersection was empty. Asking again will not help.
    } else if (isRetryable(error)) {
      // The control plane could not answer, asked to slow down, or could not be reached.
    } else if (isTerminal(error)) {
      // The control plane will not act for this agent or this human, or the token is refused.
    }
    throw error;
  }
}
