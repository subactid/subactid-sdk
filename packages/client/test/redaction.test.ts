import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AssertionSigner } from '../src/assertion.js';
import { SubactIdClient } from '../src/client.js';
import { MemoryTaskGrantStore } from '../src/store.js';
import { FakeControlPlane, issuer } from './fake-control-plane.js';
import { rsaPem } from './keys.js';

const start = Date.UTC(2026, 8, 11, 12, 0, 0);

/** Every way an object commonly ends up in a log line. */
function renderings(value: unknown): string[] {
  const out = [
    inspect(value),
    inspect(value, { showHidden: true, depth: Infinity, getters: true }),
    String(value),
  ];
  try {
    out.push(JSON.stringify(value));
  } catch (error) {
    // A throw is no leak, but the message is checked too.
    out.push(String(error));
  }
  return out;
}

function expectNoneContain(value: unknown, secrets: string[]): void {
  for (const text of renderings(value)) {
    for (const secret of secrets) {
      expect(text).not.toContain(secret);
    }
  }
}

const pemBody = rsaPem.split('\n')[1] as string;

describe('credentials stay out of logs (invariant 2)', () => {
  let plane: FakeControlPlane;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function client(store = new MemoryTaskGrantStore()): SubactIdClient {
    return new SubactIdClient({
      issuer,
      agentId: 'jira-triage',
      kid: 'k1',
      privateKey: rsaPem,
      fetch: plane.fetch,
      grantStore: store,
    });
  }

  it('a session, running or stopped, shows neither its token nor its grant', async () => {
    const store = new MemoryTaskGrantStore();
    const session = await client(store).exchange({
      subjectToken: 'user-token',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const token = await session.accessToken();
    const grant = (await store.load(session.taskId))?.grant as string;
    expect(grant).toBeTruthy();

    expectNoneContain(session, [token, grant]);
    session.stop();
    expectNoneContain(session, [token, grant]);
  });

  it('a session serialises to what it is, with a refresh timer pending', async () => {
    const session = await client().exchange({
      subjectToken: 'user-token',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    expect(JSON.parse(JSON.stringify(session))).toEqual({
      taskId: session.taskId,
      resource: 'https://jira.internal',
      scope: 'jira:read',
      taskExpiresAt: session.taskExpiresAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      isEnded: false,
    });
    session.stop();
  });

  it('a client shows neither its private key nor the grants in its store, before and after signing', async () => {
    const store = new MemoryTaskGrantStore();
    const c = client(store);
    expectNoneContain(c, [pemBody]);

    const session = await c.exchange({
      subjectToken: 'user-token',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const grant = (await store.load(session.taskId))?.grant as string;

    expectNoneContain(c, [pemBody, grant]);
    expectNoneContain(store, [grant]);
    session.stop();
  });

  it('a signer drops the PEM once the key is imported, and still signs', async () => {
    const signer = new AssertionSigner({ agentId: 'jira-triage', kid: 'k1', privateKey: rsaPem });
    expectNoneContain(signer, [pemBody]);

    const first = await signer.sign(issuer);
    const second = await signer.sign(issuer);

    expect(first.split('.')).toHaveLength(3);
    expect(second).not.toBe(first);
    expectNoneContain(signer, [pemBody]);
  });
});
