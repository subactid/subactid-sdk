import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SubactIdClient } from '../src/client.js';
import { base64UrlEncode, utf8 } from '../src/encoding.js';
import { TaskSession } from '../src/session.js';
import {
  AccessDeniedError,
  InvalidClientError,
  InvalidGrantError,
  InvalidScopeError,
  InvalidTargetError,
  isRetryable,
  isTaskOver,
  isTerminal,
  SessionStoppedError,
  SubactIdError,
  SlowDownError,
  TaskEndedError,
  TemporarilyUnavailableError,
  TransportError,
  UnknownOAuthError,
  UnsupportedTokenTypeError,
  taskOverReasons,
  liftableReasons,
  isLiftableReason,
} from '../src/errors.js';
import { MemoryTaskGrantStore, type StoredTaskGrant, type TaskGrantStore } from '../src/store.js';
import { FakeControlPlane, issuer, revocationEndpoint } from './fake-control-plane.js';
import { rsaPem } from './keys.js';

const start = Date.UTC(2026, 8, 11, 12, 0, 0);
const realSetImmediate = globalThis.setImmediate;

/**
 * Lets real work finish: signing an assertion runs off the event loop, which fake timers do not
 * cover, and how long it takes depends on what else the machine is doing. So the tests wait for
 * the work itself rather than for a slice of wall clock. setImmediate is not faked and costs the
 * same on every platform, where a 1 ms setTimeout is rounded up to 15 ms on Windows.
 */
async function tick(): Promise<void> {
  await new Promise<void>((resolve) => realSetImmediate(resolve));
}

/** Waits, in real time, until `done()` holds. Fails the test rather than hanging if it never does. */
async function until(done: () => boolean, what: string): Promise<void> {
  const deadline = performance.now() + 10_000;
  while (!done()) {
    expect(performance.now(), `timed out waiting for ${what}`).toBeLessThan(deadline);
    await tick();
  }
}

/**
 * Waits for whatever the last clock advance set off to land: a refresh signs an assertion with
 * real crypto, so the work takes real time that no amount of fake time covers. Ends as soon as
 * the fake control plane has been quiet for a while, measured in wall-clock milliseconds, so a
 * passing test is not slow.
 */
async function settle(plane: FakeControlPlane): Promise<void> {
  let seen = plane.requests.length;
  let quietSince = performance.now();
  while (performance.now() - quietSince < 20) {
    await tick();
    if (plane.requests.length !== seen) {
      seen = plane.requests.length;
      quietSince = performance.now();
    }
  }
}

/**
 * Advances the fake clock in steps, letting whatever each step sets off land before the next.
 * The step only has to be shorter than the gap between two things the session has scheduled;
 * a test that watches a tighter cycle than that passes its own.
 */
async function run(plane: FakeControlPlane, ms: number, step = 30_000): Promise<void> {
  for (let elapsed = 0; elapsed < ms; elapsed += step) {
    await vi.advanceTimersByTimeAsync(Math.min(step, ms - elapsed));
    await settle(plane);
  }
}

describe('SubactIdClient', () => {
  let plane: FakeControlPlane;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function client(
    extra: Partial<ConstructorParameters<typeof SubactIdClient>[0]> = {},
  ): SubactIdClient {
    return new SubactIdClient({
      issuer,
      agentId: 'jira-triage',
      kid: 'k1',
      privateKey: rsaPem,
      fetch: plane.fetch,
      ...extra,
    });
  }

  it('exchanges with the RFC 8693 form and an assertion addressed to the discovered issuer', async () => {
    const session = await client().exchange({
      subjectToken: 'user-token',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });

    const form = plane.requests[0]?.form;
    expect(Object.fromEntries(form?.entries() ?? [])).toMatchObject({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: 'user-token',
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });
    expect(plane.assertionClaims(0, 'actor_token')).toMatchObject({
      iss: 'jira-triage',
      sub: 'jira-triage',
      aud: issuer,
    });
    expect(session.taskId).toBe('task_1');
    expect(session.scope).toBe('jira:read jira:comment');
    expect(session.resource).toBe('https://jira.internal');
    expect(await session.accessToken()).toMatch(/^token_task_1_/);
    expect(session.expiresAt.getTime()).toBe(start + 300_000);
    session.stop();
  });

  it('fetches discovery once for any number of requests', async () => {
    const c = client();
    const a = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const b = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    expect(plane.discoveryCalls).toBe(1);
    a.stop();
    b.stop();
  });

  it('refreshes at 60% of the token lifetime with the same scope and the same grant', async () => {
    const refreshed: number[] = [];
    const session = await client({ onRefresh: () => refreshed.push(Date.now()) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });
    const first = await session.accessToken();

    await run(plane, 179_000);
    expect(refreshed).toEqual([]);
    await run(plane, 1_000);

    expect(refreshed).toEqual([start + 180_000]);
    const refresh = plane.requests[1]?.form;
    expect(Object.fromEntries(refresh?.entries() ?? [])).toMatchObject({
      grant_type: 'refresh_token',
      refresh_token: 'task_grant_1',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    });
    expect(plane.assertionClaims(1, 'client_assertion')).toMatchObject({ aud: issuer });
    expect(await session.accessToken()).not.toBe(first);
    // The control plane answers a refresh with the grant it was given: it does not rotate.
    expect(session.toStored().grant).toBe('task_grant_1');
    session.stop();
  });

  it(
    'runs thirty minutes on a five-minute token without ever handing out an expired one',
    { timeout: 30_000 },
    async () => {
      plane.taskTtlSeconds = 3600;
      const tokens: string[] = [];
      let refreshed = 0;
      const session = await client({ onRefresh: () => refreshed++ }).exchange({
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read',
      });

      // A caller asking every thirty seconds, for thirty minutes. Each token lives five minutes
      // and is renewed at 60% of that, so a refresh is due every three minutes; the loop waits
      // for the one it has just set off before asking again.
      for (let elapsed = 0; elapsed <= 30 * 60_000; elapsed += 30_000) {
        const token = await session.accessToken();
        expect(session.expiresAt.getTime() - Date.now()).toBeGreaterThanOrEqual(5_000);
        tokens.push(token);
        await vi.advanceTimersByTimeAsync(30_000);
        const due = Math.floor((elapsed + 30_000) / 180_000);
        await until(() => refreshed >= due, `refresh ${due} of the task`);
      }

      expect(refreshed).toBe(10);
      expect(
        plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token'),
      ).toHaveLength(10);
      expect(new Set(tokens).size).toBe(11);
      session.stop();
    },
  );

  it('cuts the last token to the task expiry and ends the session when the task is over', async () => {
    plane.taskTtlSeconds = 400;
    const errors: unknown[] = [];
    const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    await run(plane, 180_000);
    expect(session.expiresAt.getTime()).toBe(start + 400_000);
    expect(session.taskExpiresAt.getTime()).toBe(start + 400_000);

    // The last token lasts until the end of the task; nothing more is asked for, and then the task is over.
    await run(plane, 400_000);
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      1,
    );
    await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(TaskEndedError);
    expect(session.isEnded).toBe(true);
    await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
  });
  it('never refreshes a token that already lasts to the end of its task, and ends in its last seconds', async () => {
    plane.taskTtlSeconds = 300;
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    // The first token covers the whole task: no refresh is ever worth asking for.
    await run(plane, 294_000);
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      0,
    );
    expect(await session.accessToken()).toBeTypeOf('string');

    await run(plane, 2_000);
    await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      0,
    );
    expect(session.isEnded).toBe(true);
  });

  it('counts a last token cut to the whole second before a sub-second task end as lasting the task', async () => {
    // The live timeline: a 60-second task of 30-second tokens, started 400ms into a second. The
    // task ends at +60.4s; its last token's exp, in whole seconds, at +60s. Read as ending before
    // the task, it was refreshed at +50.4s and +54.9s for 10 and 5 seconds, and then the task
    // was reported to onRefreshError as ended while it was simply running out.
    plane.jwtTokens = true;
    plane.tokenTtlSeconds = 30;
    plane.taskTtlSeconds = 60;
    vi.setSystemTime(start + 400);
    const errors: unknown[] = [];
    const refreshed: number[] = [];
    const session = await client({
      onRefresh: () => refreshed.push(Date.now() - start),
      onRefreshError: (_, e) => errors.push(e),
    }).exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' });
    expect(session.taskExpiresAt.getTime()).toBe(start + 60_400);

    // Each refresh is let land before the clock moves on, so when it happened does not depend
    // on how long signing its assertion took.
    await vi.advanceTimersByTimeAsync(17_760);
    await until(() => refreshed.length === 1, 'the first refresh');
    await vi.advanceTimersByTimeAsync(17_904);
    await until(() => refreshed.length === 2, 'the second refresh');
    await run(plane, 40_000, 1_000);

    expect(refreshed).toEqual([18_160, 36_064]);
    expect(session.expiresAt.getTime()).toBe(start + 60_000);
    expect(errors).toEqual([]);
    expect(session.isEnded).toBe(false);
    // As before: asking for a token after the task has run out ends the session then.
    await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
    expect(errors).toHaveLength(1);
  });

  it('does not hand out a token a refresh left with less than the minimum, and ends the task', async () => {
    plane.jwtTokens = true;
    plane.taskTtlSeconds = 60;
    vi.setSystemTime(start + 400);
    const store = new MemoryTaskGrantStore();
    const errors: unknown[] = [];
    const session = await client({
      grantStore: store,
      onRefreshError: (_, e) => errors.push(e),
    }).exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' });

    // 5.2 seconds of the task left, so the refresh is sent and answered, with expires_in 5; its
    // exp at the whole second before the task's end leaves the new token 4.8.
    vi.setSystemTime(start + 55_200);
    const [thrown, alongside] = await Promise.all([
      session.accessToken().catch((e: unknown) => e),
      session.accessToken().catch((e: unknown) => e),
    ]);
    expect(alongside).toBe(thrown);
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      1,
    );
    expect(thrown).toBeInstanceOf(TaskEndedError);
    expect((thrown as Error).message).toBe('The task has expired.');
    expect(errors).toEqual([thrown]);
    expect(session.isEnded).toBe(true);
    expect(await store.load(session.taskId)).toBeUndefined();
  });

  it('does not let an exp past the end of the task stop the refreshes', async () => {
    // An exp written in milliseconds by mistake lies far past the task. Read as lasting the
    // task, it would leave no refresh scheduled; it is not one the control plane issues.
    vi.setSystemTime(start + 400);
    let refreshes = 0;
    const token = (expires_in: number) => ({
      access_token: `x.${base64UrlEncode(utf8(JSON.stringify({ exp: start + 60_000 })))}.y`,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'Bearer',
      expires_in,
      scope: 'jira:read',
      refresh_token: 'g',
      task_id: 'task',
      task_expires_at: new Date(start + 60_400).toISOString(),
    });
    const session = new TaskSession(token(30), 'https://jira.internal', Date.now(), {
      refresh: async () => {
        refreshes++;
        return token(30);
      },
      revoke: async () => undefined,
      store: new MemoryTaskGrantStore(),
      now: () => Date.now(),
    });
    expect(session.expiresAt.getTime()).toBe(start + 30_400);

    await vi.advanceTimersByTimeAsync(20_000);
    expect(refreshes).toBe(1);
    session.stop();
  });

  it('refreshes before handing out a token that is about to expire, even if the timer has not fired', async () => {
    const live = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const first = await live.accessToken();

    // Jump the clock to just before expiry without letting the timer run.
    vi.setSystemTime(start + 299_000);
    const token = await live.accessToken();

    expect(token).not.toBe(first);
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      1,
    );
    live.stop();
  });

  it('only ever narrows scope on refresh and refuses to ask for more', async () => {
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });

    await expect(session.refresh('jira:read jira:admin')).rejects.toThrow(SubactIdError);
    await expect(session.refresh('')).rejects.toThrow(SubactIdError);
    expect(plane.requests).toHaveLength(1);

    const narrowed = await session.refresh('jira:read');
    expect(narrowed.scope).toBe('jira:read');
    expect(session.scope).toBe('jira:read');

    // One-way: this class will not even ask, so a step that dropped a scope cannot quietly take
    // it back later in the session, and no refusal lands in the ledger for trying.
    await expect(session.refresh('jira:read jira:comment')).rejects.toThrow(SubactIdError);

    await run(plane, 180_000);
    expect(plane.requests.at(-1)?.form.get('scope')).toBe('jira:read');
    expect(plane.requests).toHaveLength(3);
    session.stop();
  });

  it('the control plane keeps a narrowed scope on the grant, and a resumed task carries it', async () => {
    const store = new MemoryTaskGrantStore();
    const c = client({ grantStore: store });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });
    await session.refresh('jira:read');
    session.stop();
    expect(plane.task(session.taskId)?.scope).toBe('jira:read');

    // Asked for directly, past the session's own rule, the wider scope is refused at the control plane.
    const { grant } = session.toStored();
    await expect(
      c.refresh(grant, 'https://jira.internal', 'jira:read jira:comment'),
    ).rejects.toBeInstanceOf(InvalidScopeError);

    // The store holds the narrowed scope, so a resume asks for what the grant still has.
    expect(await store.load(session.taskId)).toMatchObject({ scope: 'jira:read' });
    const resumed = await c.resume(session.taskId);
    expect(resumed?.scope).toBe('jira:read');
    resumed?.stop();
  });

  it('saves a narrowed scope before asking for it, so a store that then fails cannot strand the task', async () => {
    const memory = new MemoryTaskGrantStore();
    let saves = 0;
    let failFrom = Number.POSITIVE_INFINITY;
    const sentAtSave: number[] = [];
    const store: TaskGrantStore = {
      save: async (record) => {
        saves++;
        sentAtSave.push(plane.requests.length);
        if (saves >= failFrom) throw new Error('disk full');
        await memory.save(record);
      },
      load: (taskId) => memory.load(taskId),
      remove: (taskId) => memory.remove(taskId),
    };
    const errors: unknown[] = [];
    const c = client({ grantStore: store, onRefreshError: (_, e) => errors.push(e) });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });
    const sentBefore = plane.requests.length;

    // The save after the refresh fails. The narrowed scope is already in the store, so a resume
    // asks for what the grant now holds rather than for what the control plane will refuse.
    failFrom = saves + 2;
    await session.refresh('jira:read');
    expect(sentAtSave.at(-2)).toBe(sentBefore);
    expect(errors).toHaveLength(1);
    expect(plane.task(session.taskId)?.scope).toBe('jira:read');
    expect(await memory.load(session.taskId)).toMatchObject({ scope: 'jira:read' });
    session.stop();
    failFrom = Number.POSITIVE_INFINITY;
    const resumed = await c.resume(session.taskId);
    expect(resumed?.scope).toBe('jira:read');
    resumed?.stop();
  });

  it('does not ask for a narrowed scope it could not save first', async () => {
    const memory = new MemoryTaskGrantStore();
    let failing = false;
    const store: TaskGrantStore = {
      save: async (record) => {
        if (failing) throw new Error('disk full');
        await memory.save(record);
      },
      load: (taskId) => memory.load(taskId),
      remove: (taskId) => memory.remove(taskId),
    };
    const errors: unknown[] = [];
    const session = await client({
      grantStore: store,
      onRefreshError: (_, e) => errors.push(e),
    }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });
    const sent = plane.requests.length;

    failing = true;
    await expect(session.refresh('jira:read')).rejects.toThrow('disk full');
    expect(plane.requests).toHaveLength(sent);
    expect(errors).toHaveLength(1);
    expect(session.isEnded).toBe(false);
    expect(session.scope).toBe('jira:read jira:comment');
    expect(plane.task(session.taskId)?.scope).toBe('jira:read jira:comment');

    // The session carries on as it was, and narrows once the store takes the record.
    failing = false;
    expect((await session.refresh('jira:read')).scope).toBe('jira:read');
    expect(await memory.load(session.taskId)).toMatchObject({ scope: 'jira:read' });
    session.stop();
  });

  it('a refresh is judged in the control plane order: a revoked task is access_denied whatever else is wrong', async () => {
    const c = client();
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const { grant } = session.toStored();
    await session.revoke();

    await expect(
      c.refresh(grant, 'https://elsewhere.internal', 'jira:read jira:admin'),
    ).rejects.toBeInstanceOf(AccessDeniedError);
    // A grant presented by another agent is one that does not exist.
    await expect(
      client({ agentId: 'someone-else' }).refresh(grant, 'https://jira.internal', 'jira:read'),
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });

  it('is refused task_ending with less than five seconds of the task left', async () => {
    plane.taskTtlSeconds = 10;
    const c = client();
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    session.stop();
    vi.setSystemTime(start + 6_000);

    const refused = await c
      .refresh(session.toStored().grant, 'https://jira.internal', 'jira:read')
      .catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(AccessDeniedError);
    expect(refused).toMatchObject({ status: 400 });
  });

  it('counts expires_in in whole seconds of the token expiry, cut to the task', async () => {
    plane.taskTtlSeconds = 400;
    vi.setSystemTime(start + 700);
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    vi.setSystemTime(start + 180_900);
    const token = await session.refresh();
    // The task ends at start + 400.7s; the token with it, at the whole second before.
    expect(token.expires_in).toBe(220);
    expect(session.expiresAt.getTime()).toBe(start + 400_700);
    session.stop();
  });

  it('never counts a token as living past its exp, which expires_in rounds towards', async () => {
    plane.jwtTokens = true;
    // Sent 700ms into a second: expires_in counts from the whole second the control plane
    // truncated its clock to, so counting it from here would add 700ms the token does not have.
    vi.setSystemTime(start + 700);
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    expect(session.expiresAt.getTime()).toBe(start + 300_000);

    // 4.5 seconds left by exp, 5.2 by expires_in: too little to hand out, so it is refreshed first.
    vi.setSystemTime(start + 295_500);
    const refreshes = () =>
      plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token').length;
    await session.accessToken();
    expect(refreshes()).toBe(1);
    expect(session.expiresAt.getTime()).toBe(start + 595_000);
    session.stop();
  });

  it('counts from expires_in when the token carries no readable exp', async () => {
    vi.setSystemTime(start + 700);
    for (const token of [
      'opaque',
      'a.b.c',
      `x.${base64UrlEncode(utf8(JSON.stringify({ exp: '300' })))}.y`,
      `x.${base64UrlEncode(utf8(JSON.stringify({ iat: 1 })))}.y`,
      ...[null, true, [300], { value: 300 }].map(
        (exp) => `x.${base64UrlEncode(utf8(JSON.stringify({ exp })))}.y`,
      ),
    ]) {
      const session = new TaskSession(
        {
          access_token: token,
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: 300,
          scope: 'jira:read',
          refresh_token: 'g',
          task_id: 'task',
          task_expires_at: new Date(start + 1_800_000).toISOString(),
        },
        'https://jira.internal',
        Date.now(),
        {
          refresh: async () => {
            throw new Error('not called');
          },
          revoke: async () => undefined,
          store: new MemoryTaskGrantStore(),
          now: () => Date.now(),
        },
      );
      expect(session.expiresAt.getTime(), token).toBe(start + 300_700);
      session.stop();
    }
  });

  it('an exp in the past or in milliseconds can neither end a token early nor stretch it', async () => {
    vi.setSystemTime(start + 700);
    const counted = start + 300_700;
    for (const [exp, expected] of [
      // Long past: a token read as already spent would be refreshed on every call.
      [Math.floor(start / 1000) - 3600, counted - 1000],
      [0, counted - 1000],
      [-1, counted - 1000],
      // Milliseconds by mistake: far in the future, and never longer than expires_in.
      [start + 300_000, counted],
    ] as const) {
      const session = new TaskSession(
        {
          access_token: `x.${base64UrlEncode(utf8(JSON.stringify({ exp })))}.y`,
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: 300,
          scope: 'jira:read',
          refresh_token: 'g',
          task_id: 'task',
          task_expires_at: new Date(start + 1_800_000).toISOString(),
        },
        'https://jira.internal',
        Date.now(),
        {
          refresh: async () => {
            throw new Error('not called');
          },
          revoke: async () => undefined,
          store: new MemoryTaskGrantStore(),
          now: () => Date.now(),
        },
      );
      expect(session.expiresAt.getTime(), String(exp)).toBe(expected);
      session.stop();
    }
  });

  it('a clock ahead of the control plane cannot make exp cut a token short by more than the rounding', async () => {
    // exp is the control plane's clock and expires_in is relative, so the agent's clock running
    // 30 seconds fast would put exp 30 seconds early here. Near the end of a task, where tokens
    // are short, that would have every accessToken() refresh; exp only takes off the rounding.
    plane.jwtTokens = true;
    const session = await client({ now: () => Date.now() + 30_000 }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    expect(session.expiresAt.getTime()).toBe(start + 329_000);
    session.stop();
  });

  it('a clock that runs fast for one refresh stops the session but leaves the task resumable', async () => {
    // The live repro: the agent's clock two minutes ahead, so its assertion is not yet valid at
    // the control plane, which answers invalid_client while the task is alive.
    let skew = 0;
    const store = new MemoryTaskGrantStore();
    const c = client({ grantStore: store, now: () => Date.now() + skew });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    skew = 120_000;
    await expect(session.refresh()).rejects.toBeInstanceOf(InvalidClientError);
    expect(session.isEnded).toBe(true);
    expect(plane.task(session.taskId)?.revoked).toBe(false);
    expect(await store.load(session.taskId)).toBeDefined();

    skew = 0;
    const resumed = await c.resume(session.taskId);
    expect(await resumed?.accessToken()).toBeTypeOf('string');
    resumed?.stop();
  });

  it('a narrowing asked for during a refresh in flight is not lost', async () => {
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });

    const wide = session.refresh();
    const narrow = session.refresh('jira:read');
    await settle(plane);
    expect((await wide).scope).toBe('jira:read jira:comment');
    await settle(plane);
    expect((await narrow).scope).toBe('jira:read');
    expect(session.scope).toBe('jira:read');
    expect(
      plane.requests
        .filter((r) => r.form.get('grant_type') === 'refresh_token')
        .map((r) => r.form.get('scope')),
    ).toEqual(['jira:read jira:comment', 'jira:read']);
    session.stop();
  });

  for (const order of [
    ['jira:read jira:comment', 'jira:read'],
    ['jira:read', 'jira:read jira:comment'],
  ] as const) {
    it(`two narrowings waiting on one refresh each get no more than they asked for (${order.join(' then ')})`, async () => {
      const store = new MemoryTaskGrantStore();
      const saved: string[] = [];
      const recording: TaskGrantStore = {
        save: async (r) => {
          saved.push(r.scope);
          await store.save(r);
        },
        load: (id) => store.load(id),
        remove: (id) => store.remove(id),
      };
      const session = await client({ grantStore: recording }).exchange({
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read jira:comment jira:write',
      });
      saved.length = 0;

      const wide = session.refresh();
      const first = session.refresh(order[0]);
      const second = session.refresh(order[1]);
      const outcomes = Promise.allSettled([wide, first, second]);
      await settle(plane);
      await settle(plane);
      await settle(plane);
      const [w, a, b] = await outcomes;

      expect(w.status === 'fulfilled' && w.value.scope).toBe('jira:read jira:comment jira:write');
      expect(a.status === 'fulfilled' && a.value.scope).toBe(order[0]);
      // The second narrowing either ran on its own, judged against what the first left, or
      // shared the first because that one asked for no more than it did. Never wider.
      expect(b.status === 'fulfilled' && b.value.scope).toBe('jira:read');
      expect(session.scope).toBe('jira:read');
      const sent = plane.requests
        .filter((r) => r.form.get('grant_type') === 'refresh_token')
        .map((r) => r.form.get('scope'));
      expect(sent).toEqual(
        order[1] === 'jira:read'
          ? ['jira:read jira:comment jira:write', 'jira:read jira:comment', 'jira:read']
          : ['jira:read jira:comment jira:write', 'jira:read'],
      );
      // Every narrowing reached the store before it went out on the wire.
      for (const scope of sent.slice(1)) {
        expect(saved.indexOf(scope as string)).toBeGreaterThanOrEqual(0);
      }
      expect(saved.at(-1)).toBe('jira:read');
      session.stop();
    });
  }

  it('three narrowings waiting on one refresh run one after another, each narrower', async () => {
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'a b c d',
    });

    const all = Promise.all([
      session.refresh(),
      session.refresh('a b c'),
      session.refresh('a b'),
      session.refresh('a'),
    ]);
    for (let i = 0; i < 4; i++) await settle(plane);
    const scopes = (await all).map((t) => t.scope);

    expect(scopes).toEqual(['a b c d', 'a b c', 'a b', 'a']);
    expect(session.scope).toBe('a');
    session.stop();
  });

  it('a refresh that asks for no narrowing shares a narrowing already in flight', async () => {
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read jira:comment',
    });

    const narrow = session.refresh('jira:read');
    const plain = session.refresh();
    await settle(plane);

    expect((await narrow).scope).toBe('jira:read');
    expect((await plain).scope).toBe('jira:read');
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      1,
    );
    session.stop();
  });

  it('keeps going after a transient failure and retries before the token expires', async () => {
    const errors: unknown[] = [];
    const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    plane.nextFailure = {
      status: 503,
      body: { error: 'temporarily_unavailable', error_description: 'Later.' },
    };

    await run(plane, 180_000);
    expect(errors[0]).toBeInstanceOf(TemporarilyUnavailableError);
    expect(session.isEnded).toBe(false);
    plane.nextFailure = new TypeError('fetch failed');
    await run(plane, 72_000);
    expect(errors[1]).toBeInstanceOf(TransportError);

    await run(plane, 30_000);
    expect(errors).toHaveLength(2);
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now() + 200_000);
    expect(session.isEnded).toBe(false);
    session.stop();
  });

  it(
    'backs off between retries and gives up when the task itself has expired',
    { timeout: 60_000 },
    async () => {
      plane.taskTtlSeconds = 900;
      const errors: unknown[] = [];
      const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read',
      });
      plane.nextFailure = new TypeError('down');
      await run(plane, 180_000);
      expect(errors).toHaveLength(1);

      // Every retry fails: the waits grow 1, 2, 4, 8, 16, 32, 60, 60... seconds, never a 1 Hz loop.
      plane.alwaysFail = new TypeError('down');
      const before = plane.tokenRequestTimes.length;
      await run(plane, 120_000, 1_000);
      const attempts = plane.tokenRequestTimes.slice(before);
      const gaps = attempts.slice(1).map((t, i) => (t - (attempts[i] as number)) / 1000);
      expect(attempts[0]).toBe(start + 181_000);
      expect(gaps.slice(0, 5)).toEqual([2, 4, 8, 16, 32]);
      expect(gaps.slice(5).every((g) => g === 60)).toBe(true);
      expect(session.isEnded).toBe(false);

      // Past the end of the task nothing is tried any more: the session ends and the grant goes.
      await run(plane, 720_000, 30_000);
      expect(session.isEnded).toBe(true);
      await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
      const last = plane.tokenRequestTimes.at(-1) as number;
      expect(last).toBeLessThanOrEqual(start + 900_000);
      await run(plane, 120_000, 30_000);
      expect(plane.tokenRequestTimes.at(-1)).toBe(last);
    },
  );

  it('waits as long as the control plane asked when it is rate limited, then carries on', async () => {
    const errors: unknown[] = [];
    const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    // Longer than the retry cap: Retry-After is the control plane's word and wins over the backoff.
    plane.nextFailure = {
      status: 429,
      body: { error: 'slow_down', error_description: 'Too many requests.' },
      headers: { 'retry-after': '90' },
    };

    await run(plane, 300_000);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(SlowDownError);
    expect((errors[0] as SlowDownError).retryAfterSeconds).toBe(90);
    expect(plane.tokenRequestTimes.slice(1)).toEqual([start + 180_000, start + 270_000]);
    expect(session.isEnded).toBe(false);
    expect(session.expiresAt.getTime()).toBe(start + 570_000);
    session.stop();
  });

  it('ends the session on any refusal that a retry could only repeat, and keeps a live task resumable', async () => {
    for (const [status, error, type] of [
      [400, 'invalid_scope', InvalidScopeError],
      [400, 'invalid_target', InvalidTargetError],
      [401, 'invalid_client', InvalidClientError],
    ] as const) {
      const store = new MemoryTaskGrantStore();
      const session = await client({ grantStore: store }).exchange({
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read',
      });
      plane.nextFailure = { status, body: { error, error_description: 'No.' } };
      await expect(session.refresh()).rejects.toBeInstanceOf(type);
      expect(session.isEnded).toBe(true);
      await expect(session.accessToken()).rejects.toBeInstanceOf(type);
      // None of these says the task is over, so the grant that can resume it is kept.
      expect(await store.load(session.taskId)).toMatchObject({ taskId: session.taskId });
    }
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      3,
    );
  });

  it('a refused assertion stops the session without deleting the grant of a task that is still live', async () => {
    // The agent's clock ran two minutes fast for one refresh: the control plane refused the
    // assertion as invalid_client while the task was alive. The session must not keep asking —
    // every refusal is a denial record — and it must not drop the grant, or the task could never
    // be picked up again once the clock is right.
    const store = new MemoryTaskGrantStore();
    const errors: unknown[] = [];
    const c = client({ grantStore: store, onRefreshError: (_, e) => errors.push(e) });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    plane.nextFailure = {
      status: 401,
      body: { error: 'invalid_client', error_description: 'The client assertion is invalid.' },
    };

    await run(plane, 180_000);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(InvalidClientError);
    expect(session.isEnded).toBe(true);
    await expect(session.accessToken()).rejects.toBeInstanceOf(InvalidClientError);
    expect(await store.load(session.taskId)).toMatchObject({
      taskId: session.taskId,
      grant: session.toStored().grant,
    });

    // Nothing more is sent on its own.
    const sent = plane.requests.length;
    await run(plane, 300_000);
    expect(plane.requests).toHaveLength(sent);

    // Once the cause is fixed, the task picks up where it left off.
    const resumed = await c.resume(session.taskId);
    expect(resumed?.taskId).toBe(session.taskId);
    expect(await resumed?.accessToken()).toBeTypeOf('string');
    resumed?.stop();
  });

  it('a store that fails never costs the caller a token it already has, and never leaves a session running unseen', async () => {
    const failing: TaskGrantStore = {
      save: async () => {
        throw new Error('disk full');
      },
      load: async () => undefined,
      remove: async () => {
        throw new Error('disk full');
      },
    };
    await expect(
      client({ grantStore: failing }).exchange({
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read',
      }),
    ).rejects.toThrow('disk full');
    await run(plane, 400_000, 30_000);
    expect(plane.requests.filter((r) => r.form.get('grant_type') === 'refresh_token')).toHaveLength(
      0,
    );

    const flaky: TaskGrantStore = {
      ...new MemoryTaskGrantStore(),
      save: async () => undefined,
      load: async () => undefined,
      remove: async () => undefined,
    };
    const errors: unknown[] = [];
    const session = await client({
      grantStore: flaky,
      onRefreshError: (_, e) => errors.push(e),
    }).exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' });
    flaky.save = async () => {
      throw new Error('disk full');
    };
    const token = await session.refresh();
    expect(token.access_token).toBe(await session.accessToken());
    expect(errors).toHaveLength(1);
    expect(session.isEnded).toBe(false);

    plane.nextFailure = {
      status: 400,
      body: { error: 'access_denied', error_description: 'Revoked.' },
    };
    flaky.remove = async () => {
      throw new Error('disk full');
    };
    await expect(session.refresh()).rejects.toBeInstanceOf(AccessDeniedError);
    expect(errors).toHaveLength(3);
    expect(session.isEnded).toBe(true);
  });

  it('refuses a discovery document for another issuer or with endpoints elsewhere', async () => {
    const elsewhere = async (document: Record<string, string>) =>
      new SubactIdClient({
        issuer,
        agentId: 'a',
        kid: 'k',
        privateKey: rsaPem,
        fetch: async () => new Response(JSON.stringify(document), { status: 200 }),
      })
        .exchange({ subjectToken: 't', resource: 'r', scope: 's' })
        .catch((e: unknown) => e);

    expect(
      await elsewhere({
        issuer: 'https://other.example',
        token_endpoint: `${issuer}/oauth2/token`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
      }),
    ).toMatchObject({ message: 'The discovery document names a different issuer.' });
    expect(
      await elsewhere({
        issuer,
        token_endpoint: 'https://other.example/oauth2/token',
        jwks_uri: `${issuer}/.well-known/jwks.json`,
      }),
    ).toMatchObject({
      message: "The discovery document's token_endpoint is not under the issuer.",
    });
    expect(
      await elsewhere({ issuer, token_endpoint: `${issuer}/oauth2/token`, jwks_uri: 'not a url' }),
    ).toMatchObject({ message: "The discovery document's jwks_uri is not under the issuer." });
    // A trailing slash on the issuer is the same issuer.
    const slash = (await elsewhere({
      issuer: `${issuer}/`,
      token_endpoint: `${issuer}/oauth2/token`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
    })) as Error;
    expect(slash.message).not.toContain('different issuer');
  });

  it('answers that are not objects, and tokens with an unreadable task expiry, are transport errors', async () => {
    plane.nextFailure = { status: 502, body: null };
    await expect(
      client().exchange({ subjectToken: 't', resource: 'r', scope: 's' }),
    ).rejects.toBeInstanceOf(TransportError);
    plane.nextFailure = {
      status: 200,
      body: {
        access_token: 'a',
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        token_type: 'Bearer',
        refresh_token: 'g',
        task_id: 't',
        task_expires_at: 'never',
        scope: 's',
        expires_in: 300,
      },
    };
    await expect(
      client().exchange({ subjectToken: 't', resource: 'r', scope: 's' }),
    ).rejects.toThrow('task_expires_at');
  });

  it('resume drops an expired or revoked task from the store instead of presenting its grant again', async () => {
    const store = new MemoryTaskGrantStore();
    await store.save({
      taskId: 'old',
      grant: 'g',
      resource: 'https://jira.internal',
      scope: 'jira:read',
      taskExpiresAt: new Date(start - 1).toISOString(),
    });
    expect(await client({ grantStore: store }).resume('old')).toBeUndefined();
    expect(await store.load('old')).toBeUndefined();
    expect(plane.requests).toHaveLength(0);

    await store.save({
      taskId: 'gone',
      grant: 'g',
      resource: 'https://jira.internal',
      scope: 'jira:read',
      taskExpiresAt: new Date(start + 600_000).toISOString(),
    });
    await expect(client({ grantStore: store }).resume('gone')).rejects.toBeInstanceOf(
      InvalidGrantError,
    );
    expect(await store.load('gone')).toBeUndefined();
  });

  it('stores the grant, resumes from the store, and removes it when the task is over', async () => {
    const store = new MemoryTaskGrantStore();
    const session = await client({ grantStore: store }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    session.stop();
    expect(await store.load('task_1')).toMatchObject({
      taskId: 'task_1',
      grant: 'task_grant_1',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    const resumed = await client({ grantStore: store }).resume('task_1');
    expect(resumed?.taskId).toBe('task_1');
    expect(await store.load('task_1')).toMatchObject({ grant: 'task_grant_1', scope: 'jira:read' });
    expect(await client({ grantStore: store }).resume('task_9')).toBeUndefined();

    plane.nextFailure = {
      status: 400,
      body: { error: 'access_denied', error_description: 'The task has been revoked.' },
    };
    await expect(resumed?.refresh()).rejects.toBeInstanceOf(AccessDeniedError);
    expect(await store.load('task_1')).toBeUndefined();
  });

  it('keeps the grant of a task whose agent is disabled, and resumes it once the agent is enabled again', async () => {
    const store = new MemoryTaskGrantStore();
    const errors: unknown[] = [];
    const c = client({ grantStore: store, onRefreshError: (_, e) => errors.push(e) });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const { grant } = session.toStored();

    plane.disabledAgents.add('jira-triage');
    const refused = await session.refresh().catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(AccessDeniedError);
    expect(refused).toMatchObject({ reason: 'agent_disabled' });
    expect(isTaskOver(refused)).toBe(false);
    expect(isTerminal(refused)).toBe(true);
    expect(session.isEnded).toBe(true);
    // The session stops asking: every refusal is a denial record.
    const sent = plane.requests.length;
    await run(plane, 300_000);
    expect(plane.requests).toHaveLength(sent);
    // But the task is alive, so the grant that can resume it stays.
    expect(await store.load(session.taskId)).toMatchObject({ grant });

    // A resume while the agent is still disabled is refused the same way, and keeps the grant too.
    await expect(c.resume(session.taskId)).rejects.toMatchObject({ reason: 'agent_disabled' });
    expect(await store.load(session.taskId)).toMatchObject({ grant });

    plane.disabledAgents.delete('jira-triage');
    const resumed = await c.resume(session.taskId);
    expect(resumed?.taskId).toBe(session.taskId);
    expect(await resumed?.accessToken()).toBeTypeOf('string');
    resumed?.stop();
  });

  it('drops the grant when the control plane says the task is over', async () => {
    const store = new MemoryTaskGrantStore();
    const c = client({ grantStore: store });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    // An operator, or a block of the human, ends the task without the agent asking.
    plane.revokeTask(session.taskId);

    const refused = await session.refresh().catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(AccessDeniedError);
    expect(refused).toMatchObject({ reason: 'task_revoked' });
    expect(isTaskOver(refused)).toBe(true);
    expect(session.isEnded).toBe(true);
    expect(await store.load(session.taskId)).toBeUndefined();

    // And resume drops it the same way.
    const again = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    again.stop();
    plane.revokeTask(again.taskId);
    await expect(c.resume(again.taskId)).rejects.toMatchObject({ reason: 'task_revoked' });
    expect(await store.load(again.taskId)).toBeUndefined();
  });

  it('drops the grant on delegation_depth_exceeded, which no retry of the grant would get past', async () => {
    const store = new MemoryTaskGrantStore();
    const c = client({ grantStore: store });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const depthExceeded = {
      status: 400,
      body: {
        error: 'access_denied',
        error_description: 'The delegation is too deep.',
        reason: 'delegation_depth_exceeded',
      },
    };
    plane.nextFailure = depthExceeded;
    const refused = await session.refresh().catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(AccessDeniedError);
    expect(refused).toMatchObject({ reason: 'delegation_depth_exceeded' });
    expect(isTaskOver(refused)).toBe(true);
    expect(session.isEnded).toBe(true);
    expect(await store.load(session.taskId)).toBeUndefined();

    const again = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    again.stop();
    plane.nextFailure = depthExceeded;
    await expect(c.resume(again.taskId)).rejects.toMatchObject({
      reason: 'delegation_depth_exceeded',
    });
    expect(await store.load(again.taskId)).toBeUndefined();
  });

  it('drops the grant on an access_denied with no reason, as an older control plane answers it', async () => {
    const store = new MemoryTaskGrantStore();
    const c = client({ grantStore: store });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    plane.nextFailure = {
      status: 400,
      body: { error: 'access_denied', error_description: 'The agent is disabled.' },
    };
    const refused = await session.refresh().catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(AccessDeniedError);
    expect((refused as AccessDeniedError).reason).toBeUndefined();
    expect(isTaskOver(refused)).toBe(true);
    expect(await store.load(session.taskId)).toBeUndefined();

    const again = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    again.stop();
    plane.nextFailure = {
      status: 400,
      body: { error: 'access_denied', error_description: 'The agent is disabled.' },
    };
    await expect(c.resume(again.taskId)).rejects.toBeInstanceOf(AccessDeniedError);
    expect(await store.load(again.taskId)).toBeUndefined();
  });

  it('an exchange refused access_denied leaves the store untouched', async () => {
    const calls: string[] = [];
    const inner = new MemoryTaskGrantStore();
    const kept: StoredTaskGrant = {
      taskId: 'task_other',
      grant: 'task_grant_other',
      resource: 'https://jira.internal',
      scope: 'jira:read',
      taskExpiresAt: new Date(start + 1_800_000).toISOString(),
    };
    await inner.save(kept);
    const store: TaskGrantStore = {
      save: async (record) => {
        calls.push(`save ${record.taskId}`);
        await inner.save(record);
      },
      load: (taskId) => inner.load(taskId),
      remove: async (taskId) => {
        calls.push(`remove ${taskId}`);
        await inner.remove(taskId);
      },
    };
    for (const reason of ['task_revoked', 'sponsor_disabled', undefined]) {
      plane.nextFailure = {
        status: 400,
        body: { error: 'access_denied', error_description: 'No.', reason },
      };
      const thrown = await client({ grantStore: store })
        .exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' })
        .catch((e: unknown) => e);
      expect(thrown, String(reason)).toBeInstanceOf(AccessDeniedError);
    }
    expect(calls).toEqual([]);
    expect(await inner.load('task_other')).toEqual(kept);
  });

  it('ignores reason on every error but access_denied', async () => {
    for (const [error, Type, over] of [
      ['invalid_grant', InvalidGrantError, true],
      ['invalid_scope', InvalidScopeError, false],
      ['invalid_client', InvalidClientError, false],
      ['temporarily_unavailable', TemporarilyUnavailableError, false],
      ['server_error', UnknownOAuthError, false],
    ] as const) {
      // A liftable reason on invalid_grant must not keep a dead grant, and a task-over reason
      // on anything else must not drop a live one.
      for (const reason of ['agent_disabled', 'task_revoked']) {
        plane.nextFailure = {
          status: error === 'invalid_client' ? 401 : 400,
          body: { error, error_description: 'No.', reason },
        };
        const thrown = await client()
          .exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' })
          .catch((e: unknown) => e);
        expect(thrown, `${error} ${reason}`).toBeInstanceOf(Type);
        expect('reason' in (thrown as object), `${error} ${reason}`).toBe(false);
        expect(isTaskOver(thrown), `${error} ${reason}`).toBe(over);
      }
    }
  });

  it('reads reason off an access_denied only when it is a string', async () => {
    for (const [reason, expected] of [
      ['sponsor_disabled', 'sponsor_disabled'],
      [42, undefined],
      [null, undefined],
      [['task_revoked'], undefined],
    ] as const) {
      plane.nextFailure = {
        status: 400,
        body: { error: 'access_denied', error_description: 'No.', reason },
      };
      const thrown = await client()
        .exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' })
        .catch((e: unknown) => e);
      expect(thrown).toBeInstanceOf(AccessDeniedError);
      expect((thrown as AccessDeniedError).reason).toBe(expected);
      expect('reason' in (thrown as object)).toBe(expected !== undefined);
    }
  });

  it('a stopped session throws its own error, which does not say the task is over', async () => {
    const store = new MemoryTaskGrantStore();
    const session = await client({ grantStore: store }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    session.stop();

    const thrown = await session.accessToken().catch((e: unknown) => e);
    expect(thrown).toBeInstanceOf(SessionStoppedError);
    expect(thrown).toBeInstanceOf(SubactIdError);
    expect(thrown).not.toBeInstanceOf(TaskEndedError);
    // A caller following the README drops the grant on isTaskOver; the task is still alive.
    expect(isTaskOver(thrown)).toBe(false);
    expect(isTerminal(thrown)).toBe(false);
    expect(isRetryable(thrown)).toBe(false);
    await expect(session.refresh()).rejects.toBeInstanceOf(SessionStoppedError);
    expect(await store.load(session.taskId)).toBeDefined();
    expect(plane.task(session.taskId)?.revoked).toBe(false);
  });

  it('tells a task that is over from a refusal that may be lifted', () => {
    const denied = (reason?: string) => new AccessDeniedError('access_denied', 'No.', 400, reason);
    for (const reason of taskOverReasons) {
      expect(isTaskOver(denied(reason)), reason).toBe(true);
    }
    expect(isTaskOver(denied())).toBe(true);
    // Spec section 8: a reason the client does not recognise is treated as the task being over.
    expect(isTaskOver(denied('something_new'))).toBe(true);
    expect([...liftableReasons].sort()).toEqual([
      'agent_disabled',
      'sponsor_disabled',
      'sponsor_not_found',
    ]);
    // Spec section 8: no retry of this grant would succeed, so it is as good as over.
    expect(taskOverReasons).toContain('delegation_depth_exceeded');
    expect(isTaskOver(denied('delegation_depth_exceeded'))).toBe(true);
    expect(isLiftableReason('delegation_depth_exceeded')).toBe(false);
    for (const reason of liftableReasons) {
      expect(isTaskOver(denied(reason)), reason).toBe(false);
      expect(isTerminal(denied(reason)), reason).toBe(true);
      expect(isLiftableReason(reason), reason).toBe(true);
    }
    for (const reason of [...taskOverReasons, 'something_new', 'toString', '']) {
      expect(isLiftableReason(reason), reason).toBe(false);
    }
    expect(isTaskOver(new InvalidGrantError('invalid_grant', 'No.', 400))).toBe(true);
    expect(isTaskOver(new TaskEndedError('The task has expired.'))).toBe(true);
    expect(isTaskOver(new InvalidClientError('invalid_client', 'No.', 401))).toBe(false);
    expect(isTaskOver(new TemporarilyUnavailableError('temporarily_unavailable', 'No.', 503))).toBe(
      false,
    );
  });

  it('cannot be talked into keeping the grant of a task that is over by editing the reason lists', () => {
    expect(Object.isFrozen(taskOverReasons)).toBe(true);
    expect(Object.isFrozen(liftableReasons)).toBe(true);
    const lists = { taskOverReasons, liftableReasons } as unknown as Record<string, string[]>;
    expect(() => lists['liftableReasons']?.push('task_revoked')).toThrow(TypeError);
    expect(() => lists['taskOverReasons']?.splice(0)).toThrow(TypeError);
    expect(liftableReasons).not.toContain('task_revoked');
    expect(isTaskOver(new AccessDeniedError('access_denied', 'No.', 400, 'task_revoked'))).toBe(
      true,
    );
  });

  it("revokes the task with the agent's assertion and ends the session", async () => {
    const store = new MemoryTaskGrantStore();
    const c = client({ grantStore: store });
    const session = await c.exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    const { grant } = session.toStored();

    await session.revoke();

    const request = plane.requests.at(-1);
    expect(request?.url).toBe(revocationEndpoint);
    expect(request?.form.get('token')).toBe(grant);
    expect(request?.form.get('token_type_hint')).toBe('refresh_token');
    expect(request?.form.get('client_assertion_type')).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    );
    expect(plane.assertionClaims(plane.requests.length - 1, 'client_assertion')).toMatchObject({
      iss: 'jira-triage',
      aud: issuer,
    });
    expect(session.isEnded).toBe(true);
    await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
    expect(await store.load(session.taskId)).toBeUndefined();
    // The task is over at the control plane as well as here.
    await expect(c.refresh(grant, 'https://jira.internal', 'jira:read')).rejects.toBeInstanceOf(
      AccessDeniedError,
    );
  });

  describe('a session in trouble', () => {
    const tokenFor = (grant: string, scope: string, taskMs: number, expiresIn = 300) => ({
      access_token: `opaque_${grant}`,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope,
      refresh_token: grant,
      task_id: 'task',
      task_expires_at: new Date(start + taskMs).toISOString(),
    });

    it('keeps a narrowing whose request failed, so the next refresh never asks for more', async () => {
      const asked: string[] = [];
      const store = new MemoryTaskGrantStore();
      let calls = 0;
      const session = new TaskSession(
        tokenFor('g1', 'a b', 3_600_000),
        'https://jira.internal',
        Date.now(),
        {
          refresh: async (_grant, _resource, scope) => {
            asked.push(scope);
            // The control plane may have kept the narrowing; its answer is lost.
            if (calls++ === 0) throw new TransportError('reset');
            return tokenFor('g2', scope, 3_600_000);
          },
          revoke: async () => undefined,
          store,
          now: () => Date.now(),
        },
      );

      await expect(session.refresh('a')).rejects.toBeInstanceOf(TransportError);
      expect(session.scope).toBe('a');
      expect((await store.load('task'))?.scope).toBe('a');
      await session.refresh();
      expect(asked).toEqual(['a', 'a']);
      session.stop();
    });

    it('starts no refresh while a revocation is on the wire, and lets one go after a failed revocation', async () => {
      const store = new MemoryTaskGrantStore();
      let refreshes = 0;
      let answer: ((ok: boolean) => void) | undefined;
      const session = new TaskSession(
        tokenFor('g1', 'a', 3_600_000),
        'https://jira.internal',
        Date.now(),
        {
          refresh: async () => {
            refreshes++;
            return tokenFor('g2', 'a', 3_600_000);
          },
          revoke: () =>
            new Promise<void>((resolve, reject) => {
              answer = (ok) => (ok ? resolve() : reject(new TransportError('down')));
            }),
          store,
          now: () => Date.now(),
        },
      );
      await store.save(session.toStored());

      // A failed revocation leaves the session as it was: the waiting refresh then goes ahead.
      const failing = session.revoke();
      await until(() => answer !== undefined, 'the first revocation');
      const waiting = session.refresh();
      await tick();
      expect(refreshes).toBe(0);
      answer?.(false);
      await expect(failing).rejects.toBeInstanceOf(TransportError);
      await waiting;
      expect(refreshes).toBe(1);

      // A revocation that succeeds ends the session before the waiting refresh can run.
      answer = undefined;
      const revoking = session.revoke();
      await until(() => answer !== undefined, 'the second revocation');
      const refused = session.refresh();
      await tick();
      answer?.(true);
      await revoking;
      await expect(refused).rejects.toBeInstanceOf(TaskEndedError);
      expect(refreshes).toBe(1);
      expect(await store.load('task')).toBeUndefined();
    });

    it('does not end a live task when a slow answer leaves the fresh token short', async () => {
      const store = new MemoryTaskGrantStore();
      const session = new TaskSession(
        tokenFor('g1', 'a', 3_600_000, 1),
        'https://jira.internal',
        Date.now(),
        {
          refresh: async () => {
            // The answer takes 297 seconds of a 300-second token.
            vi.setSystemTime(Date.now() + 297_000);
            return tokenFor('g2', 'a', 3_600_000);
          },
          revoke: async () => undefined,
          store,
          now: () => Date.now(),
        },
      );
      await store.save(session.toStored());
      vi.setSystemTime(start + 2_000);

      await expect(session.accessToken()).rejects.toBeInstanceOf(TransportError);
      expect(session.isEnded).toBe(false);
      expect(await store.load('task')).toBeDefined();
      session.stop();
    });

    it('ends the task at its last token even when this clock runs behind the control plane', async () => {
      // The control plane's clock reads start + 56 s; this side's runs 5 s behind.
      vi.setSystemTime(start + 56_000);
      const behind = () => Date.now() - 5_000;
      const taskEnd = start + 60_000;
      const capped = (grant: string, expiresIn: number) => ({
        access_token: `x.${base64UrlEncode(utf8(JSON.stringify({ exp: taskEnd / 1000 })))}.y`,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        token_type: 'Bearer',
        expires_in: expiresIn,
        scope: 'a',
        refresh_token: grant,
        task_id: 'task',
        task_expires_at: new Date(taskEnd).toISOString(),
      });
      let refreshes = 0;
      const store = new MemoryTaskGrantStore();
      const session = new TaskSession(
        { ...capped('g1', 1), access_token: 'opaque' },
        'https://jira.internal',
        behind(),
        {
          refresh: async () => {
            refreshes++;
            return capped('g2', 4);
          },
          revoke: async () => undefined,
          store,
          now: behind,
        },
      );
      await store.save(session.toStored());

      await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
      await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
      expect(refreshes).toBe(1);
      expect(await store.load('task')).toBeUndefined();
    });

    it('waits out a Retry-After longer than a timer can hold instead of refreshing at once', async () => {
      let refreshes = 0;
      const session = new TaskSession(
        tokenFor('g1', 'a', 30 * 86_400_000, 10),
        'https://jira.internal',
        Date.now(),
        {
          refresh: async () => {
            refreshes++;
            throw new SlowDownError('slow_down', 'Later.', 429, 999_999_999);
          },
          revoke: async () => undefined,
          store: new MemoryTaskGrantStore(),
          now: () => Date.now(),
        },
      );
      await vi.advanceTimersByTimeAsync(10_000);
      expect(refreshes).toBe(1);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(refreshes).toBe(1);
      session.stop();
    });
  });

  it('revokes the grant a refresh already under way brings back, and leaves nothing in the store', async () => {
    vi.setSystemTime(start);
    const token = (grant: string) => ({
      access_token: 'opaque',
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'Bearer',
      expires_in: 300,
      scope: 'jira:read',
      refresh_token: grant,
      task_id: 'task',
      task_expires_at: new Date(start + 3_600_000).toISOString(),
    });
    const store = new MemoryTaskGrantStore();
    let answer: (() => void) | undefined;
    const revoked: string[] = [];
    const session = new TaskSession(token('g1'), 'https://jira.internal', Date.now(), {
      refresh: () =>
        new Promise((resolve) => {
          answer = () => resolve(token('g2'));
        }),
      revoke: async (grant) => {
        revoked.push(grant);
      },
      store,
      now: () => Date.now(),
    });
    await store.save(session.toStored());

    // The refresh is on the wire when the revocation is asked for, and answers first.
    const refreshing = session.refresh();
    await until(() => answer !== undefined, 'the refresh');
    const revoking = session.revoke();
    await tick();
    expect(revoked).toEqual([]);
    answer?.();
    await refreshing;
    await revoking;

    expect(revoked).toEqual(['g2']);
    expect(await store.load('task')).toBeUndefined();
    await expect(session.accessToken()).rejects.toBeInstanceOf(TaskEndedError);
  });

  it('a revocation that was refused, or could not be asked for, leaves the session as it was', async () => {
    const session = await client().exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });

    plane.nextFailure = new TypeError('down');
    await expect(session.revoke()).rejects.toBeInstanceOf(TransportError);
    plane.nextFailure = {
      status: 401,
      body: { error: 'invalid_client', error_description: 'No.' },
    };
    await expect(session.revoke()).rejects.toBeInstanceOf(InvalidClientError);

    expect(session.isEnded).toBe(false);
    expect(await session.accessToken()).toBeTypeOf('string');
    expect(plane.revocations).toEqual([]);
    session.stop();
  });

  it('canonicalises the issuer, so its case or a default port cannot make it disagree with the control plane', async () => {
    const session = await client({ issuer: 'https://SUBACTID.internal.example.com:443/' }).exchange(
      {
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read',
      },
    );
    expect(session.taskId).toBe('task_1');
    // Addressed to the issuer exactly as the control plane publishes it, not as configured here.
    expect(plane.assertionClaims(0, 'actor_token')['aud']).toBe(issuer);
    session.stop();

    for (const bad of [
      '',
      'subactid.internal.example.com',
      'ftp://subactid.internal.example.com',
    ]) {
      expect(() => client({ issuer: bad })).toThrow(SubactIdError);
    }
  });

  it('waits as long as the control plane asked when it answers 503, and backs off as before when it does not', async () => {
    const errors: unknown[] = [];
    const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    // At capacity, or with its database away, the control plane names the interval; it is a
    // floor under the backoff exactly as a slow_down's is.
    plane.nextFailure = {
      status: 503,
      body: { error: 'temporarily_unavailable', error_description: 'At capacity.' },
      headers: { 'retry-after': '90' },
    };

    await run(plane, 300_000);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(TemporarilyUnavailableError);
    expect((errors[0] as TemporarilyUnavailableError).retryAfterSeconds).toBe(90);
    expect(plane.tokenRequestTimes.slice(1)).toEqual([start + 180_000, start + 270_000]);
    expect(session.isEnded).toBe(false);
    session.stop();
  });

  it('keeps its own backoff for a 503 that names no interval', async () => {
    const errors: unknown[] = [];
    const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    plane.nextFailure = {
      status: 503,
      body: { error: 'temporarily_unavailable', error_description: 'Keys unavailable.' },
    };

    // Up to the refresh that fails, then second by second after it.
    await run(plane, 180_000);
    await run(plane, 5_000, 1_000);
    expect(errors).toHaveLength(1);
    expect((errors[0] as TemporarilyUnavailableError).retryAfterSeconds).toBeUndefined();
    // The first retry comes a second after the failed refresh, as the backoff has always done.
    expect(plane.tokenRequestTimes.slice(1, 3)).toEqual([start + 180_000, start + 181_000]);
    session.stop();
  });

  it.each([
    [401, 'invalid_client', InvalidClientError],
    [400, 'invalid_grant', InvalidGrantError],
    [400, 'invalid_scope', InvalidScopeError],
    [400, 'invalid_target', InvalidTargetError],
    [400, 'access_denied', AccessDeniedError],
    [400, 'unsupported_token_type', UnsupportedTokenTypeError],
    [503, 'temporarily_unavailable', TemporarilyUnavailableError],
    [429, 'slow_down', SlowDownError],
    [400, 'something_new', UnknownOAuthError],
  ])('maps a %s %s answer to its typed error', async (status, error, type) => {
    plane.nextFailure = { status, body: { error, error_description: 'Because.' } };

    const thrown = await client()
      .exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' })
      .catch((e: unknown) => e);

    expect(thrown).toBeInstanceOf(type);
    expect(thrown).toMatchObject({ error, errorDescription: 'Because.', status });
  });

  it('does not retry a 4xx that names no OAuth error, and still retries a 5xx that names none', async () => {
    // What the control plane answers for a body it cannot read or one too large: a problem
    // document, not an OAuth error. The same request gets the same answer however often it goes.
    const problem = (status: number) => ({
      status,
      body: { type: 'about:blank', title: 'The request body could not be read.', status },
      headers: { 'content-type': 'application/problem+json' },
    });
    for (const status of [400, 413]) {
      const store = new MemoryTaskGrantStore();
      const errors: unknown[] = [];
      const session = await client({
        grantStore: store,
        onRefreshError: (_, e) => errors.push(e),
      }).exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' });
      const before = plane.requests.length;
      plane.nextFailure = problem(status);
      await run(plane, 300_000);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toBeInstanceOf(UnknownOAuthError);
      expect(errors[0]).toMatchObject({ error: 'unknown', status });
      expect(isRetryable(errors[0])).toBe(false);
      expect(plane.requests.length - before).toBe(1);
      expect(session.isEnded).toBe(true);
      expect(await store.load(session.taskId)).toBeDefined();
    }

    for (const status of [500, 502, 408, 429]) {
      expect(isRetryable(new UnknownOAuthError('unknown', 'No description.', status))).toBe(true);
    }
    for (const status of [400, 401, 403, 404, 413]) {
      expect(isRetryable(new UnknownOAuthError('something_new', 'Because.', status))).toBe(false);
    }

    const errors: unknown[] = [];
    const session = await client({ onRefreshError: (_, e) => errors.push(e) }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    plane.nextFailure = problem(500);
    await run(plane, 185_000);
    expect(errors).toHaveLength(1);
    expect(session.isEnded).toBe(false);
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now() + 200_000);
    session.stop();
  });

  it('reports unreachable and malformed answers as transport errors', async () => {
    plane.nextFailure = new TypeError('fetch failed');
    await expect(
      client().exchange({ subjectToken: 't', resource: 'r', scope: 's' }),
    ).rejects.toBeInstanceOf(TransportError);

    plane.nextFailure = { status: 200, body: { access_token: 'x' } };
    await expect(
      client().exchange({ subjectToken: 't', resource: 'r', scope: 's' }),
    ).rejects.toThrow('token response has no refresh_token');

    const dead = new SubactIdClient({
      issuer,
      agentId: 'a',
      kid: 'k',
      privateKey: rsaPem,
      fetch: async () => new Response('down', { status: 502 }),
    });
    await expect(dead.exchange({ subjectToken: 't', resource: 'r', scope: 's' })).rejects.toThrow(
      'Discovery answered 502',
    );
  });

  it('types a refusal of the discovery fetch, so a cold client is told to slow down', async () => {
    const discovery = (body: string, init: ResponseInit): Promise<unknown> =>
      client({ fetch: async () => new Response(body, init) })
        .exchange({ subjectToken: 't', resource: 'r', scope: 's' })
        .catch((e: unknown) => e);
    const asJson = (status: number, headers: Record<string, string> = {}): ResponseInit => ({
      status,
      headers: { 'content-type': 'application/json', ...headers },
    });

    // Discovery is the first thing a fresh client fetches and is rate limited like every other
    // endpoint, so its 429 is the control plane's own refusal, with the interval it named.
    const limited = await discovery(
      JSON.stringify({ error: 'slow_down', error_description: 'Too many requests.' }),
      asJson(429, { 'retry-after': '2' }),
    );
    expect(limited).toBeInstanceOf(SlowDownError);
    expect(limited).toMatchObject({ error: 'slow_down', status: 429, retryAfterSeconds: 2 });

    // So is a 503 temporarily_unavailable: the instance at capacity, or its database away. It is
    // retryable and never terminal, so reading it can only make a caller wait.
    const busy = await discovery(
      JSON.stringify({ error: 'temporarily_unavailable', error_description: 'At capacity.' }),
      asJson(503, { 'retry-after': '1' }),
    );
    expect(busy).toBeInstanceOf(TemporarilyUnavailableError);
    expect(busy).toMatchObject({
      error: 'temporarily_unavailable',
      status: 503,
      retryAfterSeconds: 1,
    });
    const busyOdd = await discovery(JSON.stringify({ error: 'access_denied' }), asJson(503));
    expect(busyOdd).toBeInstanceOf(TransportError);

    // An answer that names no refusal of its own stays a transport failure, JSON or not.
    for (const body of ['down', JSON.stringify({ message: 'bad gateway' })]) {
      const broken = await discovery(body, asJson(502));
      expect(broken).toBeInstanceOf(TransportError);
      expect(broken).toMatchObject({ message: 'Discovery answered 502.' });
    }

    // And so does an answer that is OAuth-shaped but not the control plane's. Discovery takes
    // no credential, so nothing it says is a decision about this agent or its human: a 401 or
    // a 403 naming one came from something standing in front of the control plane, and typing
    // it as a refusal would make a gateway's bad minute terminal.
    for (const [status, error] of [
      [401, 'invalid_client'],
      [403, 'access_denied'],
      [500, 'temporarily_unavailable'],
      [400, 'invalid_grant'],
    ] as const) {
      const proxied = await discovery(
        JSON.stringify({ error, error_description: 'Not from the control plane.' }),
        asJson(status),
      );
      expect(proxied, `${status} ${error}`).toBeInstanceOf(TransportError);
      expect(proxied).toMatchObject({ message: `Discovery answered ${status}.` });
    }

    // A 429 that names something else is not admission control either.
    const odd = await discovery(JSON.stringify({ error: 'access_denied' }), asJson(429));
    expect(odd).toBeInstanceOf(TransportError);
  });

  it('keeps a resumed task through a gateway answering discovery for the control plane', async () => {
    // The whole point of the narrowing above, on the path that reaches it. A fresh process
    // picking a live task back up fetches discovery for the first time, and `resume` drops the
    // grant on a terminal refusal — so a proxy answering `403 {"error":"access_denied"}` there
    // used to delete the grant of a task the control plane still holds, and report the human
    // as blocked. It has to be retryable, and the grant has to survive.
    const grantStore = new MemoryTaskGrantStore();
    const started = await client({ grantStore }).exchange({
      subjectToken: 't',
      resource: 'https://jira.internal',
      scope: 'jira:read',
    });
    started.stop();

    const restarted = client({ grantStore });
    plane.nextDiscoveryFailure = {
      status: 403,
      body: { error: 'access_denied', error_description: 'Forbidden by the edge.' },
      headers: { 'content-type': 'application/json' },
    };
    const error = await restarted.resume(started.taskId).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(TransportError);
    expect(isRetryable(error)).toBe(true);
    expect(await grantStore.load(started.taskId)).toBeDefined();

    // And once whatever it was has passed, the task picks up where it left off.
    const resumed = await restarted.resume(started.taskId);
    expect(resumed).toBeDefined();
    resumed?.stop();
  });

  it.each([
    [400, 'access_denied', AccessDeniedError],
    [503, 'temporarily_unavailable', TemporarilyUnavailableError],
  ])(
    'an exchange the control plane refuses leaves nothing behind (%s %s)',
    async (status, error, type) => {
      // An exchange is refused for the human as well as for the agent or the request: a subject
      // token that verifies may have been issued before the person was blocked. Whichever it
      // was, no task was created, so there must be no grant in the store and nothing scheduled —
      // the temporarily_unavailable case most of all, because isRetryable says yes to it and a
      // caller may well loop.
      const saved: StoredTaskGrant[] = [];
      const store: TaskGrantStore = {
        save: async (record) => {
          saved.push(record);
        },
        load: async () => undefined,
        remove: async () => undefined,
      };
      plane.nextFailure = { status, body: { error, error_description: 'Not this person.' } };

      const thrown = await client({ grantStore: store })
        .exchange({ subjectToken: 't', resource: 'https://jira.internal', scope: 'jira:read' })
        .catch((e: unknown) => e);

      expect(thrown).toBeInstanceOf(type);
      expect(saved).toEqual([]);
      expect(vi.getTimerCount()).toBe(0);

      // And nothing is retried on its own: the one request that was made is the one that failed.
      await settle(plane);
      expect(plane.requests).toHaveLength(1);
      expect(vi.getTimerCount()).toBe(0);

      // Both assertions above pass by themselves if the store was never wired or a session never
      // schedules anything, so prove the instruments on the same store: one that succeeds does
      // save a grant and does leave a timer running.
      const session = await client({ grantStore: store }).exchange({
        subjectToken: 't',
        resource: 'https://jira.internal',
        scope: 'jira:read',
      });
      expect(saved).toHaveLength(1);
      expect(vi.getTimerCount()).toBe(1);
      session.stop();
    },
  );

  it('refuses an exchange with missing inputs before touching the network', async () => {
    await expect(
      client().exchange({ subjectToken: '', resource: 'r', scope: 's' }),
    ).rejects.toThrow('subjectToken is required');
    await expect(
      client().exchange({ subjectToken: 't', resource: '', scope: 's' }),
    ).rejects.toThrow('resource is required');
    await expect(
      client().exchange({ subjectToken: 't', resource: 'r', scope: '' }),
    ).rejects.toThrow('scope is required');
    expect(plane.requests).toHaveLength(0);
  });

  describe('what it sends and what it accepts', () => {
    const exchange = (c = client()) =>
      c.exchange({
        subjectToken: 'user-token',
        resource: 'https://jira.internal',
        scope: 'jira:read jira:comment',
      });

    it('follows no redirect on any request to the control plane', async () => {
      const c = client();
      const session = await exchange(c);
      await session.refresh();
      await session.revoke();

      // Discovery, the exchange, the refresh and the revocation: each carries a user's token, a
      // grant or a signed assertion, or says where they go, so a 307 is never followed.
      expect(plane.followed).toEqual([]);
      expect(plane.requests).toHaveLength(3);
    });

    it.each([
      [
        'a token type other than Bearer',
        (b: Record<string, unknown>) => ({ ...b, token_type: 'DPoP' }),
      ],
      ['no token type', (b: Record<string, unknown>) => ({ ...b, token_type: undefined })],
      [
        'no issued token type on an exchange',
        (b: Record<string, unknown>) => ({ ...b, issued_token_type: undefined }),
      ],
      [
        'an issued token type other than an access token',
        (b: Record<string, unknown>) => ({
          ...b,
          issued_token_type: 'urn:ietf:params:oauth:token-type:id_token',
        }),
      ],
      ['an empty scope', (b: Record<string, unknown>) => ({ ...b, scope: '' })],
    ])('refuses an exchange answered with %s', async (_, change) => {
      plane.nextTokenChange = change;

      await expect(exchange()).rejects.toBeInstanceOf(TransportError);
    });

    it('reads the token type without regard to case', async () => {
      plane.nextTokenChange = (b) => ({ ...b, token_type: 'bearer' });

      const session = await exchange();

      expect(session.taskId).toBe('task_1');
      session.stop();
    });

    it('accepts a refresh that does not say what it issued, but not one that says something else', async () => {
      const session = await exchange();

      plane.nextTokenChange = (b) => ({ ...b, issued_token_type: undefined });
      await expect(session.refresh()).resolves.toBeDefined();

      plane.nextTokenChange = (b) => ({
        ...b,
        issued_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      });
      await expect(session.refresh()).rejects.toBeInstanceOf(TransportError);
      session.stop();
    });

    it('keeps its own task when a refresh answers for another one', async () => {
      const session = await exchange();
      const before = await session.accessToken();

      plane.nextTokenChange = (b) => ({ ...b, task_id: 'task_someone_else' });
      await expect(session.refresh()).rejects.toBeInstanceOf(TransportError);

      expect(session.taskId).toBe('task_1');
      expect(await session.accessToken()).toBe(before);
      session.stop();
    });

    it('does not file one task under another when resuming', async () => {
      const store = new MemoryTaskGrantStore();
      const first = await exchange(client({ grantStore: store }));
      first.stop();

      plane.nextTokenChange = (b) => ({ ...b, task_id: 'task_someone_else' });
      await expect(client({ grantStore: store }).resume('task_1')).rejects.toBeInstanceOf(
        TransportError,
      );

      expect(await store.load('task_someone_else')).toBeUndefined();
      expect((await store.load('task_1'))?.taskId).toBe('task_1');
    });

    it.each([
      ['http://localhost:5100', true],
      ['http://127.0.0.1:5100', true],
      ['http://[::1]:5100', true],
      ['http://subactid.internal.example.com', false],
      ['http://192.168.1.10:5100', false],
    ])('accepts the http issuer %s only on a loopback host', (url, accepted) => {
      const make = () => client({ issuer: url });
      if (accepted) {
        expect(make).not.toThrow();
      } else {
        expect(make).toThrow(/https/);
      }
    });

    it.each([[0], [-1], [1.5], [2 ** 31], [Number.NaN], [Number.POSITIVE_INFINITY]])(
      'refuses a timeoutMs of %s',
      (timeoutMs) => {
        expect(() => client({ timeoutMs })).toThrow(
          'timeoutMs must be a whole number from 1 to 2147483647.',
        );
      },
    );

    it('refuses an issuer with a user name or password in it', () => {
      expect(() => client({ issuer: 'https://user:secret@subactid.example.com' })).toThrow(
        'issuer must not contain a user name or password.',
      );
    });

    it('accepts any http issuer when allowInsecureHttp says so', () => {
      expect(() =>
        client({ issuer: 'http://subactid.internal.example.com', allowInsecureHttp: true }),
      ).not.toThrow();
    });
  });

  it('gives up on a control plane that does not answer within timeoutMs', async () => {
    const hanging: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
      });
    const c = client({ fetch: hanging, timeoutMs: 20 });
    await expect(c.discover()).rejects.toBeInstanceOf(TransportError);
  });

  it('calls the global fetch with the global object as this, as browsers and Workers require', async () => {
    const seen: unknown[] = [];
    vi.stubGlobal('fetch', function (this: unknown, input: RequestInfo | URL, init?: RequestInit) {
      seen.push(this);
      return plane.fetch(input, init);
    });
    try {
      // No fetch option: the client falls back to the global one.
      const c = new SubactIdClient({
        issuer,
        agentId: 'jira-triage',
        kid: 'k1',
        privateKey: rsaPem,
      });
      await c.discover();
    } finally {
      vi.unstubAllGlobals();
    }

    expect(seen).toEqual([globalThis]);
  });
});
