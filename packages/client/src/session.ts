import {
  isRetryable,
  isTaskOver,
  SessionStoppedError,
  SubactIdError,
  SlowDownError,
  TaskEndedError,
  TemporarilyUnavailableError,
  TransportError,
} from './errors.js';
import { decodeJwtPayload } from './encoding.js';
import type { StoredTaskGrant, TaskGrantStore } from './store.js';
import type { TokenResponse } from './types.js';

/** Fraction of a token's lifetime after which the session refreshes it. */
export const refreshFraction = 0.6;

/** A token is not handed out with less than this many milliseconds left; it is refreshed first. */
export const minimumRemainingMs = 5_000;

/** Longest wait between retries of a refresh that failed for a reason worth retrying. */
export const maxRetryDelayMs = 60_000;

/** The longest delay `setTimeout` honours; a timer set beyond it fires at once. */
const maxTimerMs = 2_147_483_647;

export interface TaskSessionOptions {
  /** Refreshes the task; called by the session with the scope it holds. */
  refresh: (grant: string, resource: string, scope: string) => Promise<TokenResponse>;
  /** Revokes the task by its grant; called by `revoke()`. */
  revoke: (grant: string) => Promise<void>;
  store: TaskGrantStore;
  now: () => number;
  /** Called after every successful refresh. */
  onRefresh?: ((token: TokenResponse) => void) | undefined;
  /** Called when a refresh fails, and when the store fails to save or remove a grant. */
  onError?: ((error: unknown) => void) | undefined;
  /** Whether the timer should keep the process alive; defaults to no. */
  keepAlive?: boolean | undefined;
}

/**
 * One task: the current token, the grant that renews it, and a timer that renews it at 60% of
 * its lifetime so a caller never holds a token that is about to expire. `accessToken()` is the
 * only thing a caller needs: it returns a token with life left in it, refreshing first if the
 * timer has not got there yet.
 *
 * A refresh the control plane could not answer is retried with a growing wait, until the task
 * itself expires. Any other refusal ends the session, because asking again only adds denial
 * records to the audit ledger. Only a refusal that says the task is over (`isTaskOver`) removes
 * the grant from the store: the task was revoked, has expired or is ending, its grant is gone,
 * or the control plane answered `access_denied` without a `reason`. Any other refusal leaves
 * the task alive: an `access_denied` for a disabled agent or a disabled human, who can be
 * enabled again; the agent's assertion refused over a skewed clock or a key the control plane
 * has not fetched; a scope or an audience refused. The grant stays in
 * the store, so `SubactIdClient.resume()` can pick the task up again once the cause is fixed.
 */
export class TaskSession {
  readonly taskId: string;
  readonly resource: string;
  readonly taskExpiresAt: Date;

  #token: TokenResponse;
  #grant: string;
  /** When the current token expires, by this side's clock; see `tokenExpiry`. */
  private tokenExpiresAt: number;
  /** The current token's `exp` claim in milliseconds, on the control plane's clock, if readable. */
  private tokenExp: number | undefined;
  private currentScope: string;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private inFlight: Promise<TokenResponse> | undefined;
  /** The scope `inFlight` asked for. */
  private inFlightScope: string | undefined;
  private failures = 0;
  /** The wait the control plane asked for on the last failure, when it was rate limiting; 0 otherwise. */
  private retryAfterMs = 0;
  private ended: Error | undefined;
  /** A revocation on the wire. Refreshes wait for it, so none can save a grant it is ending. */
  private revoking: Promise<void> | undefined;
  /** Set once the task is over and its grant removed from the store, so nothing saves it back. */
  private taskOver = false;
  readonly #options: TaskSessionOptions;

  /**
   * @param token The exchange's answer.
   * @param resource The audience the task was issued for.
   * @param requestedAt When the exchange was sent, in milliseconds; `expires_in` counts from
   *   there, never from when the answer arrived, and the token's `exp` can only bring that
   *   earlier.
   */
  constructor(
    token: TokenResponse,
    resource: string,
    requestedAt: number,
    options: TaskSessionOptions,
  ) {
    this.#options = options;
    this.taskId = token.task_id;
    this.resource = resource;
    this.taskExpiresAt = new Date(token.task_expires_at);
    this.#token = token;
    this.#grant = token.refresh_token;
    this.currentScope = token.scope;
    this.tokenExp = readExp(token);
    this.tokenExpiresAt = tokenExpiry(token, requestedAt, this.tokenExp);
    this.schedule();
  }

  /**
   * What the session is, without its credentials: the token and the grant are never part of
   * it. Also keeps `JSON.stringify` from walking into the refresh timer.
   */
  toJSON(): {
    taskId: string;
    resource: string;
    scope: string;
    taskExpiresAt: string;
    expiresAt: string;
    isEnded: boolean;
  } {
    return {
      taskId: this.taskId,
      resource: this.resource,
      scope: this.currentScope,
      taskExpiresAt: this.taskExpiresAt.toISOString(),
      expiresAt: this.expiresAt.toISOString(),
      isEnded: this.isEnded,
    };
  }

  /** The scope the task currently holds. */
  get scope(): string {
    return this.currentScope;
  }

  /**
   * When the current token stops being usable: its own expiry (`expires_in`, cut to its `exp`
   * claim), or the end of the task if that comes first. No token outlives its task (spec
   * section 3), so at the end of a task the two are the same, give or take the second `exp` is
   * rounded to, and `expires_in` decides everywhere else. Taking the earlier of the two means
   * this session hands out no token past the end of its task, whatever `expires_in` says; the
   * session ends at the task instead.
   */
  get expiresAt(): Date {
    return new Date(Math.min(this.tokenExpiresAt, this.taskExpiresAt.getTime()));
  }

  /** Whether the session has ended: stopped, refused, or the task is over. */
  get isEnded(): boolean {
    return this.ended !== undefined;
  }

  /**
   * A token with at least a few seconds of life left, refreshed first if needed. When even a
   * fresh token has less than that left, it is not handed out. If that token already lasts to the
   * end of the task, or the task has almost no time left, the task is over and the session ends
   * as it does when too little of the task is left to ask. Otherwise the answer was slow, and a
   * retryable `TransportError` is thrown with the session left as it was.
   */
  async accessToken(): Promise<string> {
    this.throwIfEnded();
    if (this.remainingMs() < minimumRemainingMs) {
      await this.refresh();
      if (this.remainingMs() < minimumRemainingMs) {
        // Only the task running out ends the session. A fresh token can also arrive short because
        // the answer was slow, or this process was paused while it was on the wire; that task is
        // alive, so the caller is told to try again rather than the grant being dropped. The
        // second allowed is the one the control plane's whole-second `exp` can take off. A token
        // that already lasts to the task's end is judged on the control plane's clock alone, so a
        // clock running behind here cannot turn the task's last seconds into a retry loop.
        if (
          this.lastsTask() ||
          this.taskExpiresAt.getTime() - this.#options.now() < minimumRemainingMs + 1_000
        ) {
          await this.expire();
        }
        throw new TransportError(
          'The refreshed token arrived with too little life left to hand out; try again.',
        );
      }
    }
    return this.#token.access_token;
  }

  /**
   * Refreshes now. `scope`, when given, must be a subset of what this session currently holds,
   * and becomes what it holds from then on: narrowing here is one-way.
   *
   * Both this session and the control plane keep a narrowing (spec section 5). The control
   * plane checks a refresh against the scope of the grant's last successful refresh, so once a
   * refresh has narrowed the task, a later refresh for more is `invalid_scope` whoever sends
   * it. This session refuses such a request before it is sent, so no denial record lands in
   * the ledger for trying, and it saves the narrower scope to the store before asking for it,
   * so a store that fails afterwards cannot leave a resume asking for what the grant has lost.
   * A narrowing the store refuses to save is reported to `onError` and thrown, and nothing is
   * sent.
   *
   * A refresh already in flight is shared when what it asks for is within what this one asks
   * for, so its answer is never wider than this caller wanted. Otherwise this one waits for it
   * and tries again, however many others are waiting too, and runs with its own narrower scope.
   */
  async refresh(scope?: string): Promise<TokenResponse> {
    for (;;) {
      if (this.revoking !== undefined) {
        // Ended if it succeeds, and as it was if it fails; either way, judged again below.
        await this.revoking.catch(() => undefined);
        continue;
      }
      this.throwIfEnded();
      // Judged against what the task holds now: a refresh this one waited for may have narrowed
      // it, and a scope the task has just lost must not go back out on the wire.
      const requested =
        scope === undefined ? this.currentScope : narrowed(this.currentScope, scope);
      const inFlight = this.inFlight;
      if (inFlight === undefined) {
        const started = this.doRefresh(requested).finally(() => {
          this.inFlight = undefined;
          this.inFlightScope = undefined;
        });
        this.inFlight = started;
        this.inFlightScope = requested;
        return started;
      }
      if (isWithin(this.inFlightScope ?? '', requested)) {
        return inFlight;
      }
      await inFlight.catch(() => undefined);
    }
  }

  /**
   * Ends the task at the control plane (spec section 6) and then this session: the grant and
   * every token under the task are refused by introspection at once, and by local validation
   * once they expire. A control plane that refused, or could not be asked, leaves the session as
   * it was and the error is thrown, so the caller can try again.
   */
  async revoke(): Promise<void> {
    if (this.revoking !== undefined) {
      return this.revoking;
    }
    const revoking = this.doRevoke().finally(() => {
      this.revoking = undefined;
    });
    this.revoking = revoking;
    return revoking;
  }

  private async doRevoke(): Promise<void> {
    // The grant in hand is the one to revoke, so a refresh under way is let finish first. None
    // starts after this point: `refresh()` waits while a revocation is under way, so no refresh
    // can save a grant to the store after the revocation has removed it.
    while (this.inFlight !== undefined) {
      await this.inFlight.catch(() => undefined);
    }
    // A refusal leaves the session as it was, timer included, so the caller can try again.
    await this.#options.revoke(this.#grant);
    await this.end(new TaskEndedError('The task was revoked.'), true);
  }

  /**
   * Stops the timer. The task stays alive at the control plane; the grant stays in the store.
   * From then on `accessToken()` and `refresh()` throw `SessionStoppedError`, which `isTaskOver`
   * does not count as the end of the task. A session that had already ended keeps its error.
   */
  stop(): void {
    this.clearTimer();
    this.ended ??= new SessionStoppedError('The session was stopped.');
  }

  /** What a store needs to resume this task later. */
  toStored(): StoredTaskGrant {
    return {
      taskId: this.taskId,
      grant: this.#grant,
      resource: this.resource,
      scope: this.currentScope,
      taskExpiresAt: this.#token.task_expires_at,
    };
  }

  private throwIfEnded(): void {
    if (this.ended !== undefined) {
      throw this.ended;
    }
  }

  private async doRefresh(scope: string): Promise<TokenResponse> {
    this.clearTimer();
    // A task with less than the minimum left cannot yield a token worth handing out: it is over.
    if (this.taskExpiresAt.getTime() - this.#options.now() < minimumRemainingMs) {
      await this.expire();
    }

    // A narrowing is saved before it is asked for. Once the control plane has kept it, a store
    // still holding the wider scope would have every resume refused as `invalid_scope`, and the
    // task stranded until it expires. Saving it first is safe whatever the answer: a scope only
    // narrows, and the control plane refreshes a grant for less than it holds.
    if (narrowsScope(this.currentScope, scope)) {
      try {
        await this.#options.store.save({ ...this.toStored(), scope });
      } catch (error) {
        this.#options.onError?.(error);
        this.schedule();
        throw error;
      }
      // Kept from here whatever the answer: the control plane may have kept the narrowing even
      // when its answer is lost, and a later refresh for the wider scope would then be
      // `invalid_scope`, ending the session. The store already holds it.
      this.currentScope = scope;
    }

    // Counted from before the request, so a slow answer can only shorten what this side believes it has.
    const requestedAt = this.#options.now();
    let token: TokenResponse;
    try {
      token = await this.#options.refresh(this.#grant, this.resource, scope);
      // A grant renews its own task. An answer for another one is not this session's to keep:
      // refused like any answer that cannot be acted on, and retried.
      if (token.task_id !== this.taskId) {
        throw new TransportError('The refresh answered for a different task.');
      }
    } catch (error) {
      this.#options.onError?.(error);
      if (isRetryable(error)) {
        this.failures++;
        // The interval the control plane asked for, on a rate limit or a 503 at capacity or
        // with its database away, is a floor under the backoff rather than a replacement for it.
        this.retryAfterMs =
          (error instanceof SlowDownError || error instanceof TemporarilyUnavailableError) &&
          error.retryAfterSeconds !== undefined
            ? error.retryAfterSeconds * 1000
            : 0;
        this.schedule();
      } else {
        await this.end(
          error instanceof Error
            ? error
            : new SubactIdError('The refresh failed.', { cause: error }),
          isTaskOver(error),
        );
      }
      throw error;
    }

    // A task revoked or expired while this refresh was on the wire stays over: its grant was
    // removed from the store, and an answer that crossed the revocation must not put it back.
    if (this.taskOver) {
      throw this.ended ?? new TaskEndedError('The task has ended.');
    }

    // From here the token is the session's whatever the store or the callback do.
    this.#token = token;
    this.#grant = token.refresh_token;
    this.currentScope = token.scope;
    this.tokenExp = readExp(token);
    this.tokenExpiresAt = tokenExpiry(token, requestedAt, this.tokenExp);
    this.failures = 0;
    this.retryAfterMs = 0;
    try {
      await this.#options.store.save(this.toStored());
    } catch (error) {
      this.#options.onError?.(error);
    }
    this.#options.onRefresh?.(token);
    this.schedule();
    return token;
  }

  /** How long the current token has left, by this side's clock. */
  private remainingMs(): number {
    return this.expiresAt.getTime() - this.#options.now();
  }

  /**
   * Ends the session because too little of the task is left to hand out a token: reported to
   * `onError`, the grant removed from the store, and the error thrown.
   */
  private async expire(): Promise<never> {
    // Callers sharing one refresh all find it too short; the first ends the session.
    this.throwIfEnded();
    const ended = new TaskEndedError('The task has expired.');
    this.#options.onError?.(ended);
    await this.end(ended, true);
    throw ended;
  }

  /**
   * Stops the session for good. `taskIsOver` removes the grant from the store as well; it is
   * only true when the task is over (`isTaskOver`), never on a refusal that can be lifted while
   * the task lives on: for a live task the grant is the only thing that can resume it.
   */
  private async end(error: Error, taskIsOver: boolean): Promise<void> {
    this.clearTimer();
    this.ended = error;
    if (!taskIsOver) {
      return;
    }
    this.taskOver = true;
    try {
      await this.#options.store.remove(this.taskId);
    } catch (storeError) {
      this.#options.onError?.(storeError);
    }
  }

  private schedule(): void {
    if (this.ended !== undefined) {
      return;
    }
    // A token that already lasts until the end of the task cannot be bettered; nothing to schedule.
    if (this.failures === 0 && this.lastsTask()) {
      return;
    }
    const now = this.#options.now();
    const remaining = this.expiresAt.getTime() - now;
    let delay: number;
    if (this.failures === 0) {
      // A fresh token waits until 60% of its life is gone, but never so long that less than the minimum is left.
      delay = Math.min(remaining * refreshFraction, remaining - minimumRemainingMs);
    } else {
      // A failed refresh is tried again with a growing wait, or after the wait the control plane
      // asked for when that is longer, and never past the end of the task.
      delay = Math.min(
        Math.max(Math.min(1_000 * 2 ** (this.failures - 1), maxRetryDelayMs), this.retryAfterMs),
        this.taskExpiresAt.getTime() - now,
      );
    }
    this.timer = setTimeout(
      () => {
        this.refresh().catch(() => {
          // Reported through onError; the next tick, or the next accessToken(), tries again.
        });
      },
      // setTimeout takes at most 2^31 - 1 ms and fires at once for anything longer, which a large
      // Retry-After on a long task would otherwise turn into a refresh loop.
      Math.min(Math.max(1_000, delay), maxTimerMs),
    );
    if (!this.#options.keepAlive) {
      this.timer.unref?.();
    }
  }

  /**
   * Whether the current token already lasts until the end of the task, so no refresh can give a
   * longer one. The control plane cuts a token's `exp` to the task's end in whole seconds, while
   * `task_expires_at` keeps its fraction of a second, so the last token of a task ends up to a
   * second before the task does, so an exact comparison reads every last token as falling
   * short. Allowing that second is what keeps the last token from being refreshed again and
   * again for less each time until the task runs out.
   *
   * `exp` and `task_expires_at` are both on the control plane's clock, so comparing them needs
   * no allowance for this side's clock or for how long the answer took. Only an `exp` within the
   * task's last second counts: one later than that is not one the control plane issues (a token
   * never outlives its task), such as an `exp` written in milliseconds, and is not trusted to
   * stop the refreshes. A token without such an `exp` is judged by its counted expiry instead,
   * allowing the second the rounding takes off. Either way this only decides whether a refresh
   * is scheduled: `accessToken()` still refreshes, or ends the session, before it hands out a
   * token with too little left.
   */
  private lastsTask(): boolean {
    const taskEnd = this.taskExpiresAt.getTime();
    const taskEndSecond = Math.floor(taskEnd / 1000) * 1000;
    if (
      this.tokenExp !== undefined &&
      this.tokenExp >= taskEndSecond &&
      this.tokenExp <= taskEndSecond + 1000
    ) {
      return true;
    }
    return this.tokenExpiresAt >= taskEnd - 1000;
  }

  private clearTimer(): void {
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }
}

/**
 * When `token` expires, by this side's clock: `expires_in` counted from `requestedAt`, cut to
 * the token's own `exp` where that is earlier.
 *
 * The control plane writes `expires_in` as `exp` less its clock truncated to the second, so
 * counting it from a `requestedAt` that is part way into a second overstates the token's life
 * by up to a second. `exp` does not, and is read off the token without verifying it: it only
 * ever shortens what this side believes, never lengthens it. A token with no readable numeric
 * `exp` is counted from `expires_in` alone.
 *
 * `exp` is on the control plane's clock, though, and `expires_in` is not on any. An agent whose
 * clock runs ahead reads `exp` as earlier than it is, and near the end of a task, where tokens
 * are short, that reads every token as already spent. So `exp` takes off at most the second the
 * rounding can add, and a clock running ahead does not make the session refresh on every call.
 */
function tokenExpiry(token: TokenResponse, requestedAt: number, exp: number | undefined): number {
  const counted = requestedAt + token.expires_in * 1000;
  if (exp === undefined) {
    return counted;
  }
  return Math.min(counted, Math.max(exp, counted - 1000));
}

/**
 * The token's `exp` claim in milliseconds, read without verifying it, or `undefined` when the
 * token is not a JWT or its `exp` is not a finite number. See `tokenExpiry` for what it is
 * trusted with, and `lastsTask`.
 */
function readExp(token: TokenResponse): number | undefined {
  let exp: unknown;
  try {
    exp = decodeJwtPayload(token.access_token)['exp'];
  } catch {
    return undefined;
  }
  return typeof exp === 'number' && Number.isFinite(exp) ? exp * 1000 : undefined;
}

/** Whether `requested`, already a subset of `held`, leaves out a scope `held` has. */
function narrowsScope(held: string, requested: string): boolean {
  return (
    new Set(requested.split(' ').filter(Boolean)).size <
    new Set(held.split(' ').filter(Boolean)).size
  );
}

/** Whether every scope in `inner` is also in `outer`. */
function isWithin(inner: string, outer: string): boolean {
  const outerSet = new Set(outer.split(' ').filter(Boolean));
  return inner
    .split(' ')
    .filter(Boolean)
    .every((s) => outerSet.has(s));
}

/** What this session may still ask for: a subset of what it holds, never more. See `refresh`. */
function narrowed(held: string, requested: string): string {
  const heldSet = new Set(held.split(' ').filter(Boolean));
  const wanted = requested.split(' ').filter(Boolean);
  if (wanted.length === 0) {
    throw new SubactIdError('scope must name at least one scope.');
  }
  for (const scope of wanted) {
    if (!heldSet.has(scope)) {
      throw new SubactIdError(
        'This session has narrowed its scope; it cannot be refreshed for a scope it no longer holds.',
      );
    }
  }
  return wanted.join(' ');
}
