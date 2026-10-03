/**
 * The errors this client throws. Every failure is one of these, so a caller can `instanceof`
 * on the case it handles and let the rest propagate. No error ever carries a token, a grant or
 * a key: the message names what went wrong, not what was sent.
 */
export class SubactIdError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** The endpoint could not be reached, did not answer, or answered something that is not what the contract says. */
export class TransportError extends SubactIdError {}

/** The task is over: it expired or was revoked. Nothing about it can be refreshed again. */
export class TaskEndedError extends SubactIdError {}

/**
 * The session was stopped by its own `stop()`. The task is alive at the control plane and its
 * grant is still in the store, so `SubactIdClient.resume()` can carry it on.
 *
 * Deliberately not a `TaskEndedError`: code that catches that, or asks `isTaskOver`, drops the
 * grant, and this task is alive. Code that means "this session gives no more tokens", whatever
 * the cause, checks `session.isEnded` instead.
 */
export class SessionStoppedError extends SubactIdError {}

/** The control plane answered an OAuth error body (RFC 6749 section 5.2). */
export class OAuthError extends SubactIdError {
  /** The `error` code. */
  readonly error: string;
  /** The `error_description`, always present on Subact ID's answers. */
  readonly errorDescription: string;
  /** The HTTP status. */
  readonly status: number;

  constructor(error: string, errorDescription: string, status: number) {
    super(`${error}: ${errorDescription}`);
    this.error = error;
    this.errorDescription = errorDescription;
    this.status = status;
  }
}

/** The request was malformed: a missing or repeated parameter. A bug in the caller, not a state to retry. */
export class InvalidRequestError extends OAuthError {}

/** The agent's assertion was refused: wrong key, replayed `jti`, unknown agent, bad audience. */
export class InvalidClientError extends OAuthError {}

/**
 * The subject token or the task grant was refused: expired, unknown, from an untrusted issuer,
 * already revoked, or — for a subject token — carrying no usable value for the claim the control
 * plane keys people by, which is what a block of the person acts on, so no task is issued for it.
 */
export class InvalidGrantError extends OAuthError {}

/** No requested scope was available, or a refresh asked for more than the task holds. */
export class InvalidScopeError extends OAuthError {}

/** The audience is not one the agent may request, or is not the task's. */
export class InvalidTargetError extends OAuthError {}

/**
 * The control plane does not act on this request: the human it is for is one it does not act
 * for — blocked, disabled or gone — the agent is disabled, the task was revoked or has expired,
 * too little of it is left to issue a token for (`task_ending`), or the delegation depth was
 * exceeded.
 *
 * It arrives from both call sites, and means a different thing at each. On an exchange no task
 * was ever created: a subject token that verifies is not on its own a person the control plane
 * still acts for, since it may have been issued before they were blocked. On a refresh it is
 * either the end of the task or a refusal that can be lifted while the task lives on — an
 * agent or a human enabled again — and `reason` says which (see `isTaskOver`). Either way
 * nothing this client can do changes the answer, so it is not a retry.
 */
export class AccessDeniedError extends OAuthError {
  /**
   * The machine-readable reason the control plane gave, the same one its audit record carries:
   * `task_revoked`, `agent_disabled`, `sponsor_disabled` and so on. Absent when the answer had
   * none, or had one that is not a string; either way `isTaskOver` counts it as the end of the
   * task.
   */
  declare readonly reason?: string;

  constructor(error: string, errorDescription: string, status: number, reason?: string) {
    super(error, errorDescription, status);
    if (reason !== undefined) {
      this.reason = reason;
    }
  }
}

/** The grant type is not one the control plane supports. */
export class UnsupportedGrantTypeError extends OAuthError {}

/**
 * A revocation named a `token_type_hint` the server does not support (RFC 7009 section 2.2.1).
 * Subact ID v0.1 does not produce it: its revocation endpoint ignores a hint it does not
 * recognise (spec section 6). It is kept for other RFC 7009 servers.
 */
export class UnsupportedTokenTypeError extends OAuthError {}

/**
 * The control plane could not make the decision now (spec section 8, answered as `503`): it could
 * not reach something the decision depends on — the identity provider's keys, the agent's keys,
 * or, where it polls for it, the provider's answer about the human — its own database could not
 * answer, or the instance is at capacity. It is never a yes. Retry later, and not before
 * `retryAfterSeconds` when the answer named one; nothing changed, and on an exchange nothing was
 * created.
 */
export class TemporarilyUnavailableError extends OAuthError {
  /** The answer's `Retry-After`, in whole seconds, when it carried one this client could read. */
  readonly retryAfterSeconds: number | undefined;

  constructor(error: string, errorDescription: string, status: number, retryAfterSeconds?: number) {
    super(error, errorDescription, status);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * The control plane is rate limiting this source (spec section 8, answered as `429`). Nothing
 * about the task changed; retry, and not before `retryAfterSeconds` when the answer named one.
 */
export class SlowDownError extends OAuthError {
  /** The answer's `Retry-After`, in whole seconds, when it carried one this client could read. */
  readonly retryAfterSeconds: number | undefined;

  constructor(error: string, errorDescription: string, status: number, retryAfterSeconds?: number) {
    super(error, errorDescription, status);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * An `error` code this client does not know, or an answer with no `error` at all — a problem
 * document (RFC 9457) for a body the control plane could not read, or a `500`. `error` is
 * `unknown` when the answer named none. Retryable only when its status says the server could
 * not answer now; see `isRetryable`.
 */
export class UnknownOAuthError extends OAuthError {}

const byCode: Record<
  string,
  new (error: string, description: string, status: number) => OAuthError
> = {
  invalid_request: InvalidRequestError,
  invalid_client: InvalidClientError,
  invalid_grant: InvalidGrantError,
  invalid_scope: InvalidScopeError,
  invalid_target: InvalidTargetError,
  access_denied: AccessDeniedError,
  unsupported_grant_type: UnsupportedGrantTypeError,
  unsupported_token_type: UnsupportedTokenTypeError,
  temporarily_unavailable: TemporarilyUnavailableError,
};

/**
 * Builds the typed error for an OAuth error body; `retryAfterSeconds` is the answer's
 * `Retry-After`, if any, and `reason` the body's `reason`, kept on an `access_denied` only.
 */
export function oauthError(
  error: string,
  description: string,
  status: number,
  retryAfterSeconds?: number,
  reason?: string,
): OAuthError {
  if (error === 'slow_down') {
    return new SlowDownError(error, description, status, retryAfterSeconds);
  }
  if (error === 'temporarily_unavailable') {
    return new TemporarilyUnavailableError(error, description, status, retryAfterSeconds);
  }
  if (error === 'access_denied') {
    return new AccessDeniedError(error, description, status, reason);
  }
  const Type = byCode[error] ?? UnknownOAuthError;
  return new Type(error, description, status);
}

/**
 * The `reason`s of an `access_denied` on a refresh after which the grant is worth nothing:
 * nothing done to the agent or the human makes it refresh again. They are the control plane's
 * audit reasons:
 *
 * - `task_revoked`: the task was revoked — by the agent, an operator, or a block of its human,
 *   which ends every task the human has.
 * - `task_expired`: the task has expired.
 * - `task_ending`: less of it is left than a token is worth issuing for.
 * - `delegation_chain_unavailable`: a delegated task cannot be refreshed in v0.1. The task is not
 *   over (spec section 8), but no retry of this grant succeeds, so it is dropped all the same.
 * - `delegation_depth_exceeded`: not produced in v0.1. It names a task whose depth is greater
 *   than the agent's `max_delegation_depth`, a refusal no retry of this grant gets past (spec
 *   section 8), so it is treated as the end of the task.
 * - `invalid_delegation_depth`: not produced in v0.1. It names a task whose recorded delegation
 *   depth is below 1, which no token is issued under (spec section 8), so it is treated as the
 *   end of the task.
 *
 * A reason this client does not know counts as one of these, as spec section 8 asks: the only
 * refusals that leave the grant worth keeping are the ones listed in `liftableReasons`. The list
 * is frozen, and is for reading: `isTaskOver` does not consult it.
 */
export const taskOverReasons: readonly string[] = Object.freeze([
  'task_revoked',
  'task_expired',
  'task_ending',
  'delegation_chain_unavailable',
  'delegation_depth_exceeded',
  'invalid_delegation_depth',
]);

/**
 * The `reason`s of an `access_denied` that can be lifted while the task is still alive, so the
 * grant is kept and the task can be resumed once they are:
 *
 * - `agent_disabled`: an operator disabled the agent, and may enable it again.
 * - `sponsor_disabled`, `sponsor_not_found`: the identity provider does not confirm the human.
 *   A block placed at the control plane revokes the human's tasks, which then answer
 *   `task_revoked` instead.
 *
 * The list is frozen. `isTaskOver` and `isLiftableReason` judge by a private copy of it.
 */
export const liftableReasons: readonly string[] = Object.freeze([
  'agent_disabled',
  'sponsor_disabled',
  'sponsor_not_found',
]);

/**
 * What `isTaskOver` judges by. Its own copy, so nothing done to the exported list at run time
 * makes it keep the grant of a task that is over; the exported lists are frozen as well.
 */
const liftable: ReadonlySet<string> = new Set(liftableReasons);

/**
 * Whether an `access_denied` `reason` is one of `liftableReasons`: a refusal that can be lifted
 * while the task lives on, so its grant is worth keeping. Every other reason, including one this
 * client does not know, is not.
 */
export function isLiftableReason(reason: string): boolean {
  return liftable.has(reason);
}

/**
 * Whether the refusal means the task is finished, so a grant held for it is worth nothing and a
 * store keeping one should drop it. The session and `resume` drop the grant on exactly these.
 *
 * - `AccessDeniedError`, unless its `reason` is one of `liftableReasons` — a disabled agent or
 *   human, which may be enabled again while the task is alive. One with no `reason`, or a reason
 *   this client does not know, is treated as the end of the task.
 * - `InvalidGrantError`: the grant is unknown, revoked or expired.
 * - `TaskEndedError`: the task expired or was revoked here.
 *
 * Not `SessionStoppedError`: a session stopped by its caller leaves the task alive.
 */
export function isTaskOver(error: unknown): boolean {
  if (error instanceof AccessDeniedError) {
    return error.reason === undefined || !liftable.has(error.reason);
  }
  return error instanceof InvalidGrantError || error instanceof TaskEndedError;
}

/**
 * Whether the refusal is one that nothing this client can do changes, so the request is not to
 * be presented again as it is: every `isTaskOver` case, and every `access_denied`, since a
 * disabled agent or human stays refused until someone outside this client enables them. On an
 * exchange there is no task, and it means this subject token does not produce one.
 *
 * Not every refusal a retry cannot fix: a scope or an audience the agent may not have is refused
 * for good too, and says nothing about the task. Terminal does not mean the grant is worthless:
 * use `isTaskOver` for that, and `resume` the task later when it is not.
 */
export function isTerminal(error: unknown): boolean {
  return error instanceof AccessDeniedError || isTaskOver(error);
}

/**
 * Whether the same request, tried again later, can succeed. Only a control plane that could not
 * answer, could not be reached, or asked this source to slow down is worth retrying; every other
 * refusal is a fact about the human, the task, the agent or the request, and a retry only turns
 * it into another denial record.
 *
 * An answer with no `error` this client knows is judged by its status. A `5xx`, a `429` or a
 * `408` is the server or something in front of it not answering now. Any other `4xx` is a
 * refusal of the request itself — the control plane answers a body it cannot read, or one too
 * large, with a problem document and a `400` or `413` — and sending the same request again gets
 * the same answer.
 *
 * Discovery is the exception. It carries no credential, so no `4xx` on it is a decision about
 * this agent or the human it acts for. Apart from a `429` `slow_down`, a `4xx` there comes from
 * something in front of the control plane, and discovery reports it as a `TransportError`,
 * which is retryable, so a refusal from in front of the control plane does not drop the grant of
 * a task that is still alive (see `retryLater` in `client.ts`).
 */
export function isRetryable(error: unknown): boolean {
  return (
    error instanceof TemporarilyUnavailableError ||
    error instanceof SlowDownError ||
    error instanceof TransportError ||
    (error instanceof UnknownOAuthError &&
      (error.status >= 500 || error.status === 429 || error.status === 408))
  );
}
