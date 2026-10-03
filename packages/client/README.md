# @subactid/client

The agent's side of [Subact ID](https://github.com/subactid/subactid), an agent identity and delegation
control plane.

The agent sends the human's token and its own signed assertion. The control plane answers with
a token for one task. In that token, `sub` is the human and the agent is in `act`. The scope is
at most what the human has, what the agent may use, and what the agent asked for.

## Install

```sh
npm install @subactid/client
```

The packages are not published to npm yet.
[CONTRIBUTING.md](../../CONTRIBUTING.md#trying-a-build-of-main) says how to install a development
build of `main`.

Node 22 or later. No runtime dependencies: the client uses WebCrypto and `fetch`.

ESM only: load it with `import`. `require()` of it works from Node 22.12, where Node can require
an ES module; on an older Node 22, use `import()`.

## Usage

```ts
// examples/agent/index.ts
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
```

In the example, `env` reads a required environment variable, `signingKey` reads the key's
algorithm (the client infers it from the key anyway; the example also honours
`SUBACTID_AGENT_ALG` to sign an RSA key with PS256), `start` resumes a task or starts one, and
`FileGrantStore` keeps task grants in owner-only files. `jira` is where the tool server
listens; the task's `resource` is its audience, such as `https://jira.internal`, which is a name
and not necessarily an address.

Before an agent can exchange, it has to be registered at the control plane
(`POST /admin/agents`) with the public half of its key. `SUBACTID_ISSUER` must be exactly the
issuer the control plane is configured with, for example `http://subactid:5100` for the
quickstart. See
[running the examples](https://github.com/subactid/subactid-sdk#against-the-quickstart).

## `SubactIdClient`

One client per agent. It can run any number of tasks.

### Options

| Option              | Default        | Meaning                                                                                                                                                 |
| ------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`            | required       | The control plane's issuer URL, exactly as the control plane is configured. `https`, or `http` on a loopback host. No user name or password.            |
| `allowInsecureHttp` | `false`        | Accept an `http` issuer that is not on a loopback host. Credentials then travel in the clear: never for production.                                     |
| `agentId`           | required       | The agent's registered id. Goes in the assertion's `iss` and `sub`.                                                                                     |
| `kid`               | required       | The `kid` of the agent's key in its published JWKS.                                                                                                     |
| `privateKey`        | required       | The agent's private key: a PKCS#8 PEM string or a WebCrypto `CryptoKey`.                                                                                |
| `algorithm`         | from the key   | `'RS256'`, `'PS256'` or `'ES256'`. Inferred from the key when omitted: RS256 for RSA, ES256 for EC P-256. Set `'PS256'` to sign an RSA key with PSS.    |
| `instance`          | none           | Which copy of the agent is running, up to 128 characters. Copied into `act.instance`. Not verified.                                                     |
| `lifetimeSeconds`   | `60`           | Lifetime of each assertion, whole seconds from 1 to 300.                                                                                                |
| `grantStore`        | memory         | A `TaskGrantStore`. See [Grant stores](#grant-stores).                                                                                                  |
| `onRefresh`         | none           | `(session, token) => void`, called after each successful refresh.                                                                                       |
| `onRefreshError`    | none           | `(session, error) => void`, called when a refresh fails or the store fails.                                                                             |
| `keepAlive`         | `false`        | Whether refresh timers keep the Node process alive.                                                                                                     |
| `timeoutMs`         | `10000`        | Time limit for each request to the control plane, answer included. A whole number from 1 to 2147483647. A request that runs over is a `TransportError`. |
| `fetch`             | global `fetch` | The `fetch` to use.                                                                                                                                     |
| `now`               | `Date.now`     | The clock, in milliseconds.                                                                                                                             |

The key never leaves the process. Each request to the control plane carries a new assertion
(`private_key_jwt`, RFC 7523).

### Methods

| Method                                        | Returns                    | Does                                                                                                                     |
| --------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `exchange({ subjectToken, resource, scope })` | `TaskSession`              | Exchanges the human's token for a new task (RFC 8693) and saves the grant.                                               |
| `resume(taskId)`                              | `TaskSession \| undefined` | Loads a task from the grant store and refreshes it at once. `undefined` if the store has no such task or it has expired. |
| `revoke(token, hint?)`                        | `void`                     | Revokes a task token or a task grant (RFC 7009). `hint` is `'access_token'` or `'refresh_token'`.                        |
| `refresh(grant, resource, scope)`             | `TokenResponse`            | One refresh request. Sessions call this; most callers do not need it.                                                    |
| `discover()`                                  | `Discovery`                | The control plane's discovery document, fetched once and cached.                                                         |

Only the agent a token was issued to can revoke it. The control plane answers `200` to a token
that does not exist or belongs to another agent, so a return does not say whether anything was
revoked.

The client checks each answer before it acts on it:

- The discovery document must name the configured issuer, and every endpoint in it must be on
  the issuer's origin.
- A token response must carry every required field.
- A token response must not grant a scope that was not requested.

Any of these failing is a `TransportError`.

## `TaskSession`

A session owns one task.

| Member            | Meaning                                                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `accessToken()`   | A token with at least 5 seconds left. Refreshes first if needed.                                                           |
| `refresh(scope?)` | Refreshes now. `scope`, if given, must be a subset of the current scope.                                                   |
| `revoke()`        | Revokes the task at the control plane, then ends the session.                                                              |
| `stop()`          | Stops the timer. The task stays alive and the grant stays in the store. Then `accessToken()` throws `SessionStoppedError`. |
| `toStored()`      | The `StoredTaskGrant` a store needs to resume the task.                                                                    |
| `taskId`          | The task id.                                                                                                               |
| `resource`        | The audience the task was issued for.                                                                                      |
| `scope`           | The scope the session holds now.                                                                                           |
| `expiresAt`       | When the current token expires, or the task if that is earlier.                                                            |
| `taskExpiresAt`   | When the task expires.                                                                                                     |
| `isEnded`         | Whether the session has ended.                                                                                             |

### Refresh

- The session refreshes at 60% of each token's lifetime (`refreshFraction`), counted from when
  the request was sent. `expires_in` is whole seconds, so the session also reads the access
  token's `exp` claim, without verifying it, and never counts the token as living past it. That
  takes off at most a second, so an agent clock running ahead of the control plane's cannot
  shorten a token further.
- `accessToken()` refreshes first when less than 5 seconds are left (`minimumRemainingMs`). If
  the new token still has less than that, it is not handed out. If the token already lasts to
  the task's end, or the task is in its last seconds, the task is over, and the session ends
  with `TaskEndedError` and removes the grant. Otherwise the answer was slow, and
  `accessToken()` throws a `TransportError`, which is retryable; the session carries on.
- No token is used past the end of its task. A token that lasts until the task ends, to the
  whole second its `exp` is written in, is not refreshed: no refresh gives a longer one.
- Concurrent refreshes share one request.
- A narrower `scope` passed to `refresh()` is kept from the moment it is saved, even if that
  refresh fails, so no later refresh asks for more.
- `revoke()` waits for a refresh already under way, and no refresh starts until the revocation
  has answered.
- Refresh timers do not keep the process alive unless `keepAlive` is set.

### Failures

- A retryable failure (see [Errors](#errors)) is retried after 1, 2, 4 seconds and so on, up to
  60 seconds between tries, until the task expires. When the control plane sends
  `Retry-After`, the session waits at least that long.
- Any other failure ends the session: nothing more is sent, and `accessToken()` throws that
  error from then on. A retry only repeats the refusal and adds a denial record.
- The session removes its grant from the store only when the task is over (`isTaskOver`): it
  was revoked, has expired or is ending, or its grant is gone. An `access_denied` carries the
  control plane's `reason`, which tells a task that is over from an agent or a human that is
  disabled and may be enabled again. For a disabled agent or human the session stops but the
  grant stays; call `client.resume(taskId)` once they are enabled. An `access_denied` with no
  `reason` is treated as the end of the task.
- Any other refusal leaves the task alive at the control plane, and the grant stays. An
  `InvalidClientError` from a skewed clock or a key the control plane has not fetched is
  one example. Fix the cause, then call `client.resume(taskId)` to carry on. `resume` removes
  the grant on the same errors the session does.
- A store that fails to save or remove a grant is reported to `onRefreshError`. It does not end
  the session.

### Narrowing scope

`session.refresh('jira:read')` drops every other scope for the rest of the session. The session
refuses a later refresh for a scope it has dropped.

The control plane keeps the narrowing too (spec section 5): it checks each refresh against the
scope of the grant's last successful refresh, so a later refresh for a dropped scope is
`invalid_scope` whoever sends it. The session refuses such a request before sending it, so no
denial is recorded for trying.

The session saves the narrower scope to the grant store before it sends the refresh, so a later
`resume` never asks for a scope the grant has lost. If that save fails, the error goes to
`onRefreshError` and is thrown, nothing is sent, and the session keeps its current scope.

### Revoking

`session.revoke()` ends the task when the work finishes early. The control plane then refuses the
grant and every token under the task at introspection. Tool servers that validate locally
refuse those tokens once they expire. If the revocation request fails, the session is unchanged
and the error is thrown.

## Grant stores

A task grant (the `refresh_token`) is a credential. Store it like one.

`MemoryTaskGrantStore` is the default. It keeps grants for the life of the process. To resume
tasks after a restart, implement `TaskGrantStore`:

| Method           | Called                                                                               |
| ---------------- | ------------------------------------------------------------------------------------ |
| `save(record)`   | After the exchange, before a refresh that narrows the scope, and after each refresh. |
| `load(taskId)`   | By `client.resume(taskId)`.                                                          |
| `remove(taskId)` | When the task is over (see [Failures](#failures)): by the session, and by `resume`.  |

A `StoredTaskGrant` holds `taskId`, `grant`, `resource`, `scope` and `taskExpiresAt`.
[`examples/agent`](https://github.com/subactid/subactid-sdk/tree/main/examples/agent)
has a file-based store.

## Errors

Every error extends `SubactIdError`. No error carries a token, a grant or a key.

Errors from the control plane extend `OAuthError`, which has `error` (the OAuth code),
`errorDescription` and `status`. `AccessDeniedError` also has `reason`: the control plane's
machine-readable reason, the one its audit record carries, or `undefined` when the answer had
none.

| Class                         | OAuth `error`             | Meaning                                                                                                                                            | Kind                                     |
| ----------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `AccessDeniedError`           | `access_denied`           | The control plane does not act: the human is blocked, disabled or removed, the agent is disabled, the task is over, or the delegation is too deep. | terminal; task over by `reason`          |
| `InvalidGrantError`           | `invalid_grant`           | The subject token or task grant was refused: expired, unknown, untrusted or revoked. On an exchange no task was created.                           | terminal; task over on a refresh         |
| `InvalidClientError`          | `invalid_client`          | The agent's assertion was refused.                                                                                                                 | neither                                  |
| `InvalidScopeError`           | `invalid_scope`           | No requested scope is available, or a refresh asked for more than the task holds.                                                                  | neither                                  |
| `InvalidTargetError`          | `invalid_target`          | The agent may not request this audience, or it is not the task's.                                                                                  | neither                                  |
| `InvalidRequestError`         | `invalid_request`         | The request was malformed.                                                                                                                         | neither                                  |
| `UnsupportedGrantTypeError`   | `unsupported_grant_type`  | The control plane does not support the grant type.                                                                                                 | neither                                  |
| `UnsupportedTokenTypeError`   | `unsupported_token_type`  | Not produced by Subact ID v0.1, which ignores `token_type_hint` (spec section 6); kept for other RFC 7009 servers.                                 | neither                                  |
| `TemporarilyUnavailableError` | `temporarily_unavailable` | The control plane could not decide now (`503`). Has `retryAfterSeconds`.                                                                           | retryable                                |
| `SlowDownError`               | `slow_down`               | The control plane is rate limiting this source (`429`). Has `retryAfterSeconds`.                                                                   | retryable                                |
| `UnknownOAuthError`           | any other, or none        | An error code this client does not know, or an answer without one, such as the problem document for an unreadable or oversized body.               | retryable on `5xx`, `408` and `429` only |
| `TransportError`              |                           | The control plane could not be reached, or its answer broke the contract.                                                                          | retryable                                |
| `TaskEndedError`              |                           | The task expired or was revoked.                                                                                                                   | terminal; task over                      |
| `SessionStoppedError`         |                           | The session was stopped with `stop()`. The task is alive and its grant is kept; `resume` carries it on. Not a `TaskEndedError`.                    | neither                                  |

`retryAfterSeconds` is the `Retry-After` header in whole seconds, or `undefined` when the answer
had none.

Three functions sort errors:

- `isTaskOver(error)`: the task is over, so its grant is worthless. That is an
  `InvalidGrantError`, a `TaskEndedError`, or an `AccessDeniedError` unless its `reason` is one
  of `liftableReasons` (`agent_disabled`, `sponsor_disabled`, `sponsor_not_found`).
  An `AccessDeniedError` with no `reason`, or with a reason this client does not know, counts
  as the end of the task (spec section 8). Drop the grant. `taskOverReasons` lists the known
  reasons after which the grant is worthless. It includes `delegation_depth_exceeded` and
  `invalid_delegation_depth`, which Subact ID v0.1 does not produce and which this client
  treats as the end of the task. `isLiftableReason(reason)` asks the same of a bare `reason`.
  Both lists are frozen arrays, for reading only. A `SessionStoppedError` is not one: the caller
  stopped the session, and the task is alive.
- `isTerminal(error)`: nothing this client can do changes the answer, so do not send the same
  request again. Every `isTaskOver` error, and every `AccessDeniedError`: a disabled agent or
  human stays refused until someone enables them. When it is terminal but the task is not
  over, keep the grant and resume the task later.
- `isRetryable(error)`: the same request may succeed later.

An error can be none of these. For example, `InvalidScopeError` is permanent but says nothing
about the task.

### When the exchange is refused

The first exchange can be refused for the human. A subject token can verify and still belong to
someone the control plane does not act for. That is `AccessDeniedError` from `exchange`: no
task is created, and the same token is refused again.

When the control plane cannot reach something the decision depends on, such as the identity
provider's keys, `exchange` throws `TemporarilyUnavailableError`. That is worth retrying.

Neither case saves a grant or starts a timer.

## Other exports

- `AssertionSigner`: signs the agent's assertions. The client uses it internally.
- `refreshFraction` (`0.6`) and `minimumRemainingMs` (`5000`).
- `decodeJwtPayload(jwt)`: decodes a JWT's payload without verifying it.
- Types: `SubactIdClientOptions`, `TaskSessionOptions`, `TaskGrantStore`, `StoredTaskGrant`,
  `Discovery`, `ExchangeRequest`, `TokenResponse`, `AssertionSignerOptions`,
  `AssertionAlgorithm`, `AgentPrivateKey`.

## Examples

- [`examples/agent`](https://github.com/subactid/subactid-sdk/tree/main/examples/agent): the
  `instance` option, refresh callbacks, narrowing scope mid-task, a grant store that survives a
  restart, and error handling.
- [`examples/long-running`](https://github.com/subactid/subactid-sdk/tree/main/examples/long-running):
  a 30-minute task on 5-minute tokens against a live control plane. Exits non-zero if the tool
  server ever answers 401.

## Licence

Apache-2.0.
