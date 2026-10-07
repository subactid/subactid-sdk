# @subactid/server

The tool server's side of [Subact ID](https://github.com/subactid/subactid), an agent identity and
delegation control plane.

An agent calls a tool server with a task token. This package checks that token, enforces the
scope each route needs, and logs who acted for whom. It covers the tool-server steps in section
9 of the Subact ID spec. It has adapters for Express and Fastify, and works without either.

`@subactid/server/audit` verifies records from the control plane's audit ledger. See
[Audit verification](#audit-verification).

## Install

```sh
npm install @subactid/server
```

Node 22 or later. No runtime dependencies: the package uses WebCrypto and `fetch`.

ESM only: load it with `import`. `require()` of it works from Node 22.12, where Node can require
an ES module; on an older Node 22, use `import()`.

## Express

```ts
// examples/tool-server/express-app.ts
import express from 'express';
import { claimsOf, subactIdExpress, type SubactIdRequest } from '@subactid/server';
import { issuesFor, subactid, port } from './jira.js';

const app = express();
app.use(express.json());

// Only an agent acting for a human may search or comment; a person uses Jira itself.
app.get(
  '/issues',
  subactIdExpress(subactid, { scope: 'jira:read', requireActor: true }),
  (request, response) => {
    const claims = claimsOf(request as SubactIdRequest);
    response.json(issuesFor(claims?.sub ?? 'nobody', String(request.query['q'] ?? '')));
  },
);

// High-risk: the control plane is asked on every call, so a revoked task cannot comment once more.
app.post(
  '/issues/:id/comments',
  subactIdExpress(subactid, { scope: 'jira:comment', highRisk: true, requireActor: true }),
  (request, response) => {
    const claims = claimsOf(request as SubactIdRequest);
    response.status(201).json({ issue: request.params.id, by: claims?.act?.sub, for: claims?.sub });
  },
);
```

`subactIdExpress(subactid, policy)` answers a refused request itself, and the handler does not run. On
an allowed request, the verified claims are on `req.subactid`. `claimsOf(req)` returns them.

## Fastify

The plugin guards every route in the scope it is registered on, and takes each route's policy from
its `config.subactid`. To guard a single route instead, pass `onRequest: subactIdFastify(subactid, policy)`.

```ts
// examples/tool-server/fastify-app.ts
import Fastify from 'fastify';
import { subactIdFastifyPlugin, type SubactIdFastifyRequest } from '@subactid/server';
import { issuesFor, subactid, port } from './jira.js';

const app = Fastify({ logger: false });
await app.register(subactIdFastifyPlugin(subactid, { unguarded: ['GET /healthz'] }));

app.get<{ Querystring: { q?: string } }>(
  '/issues',
  { config: { subactid: { scope: 'jira:read', requireActor: true } } },
  async (request) => {
    const claims = (request as SubactIdFastifyRequest).subactid;
    return issuesFor(claims?.sub ?? 'nobody', request.query.q ?? '');
  },
);
```

The verified claims are on `request.subactid`.

`subactIdFastifyPlugin` reads each route's policy from `config.subactid`:

- A route with no `config.subactid` is refused with `403` (`unknown_route`).
- `unguarded` lists routes that skip the check, such as a health check. An entry is a path for
  every method (`/healthz`) or a method and a path (`GET /healthz`).
- A route with a policy is always checked, even if `unguarded` names it.

## Server options

`new SubactIdToolServer(options)` takes a `SubactIdToolServerOptions`:

| Option               | Default        | Meaning                                                                                                                                      |
| -------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`             | required       | The control plane's issuer URL, exactly as the control plane is configured. `https`, or `http` on a loopback host. No user name or password. |
| `allowInsecureHttp`  | `false`        | Accept an `http` issuer that is not on a loopback host. Tokens then travel in the clear: never for production.                               |
| `audience`           | required       | What this server is. A token's `aud` must include it.                                                                                        |
| `requireActor`       | `true`         | Refuse tokens without an `act` claim, so only an agent acting for a human gets in.                                                           |
| `maxDelegationDepth` | `1`            | The longest `act` chain accepted. A whole number, at least 1.                                                                                |
| `clockSkewSeconds`   | `60`           | Clock skew allowed on `exp`, `nbf` and `iat`. A whole number from 0 to 300.                                                                  |
| `timeoutMs`          | `10000`        | Time limit for each call to the control plane (keys and introspection).                                                                      |
| `realm`              | the audience   | The realm in `WWW-Authenticate`.                                                                                                             |
| `log`                | JSON on stdout | `(event: AccessEvent) => void`. See [Logging](#logging).                                                                                     |
| `fetch`              | global `fetch` | The `fetch` to use.                                                                                                                          |
| `now`                | `Date.now`     | The clock, in milliseconds.                                                                                                                  |

## Route policy

A `RoutePolicy`: the second argument to `subactIdExpress` and `subactIdFastify`, and
`config.subactid` for the plugin:

| Field                | Meaning                                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `scope`              | A scope or an array of scopes. The token must carry every one. Omit it to accept any verified token. An empty string or array is an error. |
| `highRisk`           | Introspect the token at the control plane on every request.                                                                                |
| `requireActor`       | Overrides the server's `requireActor` for this route.                                                                                      |
| `maxDelegationDepth` | Overrides the server's `maxDelegationDepth` for this route.                                                                                |

To make agent-only routes the exception, set `requireActor: false` on the server and
`requireActor: true` on those routes.

## What is checked

Each request goes through these checks in order:

1. The `Authorization` header carries a bearer token.
2. The token is verified against the control plane's JWKS, at the `jwks_uri` of its discovery
   document (`<issuer>/.well-known/openid-configuration`, fetched once, which must name this
   issuer and keep its endpoints on the issuer's origin):
   ES256 signature, `typ: at+jwt`, no `crit` header, `iss`, `aud`, `exp`, `nbf` and `iat`.
3. The token has a `sub` and a `jti`. A `sub` that starts with `agent:` is always refused: the
   agent is the actor, never the subject.
4. The `act` claim is present if required, and its depth is within `maxDelegationDepth`.
5. The token carries every scope the route needs.
6. The token is introspected at the discovery document's `introspection_endpoint` if the route is `highRisk` or the
   token carries `introspect_required: true`. Anything but an active answer for this token is a
   refusal.

The JWKS is cached for as long as the answer's `Cache-Control: max-age` says, held between thirty
seconds and an hour. The control plane sends five minutes, and five minutes is the default when
an answer names none. A token with an unknown `kid` triggers a new fetch, at most once every
thirty seconds. If a fetch fails, the last good key set stays in use for up to an hour after it
was due to be fetched again. After that every token is refused as `keys_unavailable` until a
fetch succeeds, so a key the control plane has withdrawn does not verify here for ever.

## Refusals

| Status | Body `error`              | Reasons                                                                                                                                                                                                                                 |
| ------ | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401`  | `invalid_token`           | `missing_token`, `malformed_token`, `unsupported_algorithm`, `unknown_key`, `invalid_signature`, `wrong_type`, `wrong_issuer`, `wrong_audience`, `expired`, `not_yet_valid`, `no_subject`, `subject_is_agent`, `no_actor`, `not_active` |
| `403`  | `insufficient_scope`      | `insufficient_scope`, `delegation_too_deep`, `unknown_route`, `unknown_tool` (from `@subactid/mcp`)                                                                                                                                     |
| `503`  | `temporarily_unavailable` | `keys_unavailable`, `introspection_unavailable`                                                                                                                                                                                         |
| `500`  | `server_error`            | Any error that is not an `SubactIdAuthError`.                                                                                                                                                                                           |

The body is `{ error, error_description }`. `401` and `403` carry a `WWW-Authenticate` header
(RFC 6750). When the control plane sent `Retry-After`, the refusal passes it on.

## Logging

Every request, allowed or refused, produces one `AccessEvent`. By default it is written as one
JSON line on stdout.

| Field      | Meaning                                                           |
| ---------- | ----------------------------------------------------------------- |
| `event`    | Always `'request'`.                                               |
| `at`       | ISO 8601 timestamp.                                               |
| `route`    | Method and route, for example `GET /issues/:id`. No query string. |
| `decision` | `'allow'` or `'deny'`.                                            |
| `reason`   | The denial reason, on a refusal.                                  |
| `sub`      | The human.                                                        |
| `act`      | The agent, `agent:<id>`.                                          |
| `instance` | The agent's `act.instance`, if it sent one. Not verified.         |
| `depth`    | The delegation depth.                                             |
| `task_id`  | The task, if the token has one.                                   |
| `jti`      | The token's id.                                                   |

The token itself is never logged.

## Other frameworks

The adapters are thin wrappers around `SubactIdToolServer`:

| Method                                | Does                                                                                                       |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `guard(authorization, policy, route)` | Everything: authenticate, authorize, log. Returns the claims or throws `SubactIdAuthError`.                |
| `authenticate(authorization)`         | Checks the header and verifies the token. Returns a `TaskToken`.                                           |
| `verifyToken(token)`                  | Verifies a bare token.                                                                                     |
| `authorize(claims, policy, options?)` | Actor, depth, scope and introspection checks. Returns an `SubactIdAuthError` or `undefined`. Does not log. |
| `log(route, claims, denial?)`         | Writes one `AccessEvent`.                                                                                  |
| `refusal(error)`                      | The status, headers and body to answer with.                                                               |

`authorize` takes `AuthorizeOptions`: `alreadyIntrospected: true` says the token was introspected
once already for this call, so a caller that guards at two levels does not introspect twice.
`refusal` returns a `Refusal`: `status`, `headers` and `body` (`{ error, error_description }`).

`SubactIdAuthError` has `status`, `reason` (a `DenialReason`) and `retryAfterSeconds`. Its message
never contains the token.

A `TaskToken` has `sub`, `act`, `scopes`, `audience`, `jti`, `taskId`, `exp`, `claims` (every
claim) and `token`. `act` is an `Actor`: `sub` (the agent, `agent:<id>`), `depth`, `instance`
when the agent sent one, and the next `act` in a chain. `token` is the raw token, kept for
introspection. Never log it.

`verifyTaskToken(token, options)` and `JwksCache` are also exported for callers that verify
tokens outside `SubactIdToolServer`. `VerifyOptions` is `issuer`, `audience`, `keys` (a
`JwksCache`), `now` and `clockSkewSeconds`, all required. `verifyTaskToken` does the signature,
`typ`, `crit`, `iss`, `aud`, time and `sub` checks; whether an `act` is required, and how deep it
may go, is left to the caller.

`new JwksCache(options)` takes a `JwksCacheOptions`. `jwksUri`, `fetch` and `now` are required;
`get(kid)` returns the key or throws `SubactIdAuthError`.

| Option         | Default | Meaning                                                                                                                                             |
| -------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ttlMs`        | 5 min   | How long a fetched set is served when the answer names no `max-age`. An answer's `max-age` wins. Either is held between thirty seconds and an hour. |
| `maxStaleMs`   | 1 hour  | How long the last good set is still used, once due, while every fetch fails. After that no key is served until a fetch succeeds.                    |
| `minRefreshMs` | 30 s    | Least time between fetches, including those forced by an unknown `kid`.                                                                             |
| `timeoutMs`    | 10 s    | How long one fetch may take.                                                                                                                        |

The adapter types (`SubactIdRequest`, `SubactIdResponse`, `SubactIdFastifyRequest`, `SubactIdFastifyReply`)
cover only the parts of a request and reply the adapters use. The package does not depend on
Express or Fastify.

## Audit verification

The control plane seals its audit ledger in checkpoints (spec section 7). Each checkpoint is a
signed Merkle root over a run of records, linked to the checkpoint before it.
`@subactid/server/audit` checks a record against a signed checkpoint without trusting the server
that published it.

```ts
// examples/audit-verify/index.ts
const result = await verifyAuditRecord(record, proof, checkpoint, jwks);
if (!result.ok) throw new Error(`Record ${record.seq} does not verify: ${result.detail}`);
```

The four arguments are documents the control plane publishes:

| Argument     | Source                                                                   |
| ------------ | ------------------------------------------------------------------------ |
| `record`     | `GET /audit`                                                             |
| `proof`      | `GET /audit/records/{seq}/proof`                                         |
| `checkpoint` | `GET /audit/checkpoints`, kept somewhere the control plane cannot change |
| `jwks`       | A `JwksCache`, or a JWKS document such as one read from a file           |

`verifyAuditRecord` first checks that `checkpoint` and the checkpoint inside `proof` are the same
document. Then it checks the checkpoint's signature and the record's inclusion in its root.

It does not check the chain of checkpoints. `verifyCheckpointChain` does:

```ts
// examples/audit-verify/index.ts
const chain = await verifyCheckpointChain(checkpoints, jwks);
if (!chain.ok) throw new Error(`The checkpoints do not form a chain: ${chain.detail}`);
```

It checks that the checkpoints are consecutive, that each range starts where the previous one
ended, that each links to the one before, and that each signature verifies. Pass `'links-only'`
instead of keys to skip the signatures. That only shows the checkpoints agree with each other,
not that the control plane signed them.

The types are exported as well: `AuditRecord` (a record as `GET /audit` publishes it),
`AuditCheckpoint`, `AuditProof` (the proof endpoint's answer) and `CheckpointKeySource`, which is
a `JwksCache`, a JWKS document, or anything else that is a `CheckpointKeys` (an object whose
`get(kid)` resolves a verification key).

### Results

Every check returns an `AuditVerification`, `{ ok: true }` or `{ ok: false, fault, detail }`.
`fault` is an `AuditFault`:

| `fault`                | Meaning                                                          |
| ---------------------- | ---------------------------------------------------------------- |
| `malformed_record`     | The record is not the published shape.                           |
| `malformed_checkpoint` | The checkpoint is not the published shape.                       |
| `malformed_proof`      | The proof is not the published shape.                            |
| `unsealed`             | No checkpoint covers the record.                                 |
| `mismatched`           | The documents do not belong together.                            |
| `unknown_key`          | The checkpoint names a key the key set does not hold.            |
| `bad_signature`        | The checkpoint's signature does not verify.                      |
| `broken_chain`         | A checkpoint does not follow on from the one before it.          |
| `not_included`         | The audit path does not lead from the record to the signed root. |

If the key set cannot be fetched, the check rejects instead of returning a result. An
unreachable control plane is not a broken seal.

### Lower-level functions

| Function                                                          | Does                                                          |
| ----------------------------------------------------------------- | ------------------------------------------------------------- |
| `verifyCheckpoint(checkpoint, keys)`                              | Checks one checkpoint's signature.                            |
| `verifyInclusion(leaf, auditPath, leafIndex, treeSize, rootHash)` | Folds an audit path to a root (RFC 6962).                     |
| `leafHash(record)`                                                | `sha256(0x00 \|\| canonical_json(record))`, as lowercase hex. |
| `canonicalRecordJson(record)`                                     | The bytes a record's leaf is taken over.                      |
| `checkpointSignedBytes(checkpoint)`                               | The bytes a checkpoint's signature is taken over.             |

`canonicalRecordJson`, `checkpointSignedBytes` and `leafHash` throw `AuditShapeError` for a
document that is not the published shape. The canonical form is tested against vectors produced
by the control plane's own code and against a ledger captured from a running instance.

The functions do no I/O. They work the same on a live instance, an export or a file.

## Example

[`examples/tool-server`](https://github.com/subactid/subactid-sdk/tree/main/examples/tool-server) is
one Jira tool server written for Express and for Fastify.

## Licence

Apache-2.0.
