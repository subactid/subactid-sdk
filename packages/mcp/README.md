# @subactid/mcp

[Subact ID](https://github.com/subactid/subactid) for MCP servers. Subact ID is an agent identity and
delegation control plane.

`SubactIdGuard` verifies the task token on each request, checks each tool call against a per-tool
policy, and logs who acted for whom.

## Install

```sh
npm install @subactid/mcp
```

The packages are not published to npm yet.
[CONTRIBUTING.md](../../CONTRIBUTING.md#trying-a-build-of-main) says how to install a development
build of `main`.

`@modelcontextprotocol/sdk` is a peer dependency, `>=1.20.0 <2`. Install it beside this
package. `@subactid/mcp` depends on `@subactid/server`. Node 22 or later.

ESM only: load it with `import`. `require()` of it works from Node 22.12, where Node can require
an ES module; on an older Node 22, use `import()`.

## Usage

From [`examples/mcp-jira`](https://github.com/subactid/subactid-sdk/blob/main/examples/mcp-jira/index.ts).
The guard authenticates each HTTP request:

```ts
// examples/mcp-jira/index.ts
const guard = new SubactIdGuard({
  issuer: process.env['SUBACTID_ISSUER'] ?? 'http://127.0.0.1:5100',
  allowInsecureHttp: process.env['SUBACTID_ALLOW_INSECURE_HTTP'] === 'true',
  audience: 'https://jira.internal',
  tools: { search: { scope: 'jira:read' }, comment: { scope: 'jira:comment', highRisk: true } },
});
createServer((req, res) => serve(req, res).catch((e) => guard.reject(res, e))).listen(loopback());
async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const auth = await guard.authenticate(req.headers.authorization);
  await (await jira()).handleRequest(Object.assign(req, { auth }), res);
}
```

`issuer` must be exactly the issuer the control plane is configured with, since every token's
`iss` must equal it. The example's `http://127.0.0.1:5100` fits a control plane run with that
issuer. The quickstart's is `http://subactid:5100`. See
[running the examples](https://github.com/subactid/subactid-sdk#against-the-quickstart).

The tools are registered on a server the guard protects, with one transport per request:

```ts
// examples/mcp-jira/index.ts
const server = guard.protect(new McpServer({ name: 'jira', version: '0.1.0' }));
server.registerTool(
  'search',
  { description: 'Find issues by text.', inputSchema: { query: z.string() } },
  async ({ query }) => ({
    content: [{ type: 'text', text: `PROJ-1: "${query}" reported by a user` }],
  }),
);
```

With the MCP SDK's Express middleware, pass the guard as the verifier:
`requireBearerAuth({ verifier: guard })`.

## Options

`new SubactIdGuard(options)` takes a `SubactIdGuardOptions`:

| Option               | Default        | Meaning                                                                                                                                      |
| -------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`             | required       | The control plane's issuer URL, exactly as the control plane is configured. `https`, or `http` on a loopback host. No user name or password. |
| `allowInsecureHttp`  | `false`        | Accept an `http` issuer that is not on a loopback host. Tokens then travel in the clear: never for production.                               |
| `audience`           | required       | What this server is. A token's `aud` must include it.                                                                                        |
| `tools`              | required       | Each tool's policy, by tool name. A tool not listed is refused.                                                                              |
| `requireActor`       | `true`         | Refuse tokens without an `act` claim, so only an agent acting for a human gets in.                                                           |
| `maxDelegationDepth` | `1`            | The longest `act` chain accepted.                                                                                                            |
| `clockSkewSeconds`   | `60`           | Clock skew allowed on `exp`, `nbf` and `iat`. A whole number from 0 to 300.                                                                  |
| `timeoutMs`          | `10000`        | Time limit for each call to the control plane (keys and introspection).                                                                      |
| `realm`              | the audience   | The realm in `WWW-Authenticate`.                                                                                                             |
| `log`                | JSON on stderr | `(event: CallEvent) => void`. Stderr keeps stdio transports clean.                                                                           |
| `fetch`              | global `fetch` | The `fetch` to use.                                                                                                                          |
| `now`                | `Date.now`     | The clock, in milliseconds.                                                                                                                  |

A tool policy (`ToolPolicy`) has:

| Field      | Meaning                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| `scope`    | Required. A scope or an array of scopes; the token must carry every one. Empty is an error. |
| `highRisk` | Introspect the token at the control plane on every call to this tool.                       |

## Methods

| Method                        | Does                                                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `protect(server)`             | Puts every tool call of an `McpServer` behind the guard. Returns the same server.                                        |
| `authenticate(authorization)` | Verifies the bearer token in an `Authorization` header. Returns the MCP SDK's `AuthInfo`, or throws `SubactIdAuthError`. |
| `verify(token)`               | The same check on a bare token.                                                                                          |
| `verifyAccessToken(token)`    | The MCP SDK's `OAuthTokenVerifier`. Throws the SDK's own auth errors.                                                    |
| `reject(response, error)`     | Answers a refused request on a Node `ServerResponse`: status, `WWW-Authenticate` and a JSON body.                        |
| `decide(tool, authInfo)`      | The decision for one call, logged. `protect` calls it.                                                                   |

The verified claims travel in `AuthInfo.extra.subactid`, a `TaskToken`. `SubactIdAuthExtra` is
the type of that `extra`: `{ subactid: TaskToken }`.

## What is checked

When a request comes in, `authenticate`, `verify` and `verifyAccessToken` check:

- The token's signature against the control plane's JWKS, and `typ: at+jwt`, no `crit`, `iss`,
  `aud`, `exp`, `nbf` and `iat`. The JWKS is cached, and an unknown `kid` triggers a new fetch at
  most once every thirty seconds.
- `sub` is not an agent. A `sub` that starts with `agent:` is always refused.
- The `act` claim is present if `requireActor` is on, and its depth is within
  `maxDelegationDepth`.
- A token with `introspect_required: true` is introspected at the control plane.

On each tool call, the protected server checks:

- The token has not expired since the request came in, within `clockSkewSeconds`.
- The tool is listed in `tools`. An unlisted tool is refused (`unknown_tool`).
- The token carries every scope the tool needs.
- For a `highRisk` tool, the token is introspected. An introspection done when the request came
  in counts for the first tool call only.

A refused tool call returns a tool result with `isError: true` and a text naming the reason. The
session continues. A refused task-augmented call throws an MCP `InvalidRequest` error instead.

The refusal reasons and HTTP statuses are the same as in
[`@subactid/server`](https://github.com/subactid/subactid-sdk/blob/main/packages/server/README.md#refusals)
when the guard answers through `authenticate` and `reject`. Behind the MCP SDK's
`requireBearerAuth`, the SDK writes the answer: a `503` (`keys_unavailable`,
`introspection_unavailable`) becomes its `500` `server_error`, without `Retry-After`.

## `protect` and the MCP SDK

- `protect` guards `tools/call` only. Resources and prompts get the request's token check but no
  per-tool scope check; do not serve anything through them that a tool scope should protect.
- Call `protect` before registering any tool. It throws if the server already has tools.
- `protect` reads two internals of the MCP SDK: whether a `tools/call` handler exists, and which
  method a request schema is for. If it cannot read them, it throws rather than leave tools
  unguarded.
- The tests run against `@modelcontextprotocol/sdk` 1.30.0.

## Logging

Every tool call, allowed or refused, produces one `CallEvent`. By default it is written as one
JSON line on stderr.

The fields are `event` (always `'tool.call'`), `at`, `tool`, `decision`, and, where known,
`reason`, `sub`, `act`, `instance`, `depth`, `task_id` and `jti`. `instance` is the agent's own
claim and is not verified. The token is never logged.

## Re-exports

So an MCP server needs only this package, `@subactid/mcp` re-exports from `@subactid/server`:
`SubactIdAuthError`, `SubactIdToolServer`, `verifyTaskToken`, `JwksCache`, and the types
`DenialReason`, `RoutePolicy`, `TaskToken`, `Actor`, `VerifyOptions`, `JwksCacheOptions` and
`AccessEvent`.

## Example

[`examples/mcp-jira`](https://github.com/subactid/subactid-sdk/tree/main/examples/mcp-jira) is a Jira
MCP server with a read tool and a high-risk comment tool.

## Licence

Apache-2.0.
