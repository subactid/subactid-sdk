# Subact ID SDKs

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/subactid/subactid-sdk/badge)](https://scorecard.dev/viewer/?uri=github.com/subactid/subactid-sdk) [![Release](https://img.shields.io/github/v/release/subactid/subactid-sdk?sort=semver)](https://github.com/subactid/subactid-sdk/releases/latest)

TypeScript libraries for [Subact ID](https://github.com/subactid/subactid), an agent identity and
delegation control plane. Subact ID issues short-lived, scoped tokens that let an AI agent act on
behalf of a specific human, and records every action against that human.

In every token, `sub` is the human and the agent is in `act`.

## Packages

| Package                               | Used by       | What it does                                                                                |
| ------------------------------------- | ------------- | ------------------------------------------------------------------------------------------- |
| [`@subactid/client`](packages/client) | The agent     | Exchanges the human's token for a task token, refreshes it, and stores task grants.         |
| [`@subactid/server`](packages/server) | A tool server | Verifies task tokens, enforces scope per route, and logs each request. Express and Fastify. |
| [`@subactid/mcp`](packages/mcp)       | An MCP server | Verifies task tokens, enforces scope per tool, and logs each call.                          |

`@subactid/server` also includes `@subactid/server/audit`, which verifies records from the control
plane's audit ledger.

Each package README covers its API, options and errors.

## Install

```sh
npm install @subactid/client                          # the agent
npm install @subactid/server                          # a tool server
npm install @subactid/mcp @modelcontextprotocol/sdk   # an MCP server
```

All three share one version. To try a build of `main` before a release, see
[CONTRIBUTING.md](CONTRIBUTING.md#trying-a-build-of-main); to work on the packages from a clone,
see [Development](#development).

`@subactid/mcp` needs `@modelcontextprotocol/sdk` as a peer dependency.

## Example

An MCP server behind Subact ID, taken line for line from
[`examples/mcp-jira`](examples/mcp-jira/index.ts):

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

A test in `packages/mcp` checks that this block matches the example.

## Examples

| Example                                          | Shows                                                                                                     |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| [`examples/agent`](examples/agent)               | An agent: the `instance` option, refresh callbacks, narrowing scope mid-task, a file grant store, errors. |
| [`examples/long-running`](examples/long-running) | A 30-minute task on 5-minute tokens. Exits non-zero if the tool server ever answers 401.                  |
| [`examples/tool-server`](examples/tool-server)   | One Jira tool server written twice: Express and Fastify.                                                  |
| [`examples/mcp-jira`](examples/mcp-jira)         | A Jira MCP server behind `SubactIdGuard`.                                                                 |
| [`examples/audit-verify`](examples/audit-verify) | Checks a ledger record against a signed checkpoint, and the chain of checkpoints, from saved files.       |

Each example reads its settings from environment variables, listed at the top of its source.
The packages are imported from their built output, so build them once from the repository root
first:

```sh
pnpm install
pnpm build
```

### The issuer

`SUBACTID_ISSUER` must be exactly the issuer the control plane is configured with
(`SubactId:Issuer`), not just an address that reaches it. The client refuses a discovery document
that names another issuer and calls the endpoints the document names. A tool server refuses a
token whose `iss` is anything else and fetches the keys from under the issuer. So the host running
an example has to reach the control plane by that name.

The tool-server and MCP examples default to `http://127.0.0.1:5100`. That default works only
with a control plane you run yourself with `SubactId__Issuer=http://127.0.0.1:5100`.

### Against the quickstart

The quickstart in the Subact ID repository (`quickstart/`) configures the issuer as
`http://subactid:5100` and the identity provider as `http://keycloak:8080`. Leave those as they
are, because the quickstart's own services use them. Instead, let this host resolve both names.
The packages accept plain `http` only on a loopback host unless told otherwise, so every command
below also sets `SUBACTID_ALLOW_INSECURE_HTTP=true`, which the examples pass on as
`allowInsecureHttp`. Never set it against a real control plane:

```sh
echo '127.0.0.1 subactid keycloak' | sudo tee -a /etc/hosts
```

Register the agent first (`POST /admin/agents`, spec section 2). `pnpm registration` in
`examples/agent` prints the request body, with the public half of the agent's key inline as
`jwks`:

```json
{
  "agent_id": "sdk-example",
  "display_name": "Example triage agent",
  "sponsor_required": true,
  "allowed_scopes": ["jira:read", "jira:comment"],
  "allowed_audiences": ["https://jira.internal"],
  "max_delegation_depth": 1,
  "jwks": {
    "keys": [
      {
        "kty": "RSA",
        "n": "...",
        "e": "AQAB",
        "kid": "sdk-example-1",
        "alg": "RS256",
        "use": "sig"
      }
    ]
  }
}
```

The key can be RSA or EC on P-256. An EC key signs with `ES256`. An RSA key signs with `RS256`,
or with `PS256` when `SUBACTID_AGENT_ALG=PS256` is set. The registration prints that as the
key's `alg`, and the agent example passes the same value to the client's `algorithm` option,
so set `SUBACTID_AGENT_ALG` the same way for both.

A registration can name a `jwks_uri` instead of `jwks`: an https URL where the agent publishes its
keys. It carries exactly one of the two.

```sh
cd examples/agent
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out agent-key.pem
export SUBACTID_ISSUER=http://subactid:5100 SUBACTID_ALLOW_INSECURE_HTTP=true SUBACTID_AGENT_ID=sdk-example \
  SUBACTID_AGENT_KID=sdk-example-1 SUBACTID_AGENT_KEY_FILE="$PWD/agent-key.pem"
pnpm --silent registration > agent.json

# The admin key: run this in the quickstart directory.
ADMIN_KEY=$(docker compose exec -T subactid cat /etc/subactid/admin-key)
curl -s -X POST -H "authorization: Bearer $ADMIN_KEY" -H 'content-type: application/json' \
  --data @agent.json http://subactid:5100/admin/agents
```

That generates an RSA key. For an EC key, generate it with
`openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out agent-key.pem` instead.

Start the tool server from `examples/tool-server` in another terminal. It listens on
`127.0.0.1:4000`, which is where the agent example calls by default:

```sh
SUBACTID_ISSUER=http://subactid:5100 SUBACTID_ALLOW_INSECURE_HTTP=true pnpm start
```

Then sign the quickstart's demo user in and run the agent:

```sh
export SUBACTID_SUBJECT_TOKEN=$(curl -s -d grant_type=password -d client_id=demo-cli \
  -d username=demo -d password=demo \
  http://keycloak:8080/realms/subactid-demo/protocol/openid-connect/token | jq -r .access_token)
pnpm start
```

Sign the user in at `keycloak:8080`, not `localhost:8080`. The identity provider writes the host
it was asked on into the token's `iss`, and the control plane accepts only the issuer it knows.

The quickstart's own tool server, on port 8082, is a separate program with other routes
(`POST /tools/{tool}`). The agent example calls `GET /issues` on `examples/tool-server`.

## Development

Node 22 or later. The packages use only WebCrypto and `fetch` from the platform.

```sh
pnpm install
pnpm build && pnpm typecheck && pnpm test
```

Changes come from members of the subactid organization. [CONTRIBUTING.md](CONTRIBUTING.md) says
how, and how to report a bug or ask to join from outside; [SECURITY.md](SECURITY.md) says how to
report a vulnerability.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The Code of Conduct is CC-BY-4.0;
[`REUSE.toml`](REUSE.toml) says which licence covers each path and [`LICENSES/`](LICENSES) holds
the texts. The Subact ID name and logo are not covered by any of these licences; see
[TRADEMARKS.md](TRADEMARKS.md).
