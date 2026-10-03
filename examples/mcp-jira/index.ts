/**
 * A Jira MCP server that only an agent acting for a human may call. Every task token is
 * verified against the control plane's keys, every tool needs its scope, and `comment` is
 * checked with the control plane on every call so a kill switch is felt at once. Each call is
 * logged with the human (`sub`) and the agent (`act`) on stderr.
 *
 *   SUBACTID_ISSUER  the control plane's issuer, exactly as it is configured there
 *                    (`SubactId:Issuer`); http://127.0.0.1:5100 by default. For the quickstart
 *                    it is http://subactid:5100, with `127.0.0.1 subactid` in /etc/hosts.
 *   SUBACTID_ALLOW_INSECURE_HTTP  `true` to accept a plain http issuer that is not on a
 *                    loopback host, as the quickstart's is. Never against a real control plane
 *   PORT             where to listen on 127.0.0.1; 3000 by default
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  StreamableHTTPServerTransport,
  type StreamableHTTPServerTransportOptions,
} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { SubactIdGuard } from '@subactid/mcp';
import { z } from 'zod';

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

/** The MCP server, one per request in stateless mode, with every tool behind the guard. */
async function jira(): Promise<StreamableHTTPServerTransport> {
  const server = guard.protect(new McpServer({ name: 'jira', version: '0.1.0' }));
  server.registerTool(
    'search',
    { description: 'Find issues by text.', inputSchema: { query: z.string() } },
    async ({ query }) => ({
      content: [{ type: 'text', text: `PROJ-1: "${query}" reported by a user` }],
    }),
  );
  server.registerTool(
    'comment',
    { description: 'Comment on an issue.', inputSchema: { issue: z.string(), body: z.string() } },
    async ({ issue, body }) => ({
      content: [{ type: 'text', text: `Commented on ${issue}: ${body}` }],
    }),
  );
  // Stateless: no session id. The SDK's option type wants the key present, so it is passed as such.
  const options = {
    sessionIdGenerator: undefined,
  } as unknown as StreamableHTTPServerTransportOptions;
  const transport = new StreamableHTTPServerTransport(options);
  await server.connect(transport as Transport);
  return transport;
}

/** Loopback only: the example is not meant to be reachable from other machines. */
function loopback(): { host: string; port: number } {
  return { host: '127.0.0.1', port: Number(process.env['PORT'] ?? 3000) };
}
