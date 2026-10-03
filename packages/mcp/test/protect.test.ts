import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ServerResponse, IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import { z } from 'zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SubactIdGuard, type CallEvent } from '../src/guard.js';
import { SubactIdAuthError } from '../src/index.js';
import { audience, FakeControlPlane, issuer } from '../../server/test/control-plane.js';

const start = Date.UTC(2026, 8, 11, 12, 0, 0);

/** A client whose every message carries the given auth, as the SDK's HTTP transports do after the bearer middleware. */
async function connect(server: McpServer, auth: AuthInfo | undefined): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) =>
    send(message, { ...options, ...(auth ? { authInfo: auth } : {}) });
  await server.connect(serverTransport);
  const client = new Client({ name: 'test', version: '0' });
  await client.connect(clientTransport);
  return client;
}

describe('SubactIdGuard.protect', () => {
  let plane: FakeControlPlane;
  let events: CallEvent[];
  let guard: SubactIdGuard;
  const calls: string[] = [];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
    events = [];
    calls.length = 0;
    guard = new SubactIdGuard({
      issuer,
      audience,
      tools: {
        search_issues: { scope: 'jira:read' },
        add_comment: { scope: 'jira:comment', highRisk: true },
      },
      fetch: plane.fetch,
      log: (e) => events.push(e),
    });
  });

  afterEach(() => vi.useRealTimers());

  function jira(): McpServer {
    const server = guard.protect(new McpServer({ name: 'jira', version: '0' }));
    server.registerTool(
      'search_issues',
      { inputSchema: { query: z.string() } },
      async ({ query }) => {
        calls.push(`search:${query}`);
        return { content: [{ type: 'text', text: `found ${query}` }] };
      },
    );
    server.registerTool(
      'add_comment',
      { inputSchema: { issue: z.string(), body: z.string() } },
      async ({ issue }) => {
        calls.push(`comment:${issue}`);
        return { content: [{ type: 'text', text: `commented on ${issue}` }] };
      },
    );
    server.registerTool('unlisted', {}, async () => {
      calls.push('unlisted');
      return { content: [{ type: 'text', text: 'oops' }] };
    });
    return server;
  }

  it('lets a call through when the token carries the scope, and hands the tool its arguments', async () => {
    const client = await connect(jira(), await guard.verifyAccessToken(plane.token()));

    const result = await client.callTool({ name: 'search_issues', arguments: { query: 'PROJ-1' } });

    expect(result).toMatchObject({ content: [{ type: 'text', text: 'found PROJ-1' }] });
    expect(calls).toEqual(['search:PROJ-1']);
    expect(events).toMatchObject([
      {
        tool: 'search_issues',
        decision: 'allow',
        sub: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        act: 'agent:jira-triage',
      },
    ]);
  });

  it('refuses without running the tool: no token, a missing scope, an unlisted tool', async () => {
    const readOnly = await connect(
      jira(),
      await guard.verifyAccessToken(plane.token({ scope: 'jira:read' })),
    );
    const anonymous = await connect(jira(), undefined);

    const short = await readOnly.callTool({
      name: 'add_comment',
      arguments: { issue: 'PROJ-1', body: 'hi' },
    });
    expect(short).toMatchObject({
      isError: true,
      content: [
        {
          type: 'text',
          text: 'Subact ID refused add_comment: the token lacks scope jira:comment.',
        },
      ],
    });
    const unlisted = await readOnly.callTool({ name: 'unlisted', arguments: {} });
    expect(unlisted).toMatchObject({
      isError: true,
      content: [
        {
          type: 'text',
          text: 'Subact ID refused unlisted: the tool has no access policy, so nobody may call it.',
        },
      ],
    });
    const none = await anonymous.callTool({ name: 'search_issues', arguments: { query: 'x' } });
    expect(none).toMatchObject({
      isError: true,
      content: [
        {
          type: 'text',
          text: 'Subact ID refused search_issues: The call carries no verified token.',
        },
      ],
    });

    expect(calls).toEqual([]);
    expect(events.map((e) => [e.tool, e.decision, e.reason])).toEqual([
      ['add_comment', 'deny', 'insufficient_scope'],
      ['unlisted', 'deny', 'unknown_tool'],
      ['search_issues', 'deny', 'missing_token'],
    ]);
  });

  it('introspects a high-risk tool per call and stops the moment the control plane says the token is not active', async () => {
    const token = plane.token();
    const client = await connect(jira(), await guard.verifyAccessToken(token));

    await client.callTool({ name: 'add_comment', arguments: { issue: 'PROJ-1', body: 'hi' } });
    plane.introspection = { active: false, revocation_reason: 'operator_kill_switch' };
    const revoked = await client.callTool({
      name: 'add_comment',
      arguments: { issue: 'PROJ-2', body: 'hi' },
    });

    expect(plane.introspections).toEqual([token, token]);
    expect(calls).toEqual(['comment:PROJ-1']);
    expect(revoked).toMatchObject({
      isError: true,
      content: [
        {
          type: 'text',
          text: 'Subact ID refused add_comment: the token is no longer active (operator_kill_switch).',
        },
      ],
    });
    expect(events.map((e) => e.decision)).toEqual(['allow', 'deny']);
  });

  it('never runs a tool for a task-augmented call it would refuse', async () => {
    const client = await connect(
      jira(),
      await guard.verifyAccessToken(plane.token({ scope: 'jira:read' })),
    );

    // The SDK refuses task creation on a server without task support; on one with it, the guard throws the refusal.
    await expect(
      client.request(
        {
          method: 'tools/call',
          params: {
            name: 'add_comment',
            arguments: { issue: 'PROJ-1', body: 'hi' },
            task: { ttl: 1000 },
          },
        },
        z.any(),
      ),
    ).rejects.toThrow();
    expect(calls).toEqual([]);
  });

  it('guards tools registered with the deprecated tool() as well', async () => {
    const server = guard.protect(new McpServer({ name: 'jira', version: '0' }));
    server.tool('search_issues', { query: z.string() }, async () => ({
      content: [{ type: 'text', text: 'ok' }],
    }));
    const client = await connect(
      server,
      await guard.verifyAccessToken(plane.token({ scope: 'jira:comment' })),
    );

    expect(
      await client.callTool({ name: 'search_issues', arguments: { query: 'x' } }),
    ).toMatchObject({
      isError: true,
    });
  });

  it('reads an SDK that hides the method literal by what its schema accepts, and refuses one it cannot read at all', async () => {
    const registered: unknown[] = [];
    const fake = {
      server: {
        setRequestHandler: (schema: unknown, handler: unknown) =>
          registered.push([schema, handler]),
      },
      _registeredTools: {},
    } as unknown as McpServer;

    guard.protect(fake);
    const accepts = (method: string) => ({
      safeParse: (value: unknown) => ({ success: (value as { method: string }).method === method }),
    });
    fake.server.setRequestHandler(accepts('tools/list') as never, (() => 'list') as never);
    fake.server.setRequestHandler(accepts('tools/call') as never, (() => 'called') as never);
    expect(registered[0]?.[1]()).toBe('list');
    // The tools/call handler was wrapped: a call with no verified token is refused, not dispatched.
    expect(await registered[1]?.[1]({ params: { name: 'search_issues' } }, {})).toMatchObject({
      isError: true,
    });
    expect(() => fake.server.setRequestHandler({} as never, (() => undefined) as never)).toThrow(
      'not supported',
    );

    expect(() =>
      guard.protect({ server: { setRequestHandler: () => undefined } } as unknown as McpServer),
    ).toThrow('not supported');
  });

  it('refuses to protect a server that already has tools, so none can be registered unguarded', () => {
    const server = new McpServer({ name: 'jira', version: '0' });
    server.registerTool('early', {}, async () => ({ content: [] }));

    expect(() => guard.protect(server)).toThrow(
      'protect() must be called before any tool is registered.',
    );
  });

  it('answers a refused HTTP request with the status, WWW-Authenticate and a JSON body naming the reason', () => {
    const response = new ServerResponse(new IncomingMessage(new Socket()));
    const written: string[] = [];
    response.write = ((chunk: unknown) => {
      written.push(String(chunk));
      return true;
    }) as typeof response.write;
    response.end = ((chunk?: unknown) => {
      if (chunk) written.push(String(chunk));
      return response;
    }) as typeof response.end;

    guard.reject(response, new SubactIdAuthError(401, 'expired', 'The token has expired.'));

    expect(response.statusCode).toBe(401);
    expect(response.getHeader('www-authenticate')).toBe(
      'Bearer realm="https://jira.internal", error="invalid_token", error_description="The token has expired."',
    );
    expect(JSON.parse(written.join(''))).toEqual({
      error: 'invalid_token',
      error_description: 'The token has expired.',
    });

    const other = new ServerResponse(new IncomingMessage(new Socket()));
    other.end = (() => other) as typeof other.end;
    guard.reject(other, new Error('secret detail'));
    expect(other.statusCode).toBe(500);
  });
});
