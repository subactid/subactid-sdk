import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  InsufficientScopeError,
  InvalidTokenError,
  ServerError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import type { ServerResponse } from 'node:http';
import {
  SubactIdAuthError,
  SubactIdToolServer,
  type DenialReason,
  type RoutePolicy,
  type TaskToken,
} from '@subactid/server';

/** What a tool needs from a caller. */
export interface ToolPolicy {
  /** Scope, or scopes, the token must carry; every one listed. */
  scope: string | string[];
  /** Introspect the token at the control plane on every call, so a revocation is seen at once. */
  highRisk?: boolean;
}

export interface SubactIdGuardOptions {
  /**
   * The control plane's issuer URL, as in its discovery document. `https`, or `http` on a
   * loopback host (`localhost`, `127.0.0.0/8`, `::1`) for local development.
   */
  issuer: string;
  /**
   * Accept an `http` issuer that is not on a loopback host. Every token then travels in the
   * clear: for a demo or a network you trust, never for production. Default false.
   */
  allowInsecureHttp?: boolean;
  /** The audience this server is: the `aud` a token must carry. */
  audience: string;
  /** Every tool this server exposes and what it requires. A tool not listed here is refused. */
  tools: Record<string, ToolPolicy>;
  /** Refuse tokens without an `act` claim, so only agents acting for a human get in; default true. */
  requireActor?: boolean;
  /** Longest `act` chain accepted; default 1, direct agents only. Raise it deliberately. */
  maxDelegationDepth?: number;
  /** Clock skew tolerated, in seconds; default 60. */
  clockSkewSeconds?: number;
  /** How long a call to the control plane (keys, introspection) may take, in milliseconds; default 10000. */
  timeoutMs?: number;
  /** Realm named in `WWW-Authenticate`; defaults to the audience. */
  realm?: string;
  /** Where every call is logged; defaults to one JSON line on stderr, which is safe for stdio transports. */
  log?: (event: CallEvent) => void;
  fetch?: typeof fetch;
  now?: () => number;
}

/** Step 5 of the tool-server contract: one of these per call, allowed or not. Never a token. */
export interface CallEvent {
  event: 'tool.call';
  at: string;
  tool: string;
  decision: 'allow' | 'deny';
  reason?: DenialReason;
  /** The human, when the caller was authenticated. */
  sub?: string;
  /** The agent that acted, `agent:<id>`. */
  act?: string;
  /** Which copy of the agent, when it said so: the token's `act.instance`, the agent's own claim about itself, never verified. */
  instance?: string;
  depth?: number;
  task_id?: string;
  jti?: string;
}

/** The verified token as it travels inside `AuthInfo.extra`. */
export interface SubactIdAuthExtra {
  subactid: TaskToken;
}

/**
 * Verified tokens whose introspection at the transport has not been spent on a tool call.
 *
 * A token for a high-risk audience must be introspected on every call (spec sections 4 and 6),
 * and `verify()` does one as the caller comes in. That answer is good for exactly one call: the
 * one the transport authenticated. Every later call in the session is introspected again, so
 * revocation is felt at once rather than when the token expires, which is what marking an
 * audience high-risk buys. Membership is therefore taken, not read.
 */
const unspentIntrospection = new WeakSet<TaskToken>();

/**
 * Subact ID for an MCP server. One guard per server: it verifies task tokens against the control
 * plane's keys, decides every tool call from the token's scope and the tool's policy, asks the
 * control plane per call for the tools marked high-risk, and logs `sub` and `act.sub` for each
 * call. It implements the MCP SDK's `OAuthTokenVerifier`, so it plugs into the SDK's bearer
 * middleware, and `authenticate()` does the same for any other transport.
 */
export class SubactIdGuard {
  /** The tool-server contract itself; the guard is this plus the MCP plumbing. */
  private readonly subactid: SubactIdToolServer;
  private readonly tools: Map<string, RoutePolicy>;
  private readonly requireActor: boolean;
  private readonly maxDelegationDepth: number;
  private readonly log: (event: CallEvent) => void;
  private readonly now: () => number;
  private readonly clockSkewSeconds: number;

  constructor(options: SubactIdGuardOptions) {
    if (!options.tools || typeof options.tools !== 'object') throw new Error('tools is required.');
    this.tools = new Map();
    for (const [name, policy] of Object.entries(options.tools)) {
      const scopes = (Array.isArray(policy.scope) ? policy.scope : [policy.scope]).filter(Boolean);
      if (scopes.length === 0) throw new Error(`Tool ${name} lists no scope.`);
      this.tools.set(name, { scope: scopes, highRisk: policy.highRisk === true });
    }
    this.requireActor = options.requireActor ?? true;
    this.maxDelegationDepth = options.maxDelegationDepth ?? 1;
    // The log is this package's own: an MCP call is not an HTTP request and says so.
    this.log = options.log ?? ((event) => console.error(JSON.stringify(event)));
    this.now = options.now ?? Date.now;
    this.subactid = new SubactIdToolServer({
      ...options,
      requireActor: this.requireActor,
      maxDelegationDepth: this.maxDelegationDepth,
      log: () => undefined,
    });
    // Validated by the tool server above.
    this.clockSkewSeconds = options.clockSkewSeconds ?? 60;
  }

  /**
   * The MCP SDK's `OAuthTokenVerifier`, for `requireBearerAuth({ verifier: guard })`: a verified
   * token as `AuthInfo`, with the claims under `extra.subactid`. A refusal is thrown as the SDK's own
   * error type, so the SDK's middleware answers 401 or 403 with the reason; `authenticate()` is
   * the same check with an `SubactIdAuthError` instead.
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      return await this.verify(token);
    } catch (error) {
      if (!(error instanceof SubactIdAuthError)) throw error;
      const Type =
        error.status === 401
          ? InvalidTokenError
          : error.status === 403
            ? InsufficientScopeError
            : ServerError;
      throw new Type(`${error.reason}: ${error.message}`);
    }
  }

  /** The same check as `verifyAccessToken`, refusing with an `SubactIdAuthError` that carries the status and reason. */
  async verify(token: string): Promise<AuthInfo> {
    const verified = await this.subactid.verifyToken(token);
    // The actor rules are settled here, at the transport, so an unwelcome caller never reaches a tool.
    const denial = await this.subactid.authorize(verified, {});
    if (denial) throw denial;
    // A token for a high-risk audience was just introspected by that call; the first tool call
    // of this authentication may use that answer, and no later one may.
    if (verified.claims['introspect_required'] === true) unspentIntrospection.add(verified);
    const extra: SubactIdAuthExtra = { subactid: verified };
    const clientId = verified.claims['client_id'];
    return {
      token,
      clientId:
        typeof clientId === 'string' && clientId.length > 0
          ? clientId
          : (verified.act?.sub ?? verified.sub),
      scopes: verified.scopes,
      expiresAt: verified.exp,
      extra: extra as unknown as Record<string, unknown>,
    };
  }

  /** `AuthInfo` for an `Authorization` header, or an `SubactIdAuthError` saying why not. For transports without the SDK's middleware. */
  async authenticate(authorization: string | string[] | undefined): Promise<AuthInfo> {
    const header = Array.isArray(authorization) ? undefined : authorization;
    if (header === undefined || !/^Bearer /i.test(header) || header.slice(7).trim().length === 0) {
      throw new SubactIdAuthError(401, 'missing_token', 'A bearer token is required.');
    }
    return this.verify(header.slice(7).trim());
  }

  /**
   * Answers a refused request on a Node response: the status, `WWW-Authenticate`, and a JSON
   * body naming the reason. Anything that is not an `SubactIdAuthError` is answered as 500 without
   * detail. Returns `undefined` so it can end a `catch` in one expression.
   */
  reject(response: ServerResponse, error: unknown): undefined {
    if (response.headersSent) {
      // Too late to answer; the connection is all that can be closed.
      response.destroy();
      return undefined;
    }
    const { status, headers, body } = this.subactid.refusal(error);
    response.statusCode = status;
    for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
    response.end(JSON.stringify(body));
    return undefined;
  }

  /**
   * Puts the guard in front of every tool call the server dispatches: the caller must
   * be authenticated, the tool must be listed, the token must carry the tool's scopes, and a
   * high-risk tool is introspected first unless the transport already did it for this call. Call it before registering tools; it refuses a server
   * that already has any, so no tool can slip in unguarded. Returns the same server.
   */
  protect<T extends McpServer>(server: T): T {
    const inner = server.server as unknown as {
      setRequestHandler: (schema: unknown, handler: RequestHandler) => void;
    };
    // Fail closed: if the server cannot show it has no tools yet, it is not protected.
    const registered = hasToolsRegistered(server);
    if (registered === undefined) {
      throw new Error(
        "protect() cannot see the server's request handlers; this MCP SDK version is not supported.",
      );
    }
    if (registered) {
      throw new Error('protect() must be called before any tool is registered.');
    }
    const originalSet = inner.setRequestHandler.bind(server.server);
    inner.setRequestHandler = (schema, handler) => {
      const toolCall = isToolCallSchema(schema);
      if (toolCall === undefined) {
        throw new Error(
          'protect() cannot read the method of a request schema; this MCP SDK version is not supported.',
        );
      }
      if (!toolCall) {
        originalSet(schema, handler);
        return;
      }
      originalSet(schema, async (request, extra) => {
        const params = (request as { params?: { name?: unknown; task?: unknown } }).params;
        const tool = String(params?.name ?? '');
        const denial = await this.decide(tool, extra.authInfo);
        if (denial) {
          const text = `Subact ID refused ${tool}: ${denial.message}`;
          // A task-augmented call expects a task, not a tool result; the refusal is a protocol error there.
          if (params?.task !== undefined) throw new McpError(ErrorCode.InvalidRequest, text);
          return { isError: true, content: [{ type: 'text', text }] };
        }
        return handler(request, extra);
      });
    };
    return server;
  }

  /** The decision for one call, logged either way; `undefined` means allowed. */
  async decide(
    tool: string,
    authInfo: AuthInfo | undefined,
  ): Promise<SubactIdAuthError | undefined> {
    const claims = (authInfo?.extra as SubactIdAuthExtra | undefined)?.subactid;
    const denial = await this.check(tool, claims);
    const event: CallEvent = {
      event: 'tool.call',
      at: new Date(this.now()).toISOString(),
      tool,
      decision: denial ? 'deny' : 'allow',
    };
    if (denial) event.reason = denial.reason;
    if (claims) {
      event.sub = claims.sub;
      if (claims.act) {
        event.act = claims.act.sub;
        if (claims.act.instance !== undefined) event.instance = claims.act.instance;
        event.depth = claims.act.depth;
      }
      if (claims.taskId !== undefined) event.task_id = claims.taskId;
      event.jti = claims.jti;
    }
    this.log(event);
    return denial;
  }

  private async check(
    tool: string,
    claims: TaskToken | undefined,
  ): Promise<SubactIdAuthError | undefined> {
    if (!claims) {
      return new SubactIdAuthError(401, 'missing_token', 'The call carries no verified token.');
    }
    // Checked again at each call, so a transport that authenticates once per connection, rather
    // than per request as `requireBearerAuth` does, cannot carry a token past its expiry.
    if (!(claims.exp + this.clockSkewSeconds > Math.floor(this.now() / 1000))) {
      return new SubactIdAuthError(401, 'expired', 'The token has expired.');
    }
    const policy = this.tools.get(tool);
    if (!policy) {
      return new SubactIdAuthError(
        403,
        'unknown_tool',
        'the tool has no access policy, so nobody may call it.',
      );
    }
    // `verify` introspected at the transport if the token carried `introspect_required`, so the
    // call it authenticated costs one round trip rather than two. That answer is spent here and
    // is not available to any later call, so a long-lived session introspects every call as the
    // spec requires. A tool marked high risk on a token without that claim is introspected here
    // whatever the transport did.
    return this.subactid.authorize(claims, policy, {
      alreadyIntrospected: unspentIntrospection.delete(claims),
    });
  }
}

type RequestHandler = (request: unknown, extra: { authInfo?: AuthInfo }) => unknown;

/*
 * `protect` reaches past the MCP SDK's public surface in two places, both read and neither
 * written: whether the server has dispatched a `tools/call` handler yet, and which request a
 * schema handed to `setRequestHandler` is for. Each has a second way of being answered, and
 * when neither works the answer is "unknown", which the caller turns into a refusal rather
 * than a guess. Verified against every minor of `@modelcontextprotocol/sdk` from 1.20 to 1.30.
 */

/** Whether any tool is registered: `true` or `false` when the server can show it, `undefined` when it cannot. */
function hasToolsRegistered(server: McpServer): boolean | undefined {
  const handlers = (server.server as unknown as { _requestHandlers?: unknown })._requestHandlers;
  if (handlers instanceof Map) return handlers.has('tools/call');
  const tools = (server as unknown as { _registeredTools?: unknown })._registeredTools;
  if (typeof tools === 'object' && tools !== null) return Object.keys(tools).length > 0;
  return undefined;
}

/** Whether `schema` is the `tools/call` request: by its method literal, or by what it accepts. */
function isToolCallSchema(schema: unknown): boolean | undefined {
  const candidate = schema as
    | {
        shape?: { method?: { value?: unknown } };
        safeParse?: (value: unknown) => { success: boolean };
      }
    | undefined;
  const literal = candidate?.shape?.method?.value;
  if (typeof literal === 'string') return literal === 'tools/call';
  if (typeof candidate?.safeParse === 'function') {
    return candidate.safeParse({ method: 'tools/call', params: { name: 'tool', arguments: {} } })
      .success;
  }
  return undefined;
}
