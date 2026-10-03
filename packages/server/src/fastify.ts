import { SubactIdAuthError } from './errors.js';
import type { RoutePolicy, SubactIdToolServer } from './validator.js';
import type { TaskToken } from './token.js';

/** As much of a Fastify request as the hook touches. */
export interface SubactIdFastifyRequest {
  method?: string | undefined;
  url?: string | undefined;
  routeOptions?: { url?: string | undefined; config?: unknown } | undefined;
  headers: { authorization?: string | string[] | undefined };
  /** The verified claims, set by the hook once the caller is through. */
  subactid?: TaskToken;
}

/** As much of a Fastify reply as the hook touches. */
export interface SubactIdFastifyReply {
  code(status: number): SubactIdFastifyReply;
  header(name: string, value: string): SubactIdFastifyReply;
  send(payload: unknown): unknown;
}

/**
 * A Fastify hook for one route: every request must carry a task token this control plane
 * issued for this server, satisfying `policy`. A refusal is answered here and the handler
 * never runs. What got through is on `request.subactid`.
 *
 *     app.get('/issues', { onRequest: subactIdFastify(subactid, { scope: 'jira:read' }) }, handler);
 */
export function subactIdFastify(
  subactid: SubactIdToolServer,
  policy: RoutePolicy,
): (request: SubactIdFastifyRequest, reply: SubactIdFastifyReply) => Promise<void> {
  return async (request, reply) => {
    try {
      request.subactid = await subactid.guard(
        request.headers.authorization,
        policy,
        routeOf(request),
      );
    } catch (error) {
      const { status, headers, body } = subactid.refusal(error);
      reply.code(status);
      for (const [name, value] of Object.entries(headers)) reply.header(name, value);
      await reply.send(body);
    }
  };
}

/**
 * A Fastify plugin that guards every route in the scope it is registered on, taking each
 * route's policy from that route's own `config.subactid`. A route with no `config.subactid` is refused,
 * so a route cannot be left open by forgetting to say what it needs.
 *
 *     await app.register(subactIdFastifyPlugin(subactid));
 *     app.get('/issues', { config: { subactid: { scope: 'jira:read' } } }, handler);
 *
 * `unguarded` names the few routes that are nobody's business to authenticate, a health check
 * being the usual one. An entry is a route as Fastify knows it, either `/healthz` for every
 * method or `GET /healthz` for one. A route that has a policy is guarded whatever `unguarded`
 * says, so naming a path there can never quietly undo a policy someone wrote.
 */
export function subactIdFastifyPlugin(
  subactid: SubactIdToolServer,
  options: { unguarded?: string[] } = {},
): (app: { addHook: (name: 'onRequest', hook: SubactIdFastifyHook) => unknown }) => Promise<void> {
  const unguarded = new Set(options.unguarded ?? []);
  const plugin = async (app: {
    addHook: (name: 'onRequest', hook: SubactIdFastifyHook) => unknown;
  }): Promise<void> => {
    app.addHook('onRequest', async (request, reply) => {
      const config = request.routeOptions?.config;
      const policy =
        typeof config === 'object' && config !== null
          ? (config as { subactid?: RoutePolicy }).subactid
          : undefined;
      if (policy !== undefined) {
        await subactIdFastify(subactid, policy)(request, reply);
        return;
      }
      const url = request.routeOptions?.url;
      if (
        url !== undefined &&
        (unguarded.has(url) || unguarded.has(`${request.method ?? 'GET'} ${url}`))
      ) {
        return;
      }
      // Nothing says what this route needs, so nobody may have it.
      const denial = new SubactIdAuthError(
        403,
        'unknown_route',
        'the route has no access policy, so nobody may call it.',
      );
      subactid.log(routeOf(request), undefined, denial);
      const { status, headers, body } = subactid.refusal(denial);
      reply.code(status);
      for (const [name, value] of Object.entries(headers)) reply.header(name, value);
      await reply.send(body);
    });
  };
  // Fastify wraps a plugin in its own scope unless it is told the plugin belongs to its parent's.
  return Object.assign(plugin, { [Symbol.for('skip-override')]: true });
}

type SubactIdFastifyHook = (
  request: SubactIdFastifyRequest,
  reply: SubactIdFastifyReply,
) => Promise<void>;

/** `GET /issues/:id`: the route as Fastify knows it when it can, the path without its query otherwise. */
function routeOf(request: SubactIdFastifyRequest): string {
  const method = request.method ?? 'GET';
  const pattern = request.routeOptions?.url;
  if (typeof pattern === 'string' && pattern.length > 0) return `${method} ${pattern}`;
  const url = request.url ?? '/';
  return `${method} ${url.split('?')[0] ?? '/'}`;
}
