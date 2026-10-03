import type { RoutePolicy, SubactIdToolServer } from './validator.js';
import type { TaskToken } from './token.js';

/** As much of an Express request as the middleware touches. */
export interface SubactIdRequest {
  method?: string | undefined;
  url?: string | undefined;
  originalUrl?: string | undefined;
  route?: { path?: string | undefined } | undefined;
  baseUrl?: string | undefined;
  headers: { authorization?: string | string[] | undefined };
  /** The verified claims, set by the middleware once the caller is through. */
  subactid?: TaskToken;
}

/** As much of an Express response as the middleware touches. */
export interface SubactIdResponse {
  status(code: number): unknown;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
}

/** The verified claims of a request the middleware let through, or `undefined` on one it did not guard. */
export function claimsOf(request: SubactIdRequest): TaskToken | undefined {
  return request.subactid;
}

/**
 * Express middleware for one route or router: every request must carry a task token this
 * control plane issued for this server, satisfying `policy`. A refusal is answered here, with
 * the status, `WWW-Authenticate` and reason, and the handler never runs. What got through is
 * on `req.subactid`.
 *
 *     app.get('/issues', subactIdExpress(subactid, { scope: 'jira:read' }), handler);
 */
export function subactIdExpress(
  subactid: SubactIdToolServer,
  policy: RoutePolicy,
): (request: SubactIdRequest, response: SubactIdResponse, next: (error?: unknown) => void) => void {
  return (request, response, next) => {
    subactid
      .guard(request.headers.authorization, policy, routeOf(request))
      .then((claims) => {
        request.subactid = claims;
        next();
      })
      .catch((error: unknown) => {
        const { status, headers, body } = subactid.refusal(error);
        response.status(status);
        for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
        response.json(body);
      });
  };
}

/** `GET /issues/:id`: the route as the framework knows it when it can, the path without its query otherwise. */
function routeOf(request: SubactIdRequest): string {
  const method = request.method ?? 'GET';
  const pattern = request.route?.path;
  if (typeof pattern === 'string' && pattern.length > 0) {
    return `${method} ${(request.baseUrl ?? '') + pattern}`;
  }
  const url = request.originalUrl ?? request.url ?? '/';
  return `${method} ${url.split('?')[0] ?? '/'}`;
}
