/** What both apps serve, so the only difference between them is the framework. */
import { SubactIdToolServer } from '@subactid/server';

/**
 * One tool server. `requireActor: false` makes the server's own default permissive, so each
 * route says for itself whether only an agent may call it; a server that is agent-only
 * throughout can leave the default alone and say nothing per route.
 */
export const subactid = new SubactIdToolServer({
  issuer: process.env['SUBACTID_ISSUER'] ?? 'http://127.0.0.1:5100',
  // The quickstart's issuer is plain http on a name that is not loopback; say so to use it.
  allowInsecureHttp: process.env['SUBACTID_ALLOW_INSECURE_HTTP'] === 'true',
  audience: process.env['SUBACTID_AUDIENCE'] ?? 'https://jira.internal',
  requireActor: false,
});

export const port = Number(process.env['PORT'] ?? 4000);

export function issuesFor(
  sub: string,
  query: string,
): { issues: { id: string; summary: string }[] } {
  return { issues: [{ id: 'PROJ-1', summary: `"${query}" reported by ${sub}` }] };
}
