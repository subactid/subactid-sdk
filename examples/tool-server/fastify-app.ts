/**
 * The same Jira tool server on Fastify. The plugin guards every route in the scope it is
 * registered on and takes each route's policy from that route's own `config.subactid`, so a route
 * whose policy someone forgot is refused rather than left open. Configured as express-app.ts is.
 */
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

app.post<{ Params: { id: string } }>(
  '/issues/:id/comments',
  { config: { subactid: { scope: 'jira:comment', highRisk: true, requireActor: true } } },
  async (request, reply) => {
    const claims = (request as SubactIdFastifyRequest).subactid;
    return reply
      .code(201)
      .send({ issue: request.params.id, by: claims?.act?.sub, for: claims?.sub });
  },
);

app.get('/whoami', { config: { subactid: {} } }, async (request) => {
  const claims = (request as SubactIdFastifyRequest).subactid;
  return { sub: claims?.sub, act: claims?.act?.sub ?? null, scope: claims?.scopes };
});

app.get('/healthz', async () => ({ status: 'ok' }));

await app.listen({ port, host: '127.0.0.1' });
console.log(`jira on fastify listening on ${port}`);
