/**
 * A Jira tool server on Express, behind Subact ID. Every route says what it needs; the middleware
 * validates the task token against the control plane's keys, enforces the scope, introspects
 * the high-risk route on every request, and logs the human and the agent either way.
 *
 *   SUBACTID_ISSUER    the control plane's issuer, exactly as it is configured there
 *                      (`SubactId:Issuer`), since every token's `iss` must equal it; the keys
 *                      are fetched from under it. http://subactid:5100 for the quickstart, with
 *                      `127.0.0.1 subactid` in /etc/hosts. http://127.0.0.1:5100 by default.
 *   SUBACTID_ALLOW_INSECURE_HTTP  `true` to accept a plain http issuer that is not on a
 *                      loopback host, as the quickstart's is. Never against a real control plane
 *   SUBACTID_AUDIENCE  what this server is; https://jira.internal by default
 *   PORT               where to listen on 127.0.0.1; 4000 by default
 *
 * examples/agent calls `GET /issues` here. The quickstart's own tool server, on port 8082, is a
 * different program with different routes (`POST /tools/{tool}`).
 */
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

// A human's own token is enough here, because this route only tells them who they are.
app.get('/whoami', subactIdExpress(subactid, {}), (request, response) => {
  const claims = claimsOf(request as SubactIdRequest);
  response.json({ sub: claims?.sub, act: claims?.act?.sub ?? null, scope: claims?.scopes });
});

app.listen(port, '127.0.0.1', () => console.log(`jira on express listening on ${port}`));
