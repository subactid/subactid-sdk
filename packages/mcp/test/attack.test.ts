import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SubactIdGuard, type CallEvent } from '../src/guard.js';
import { audience, FakeControlPlane, issuer } from '../../server/test/control-plane.js';

const start = Date.UTC(2026, 8, 11, 12, 0, 0);

describe('attack: high-risk introspection on a long-lived session', () => {
  let plane: FakeControlPlane;
  let events: CallEvent[];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(start);
    plane = new FakeControlPlane(() => Date.now());
    events = [];
  });
  afterEach(() => vi.useRealTimers());

  function guard(extra = {}): SubactIdGuard {
    return new SubactIdGuard({
      issuer,
      audience,
      tools: {
        search_issues: { scope: 'jira:read' },
        add_comment: { scope: ['jira:read', 'jira:comment'], highRisk: true },
      },
      fetch: plane.fetch,
      log: (e) => events.push(e),
      ...extra,
    });
  }

  it('introspects on every call of a high-risk tool', async () => {
    const g = guard();
    const auth = await g.verify(plane.token());
    plane.introspections.length = 0;
    await g.decide('add_comment', auth);
    await g.decide('add_comment', auth);
    await g.decide('add_comment', auth);
    expect(plane.introspections.length).toBe(3);
  });

  it('introspects on every call when the audience itself is high risk', async () => {
    const g = guard();
    // introspect_required is the control plane's own marking of a high-risk audience.
    const auth = await g.verify(plane.token({ introspect_required: true }));
    // The transport's own check spends one, and it covers the call it authenticated.
    expect(plane.introspections.length).toBe(1);

    // A long-lived transport (stdio) authenticates once and then dispatches many calls. Three
    // calls must cost three introspections however many times the caller authenticated.
    await g.decide('search_issues', auth);
    await g.decide('search_issues', auth);
    await g.decide('search_issues', auth);

    expect(plane.introspections.length).toBe(3);
  });

  it('refuses a revoked token on the next call of a high-risk audience', async () => {
    const g = guard();
    const auth = await g.verify(plane.token({ introspect_required: true }));
    expect(await g.decide('search_issues', auth)).toBeUndefined();

    // The operator revokes the task. The very next call must be refused.
    plane.introspection = { active: false, revocation_reason: 'operator_kill_switch' };
    expect(await g.decide('search_issues', auth)).toMatchObject({ reason: 'not_active' });
  });

  it('refuses a revoked token on the next call of a high-risk tool', async () => {
    const g = guard();
    const auth = await g.verify(plane.token());
    expect(await g.decide('add_comment', auth)).toBeUndefined();
    plane.introspection = { active: false, revocation_reason: 'operator_kill_switch' };
    expect(await g.decide('add_comment', auth)).toMatchObject({ reason: 'not_active' });
  });
});
