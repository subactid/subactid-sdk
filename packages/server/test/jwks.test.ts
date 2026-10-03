import { beforeEach, describe, expect, it } from 'vitest';
import { SubactIdAuthError } from '../src/errors.js';
import { cacheLifetimeMs, JwksCache } from '../src/jwks.js';
import { FakeControlPlane, issuer } from './control-plane.js';

const start = Date.UTC(2026, 8, 12, 12, 0, 0);

describe('JwksCache', () => {
  let now: number;
  let plane: FakeControlPlane;

  beforeEach(() => {
    now = start;
    plane = new FakeControlPlane(() => now);
  });

  function cache(): JwksCache {
    return new JwksCache({
      jwksUri: `${issuer}/.well-known/jwks.json`,
      fetch: plane.fetch,
      now: () => now,
    });
  }

  describe('when the clock steps backwards', () => {
    it('fetches again once the set in hand claims to be good for longer than any answer allows', async () => {
      const c = cache();
      await c.get('key-1');
      expect(plane.jwksFetches).toBe(1);

      // The set was due at start + 5 minutes; from two hours earlier that is further off than
      // the longest any answer is served for, so it cannot be a lifetime this cache gave it.
      now = start - 2 * 60 * 60_000;
      await c.get('key-1');
      expect(plane.jwksFetches).toBe(2);

      // And the next one is due on the new clock, not on the old one.
      now += 300_000;
      await c.get('key-1');
      expect(plane.jwksFetches).toBe(3);
    });

    it('still fetches for an unknown kid, though the last attempt is now in the future', async () => {
      const c = cache();
      await c.get('key-1');

      now = start - 10 * 60_000;
      plane.rotate('key-2');
      await expect(c.get('key-2')).resolves.toBeDefined();
      expect(plane.jwksFetches).toBe(2);
    });

    it('still stops serving a stale set once every fetch has failed for the bound', async () => {
      const c = cache();
      await c.get('key-1');
      plane.jwksFails = true;

      now = start - 2 * 60 * 60_000;
      await expect(c.get('key-1')).resolves.toBeDefined();
      expect(plane.jwksFetches).toBe(2);

      now += 60 * 60_000;
      const refused = await c.get('key-1').then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(refused).toBeInstanceOf(SubactIdAuthError);
      expect((refused as SubactIdAuthError).reason).toBe('keys_unavailable');
    });
  });

  describe('cacheLifetimeMs', () => {
    it.each([
      ['max-age=300', 300_000],
      ['max-age=9999999999', 3_600_000],
      ['max-age=99999999999999999999999999', 3_600_000],
      ['max-age=0', 30_000],
      ['max-age=-1', 300_000],
      ['max-age=abc', 300_000],
    ])('reads %s as %i ms', (header, ttl) => {
      expect(cacheLifetimeMs(header, 300_000)).toBe(ttl);
    });
  });
});
