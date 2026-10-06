import { constants, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AssertionSigner } from '../src/assertion.js';
import { base64UrlDecode, fromUtf8 } from '../src/encoding.js';
import { SubactIdError } from '../src/errors.js';
import { ecPem, rsaPem } from './keys.js';

const now = Date.UTC(2026, 8, 11, 12, 0, 0);

function parts(jws: string): {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
} {
  const [h, c, s] = jws.split('.') as [string, string, string];
  return {
    header: JSON.parse(fromUtf8(base64UrlDecode(h))) as Record<string, unknown>,
    claims: JSON.parse(fromUtf8(base64UrlDecode(c))) as Record<string, unknown>,
    signingInput: `${h}.${c}`,
    signature: base64UrlDecode(s),
  };
}

describe('AssertionSigner', () => {
  it('mints a private_key_jwt with the RFC 7523 claims and a fresh jti each time', async () => {
    const signer = new AssertionSigner({
      agentId: 'jira-triage',
      kid: 'k1',
      privateKey: rsaPem,
      now: () => now,
    });

    const first = parts(await signer.sign('https://subactid.internal.example.com/oauth2/token'));
    const second = parts(await signer.sign('https://subactid.internal.example.com/oauth2/token'));

    expect(first.header).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'k1' });
    expect(first.claims).toMatchObject({
      iss: 'jira-triage',
      sub: 'jira-triage',
      aud: 'https://subactid.internal.example.com/oauth2/token',
      iat: now / 1000,
      exp: now / 1000 + 60,
    });
    expect(first.claims['jti']).toBeTypeOf('string');
    expect(first.claims['jti']).not.toBe(second.claims['jti']);
    const publicKey = createPublicKey(rsaPem);
    expect(verify('sha256', Buffer.from(first.signingInput), publicKey, first.signature)).toBe(
      true,
    );
  });

  it('signs ES256 with the raw r||s signature JOSE expects', async () => {
    const signer = new AssertionSigner({
      agentId: 'a',
      kid: 'k2',
      privateKey: ecPem,
      algorithm: 'ES256',
      now: () => now,
    });

    const { header, signingInput, signature } = parts(
      await signer.sign('https://subactid/oauth2/token'),
    );

    expect(header['alg']).toBe('ES256');
    expect(signature).toHaveLength(64);
    expect(
      verify(
        'sha256',
        Buffer.from(signingInput),
        { key: createPublicKey(ecPem), dsaEncoding: 'ieee-p1363' },
        signature,
      ),
    ).toBe(true);
  });

  it('signs PS256, the third algorithm the control plane accepts', async () => {
    const signer = new AssertionSigner({
      agentId: 'a',
      kid: 'k3',
      privateKey: rsaPem,
      algorithm: 'PS256',
      now: () => now,
    });

    const { header, signingInput, signature } = parts(
      await signer.sign('https://subactid/oauth2/token'),
    );

    expect(header['alg']).toBe('PS256');
    expect(
      verify(
        'sha256',
        Buffer.from(signingInput),
        {
          key: createPublicKey(rsaPem),
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: 32,
        },
        signature,
      ),
    ).toBe(true);
  });

  it('carries the instance the agent says it is, so act.instance can name it', async () => {
    const signer = new AssertionSigner({
      agentId: 'a',
      kid: 'k',
      privateKey: rsaPem,
      instance: 'pod-7f9c4b',
      now: () => now,
    });

    const { claims } = parts(await signer.sign('https://subactid/oauth2/token'));

    expect(claims['instance']).toBe('pod-7f9c4b');
  });

  it('omits instance when the agent does not name one', async () => {
    const signer = new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: rsaPem });

    const { claims } = parts(await signer.sign('https://subactid/oauth2/token'));

    expect(claims).not.toHaveProperty('instance');
  });

  it.each(['', '   '])(
    'omits a blank instance (%j), so the assertion says nothing',
    async (blank) => {
      const signer = new AssertionSigner({
        agentId: 'a',
        kid: 'k',
        privateKey: rsaPem,
        instance: blank,
        now: () => now,
      });

      const { claims } = parts(await signer.sign('https://subactid/oauth2/token'));

      expect(claims).not.toHaveProperty('instance');
    },
  );

  it('refuses an instance longer than the control plane accepts', () => {
    expect(
      () =>
        new AssertionSigner({
          agentId: 'a',
          kid: 'k',
          privateKey: rsaPem,
          instance: 'x'.repeat(129),
        }),
    ).toThrow(SubactIdError);
  });

  it('never mints an assertion the control plane would refuse for its lifetime', () => {
    expect(
      () =>
        new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: rsaPem, lifetimeSeconds: 301 }),
    ).toThrow(SubactIdError);
    expect(
      () => new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: rsaPem, lifetimeSeconds: 0 }),
    ).toThrow(SubactIdError);
    // Whole seconds only: `exp` is a NumericDate, and a fraction would put one on the wire.
    for (const lifetimeSeconds of [0.5, 59.9, Number.NaN]) {
      expect(
        () => new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: rsaPem, lifetimeSeconds }),
      ).toThrow(SubactIdError);
    }
    expect(
      () =>
        new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: rsaPem, lifetimeSeconds: 300 }),
    ).not.toThrow();
  });

  it('refuses anything but a PKCS#8 PEM, without echoing it', async () => {
    const signer = new AssertionSigner({
      agentId: 'a',
      kid: 'k',
      privateKey: '-----BEGIN RSA PRIVATE KEY-----\nSECRETMATERIAL\n-----END RSA PRIVATE KEY-----',
    });

    const error = await signer.sign('aud').catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SubactIdError);
    expect((error as Error).message).not.toContain('SECRETMATERIAL');
  });

  it('refuses a long PEM-shaped string without stalling on it', async () => {
    // A `BEGIN` marker repeated with no `END` made the regular expression that used to find the
    // body rescan from every marker, quadratic in the string; at this length the old parser ran
    // for minutes, so the test timing out is what a regression looks like.
    const hostile = '-----BEGIN PRIVATE KEY-----a'.repeat(50_000);
    const signer = new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: hostile });

    await expect(signer.sign('aud')).rejects.toBeInstanceOf(SubactIdError);
  });

  it('reports a key that does not match the algorithm', async () => {
    const signer = new AssertionSigner({
      agentId: 'a',
      kid: 'k',
      privateKey: ecPem,
      algorithm: 'RS256',
    });

    await expect(signer.sign('aud')).rejects.toThrow('could not be imported for RS256');
  });

  describe('the algorithm, when none is given', () => {
    const headerOf = async (signer: AssertionSigner) =>
      JSON.parse(
        fromUtf8(
          base64UrlDecode((await signer.sign('https://cp.example')).split('.')[0] as string),
        ),
      ) as {
        alg: string;
      };
    const ecKey = (curve: string) =>
      generateKeyPairSync('ec', { namedCurve: curve }).privateKey.export({
        type: 'pkcs8',
        format: 'pem',
      }) as string;

    it('is ES256 for the P-256 key subactid agent init writes, and the signature verifies', async () => {
      const signer = new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: ecPem });
      const jwt = await signer.sign('https://cp.example');
      const [header, claims, signature] = jwt.split('.') as [string, string, string];

      expect((await headerOf(signer)).alg).toBe('ES256');
      expect(
        verify(
          'sha256',
          Buffer.from(`${header}.${claims}`),
          { key: createPublicKey(ecPem), dsaEncoding: 'ieee-p1363' },
          base64UrlDecode(signature),
        ),
      ).toBe(true);
    });

    it('is RS256 for an RSA key, which signs PS256 only when asked', async () => {
      expect(
        (await headerOf(new AssertionSigner({ agentId: 'a', kid: 'k', privateKey: rsaPem }))).alg,
      ).toBe('RS256');
    });

    it('is read from a CryptoKey', async () => {
      const { privateKey } = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign'],
      );

      expect(
        (await headerOf(new AssertionSigner({ agentId: 'a', kid: 'k', privateKey }))).alg,
      ).toBe('ES256');
    });

    it('is what was asked for when it is given', async () => {
      const signer = new AssertionSigner({
        agentId: 'a',
        kid: 'k',
        privateKey: rsaPem,
        algorithm: 'PS256',
      });

      expect((await headerOf(signer)).alg).toBe('PS256');
    });

    it('refuses a key it cannot sign with, at the first assertion', async () => {
      // P-384 is not one of the three algorithms the control plane accepts.
      const signer = new AssertionSigner({
        agentId: 'a',
        kid: 'k',
        privateKey: ecKey('P-384'),
      });

      await expect(signer.sign('https://cp.example')).rejects.toBeInstanceOf(SubactIdError);
    });
  });
});
