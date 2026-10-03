import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  AuditShapeError,
  canonicalRecordJson,
  checkpointSignedBytes,
  leafHash,
  verifyAuditRecord,
  verifyCheckpoint,
  verifyCheckpointChain,
  verifyInclusion,
  type AuditCheckpoint,
  type AuditProof,
  type AuditRecord,
  type AuditVerification,
} from '../src/audit.js';
import { SubactIdAuthError } from '../src/errors.js';
import { JwksCache } from '../src/jwks.js';
import { FakeControlPlane, issuer, ledger } from './control-plane.js';

/**
 * Canonical JSON and leaf vectors produced by the control plane's own code
 * (`SubactId.Core.Audit.AuditHash` and `MerkleTree`), not written here from the prose of spec
 * section 7. If this SDK's idea of the canonical form ever drifts from the server's, these are
 * what says so.
 */
const vectors = JSON.parse(
  readFileSync(new URL('./fixtures/canonical.json', import.meta.url), 'utf8'),
) as { vectors: { about: string; record: AuditRecord; canonical_json: string; leaf: string }[] };

/**
 * Every tree shape from one leaf to seventeen, with every leaf's audit path, produced by
 * `SubactId.Core.Audit.MerkleTree`. A captured ledger only holds the shapes its traffic happened to
 * make; a fold that is wrong for, say, nine leaves would pass everything else in this file.
 */
const merkle = JSON.parse(
  readFileSync(new URL('./fixtures/merkle.json', import.meta.url), 'utf8'),
) as {
  trees: {
    tree_size: number;
    root_hash: string;
    proofs: { leaf_index: number; leaf: string; audit_path: string[] }[];
  }[];
};

const decoder = new TextDecoder();
const checkpointsById = new Map(ledger.checkpoints.map((c) => [c.checkpoint_id, c]));

/** The captured ledger's records, each with the proof and checkpoint the instance gave for it. */
const sealed = ledger.records.map((record) => ({
  record,
  proof: ledger.proofs[String(record.seq)] as AuditProof,
  checkpoint: checkpointsById.get(record.checkpoint as number) as AuditCheckpoint,
}));

function expectFault(result: AuditVerification, fault: string): void {
  expect(result.ok).toBe(false);
  expect(result.ok === false && result.fault).toBe(fault);
}

describe('canonical JSON', () => {
  it.each(vectors.vectors.map((v) => [v.about, v] as const))(
    'reproduces the bytes the server hashed: %s',
    async (_about, vector) => {
      expect(decoder.decode(canonicalRecordJson(vector.record))).toBe(vector.canonical_json);
      expect(await leafHash(vector.record)).toBe(vector.leaf);
    },
  );

  it('leaves seq and checkpoint out, because neither is a fact about the event', () => {
    const [{ record }] = vectors.vectors as [{ record: AuditRecord }];
    const json = decoder.decode(canonicalRecordJson({ ...record, seq: 99, checkpoint: 7 }));
    expect(json).not.toContain('seq');
    expect(json).not.toContain('checkpoint');
    expect(json).toBe(decoder.decode(canonicalRecordJson({ ...record, seq: 1, checkpoint: 1 })));
  });

  it('writes no count on a record that stands for one event', () => {
    const record = plain();
    expect(decoder.decode(canonicalRecordJson(record))).not.toContain('count');
    // A pipeline that fills absent keys in with nulls has not changed the record, so it has not
    // changed the leaf either.
    expect(decoder.decode(canonicalRecordJson({ ...record, count: null as never }))).toBe(
      decoder.decode(canonicalRecordJson(record)),
    );
  });

  it('refuses a key spec section 7 does not publish, rather than quietly dropping it', () => {
    // Dropping it would let a record be shown to a reader carrying a field nobody sealed, under
    // a verification that passed.
    expect(() => canonicalRecordJson({ ...plain(), admin_override: true } as never)).toThrow(
      AuditShapeError,
    );
  });

  it('refuses a timestamp that is not the form the leaf was taken over', () => {
    for (const ts of [
      '2026-09-09T14:03:41.33Z',
      '2026-09-09T14:03:41Z',
      '2026-09-09T14:03:41.330+00:00',
    ]) {
      expect(() => canonicalRecordJson({ ...plain(), ts })).toThrow(AuditShapeError);
    }
  });

  it('refuses a record missing a field its canonical form writes', () => {
    const { reason: _reason, ...rest } = plain();
    expect(() => canonicalRecordJson(rest as AuditRecord)).toThrow(AuditShapeError);
  });

  it('refuses a string holding an unpaired surrogate', () => {
    // The one place this canonical form is knowably not the server's: .NET writes an unpaired
    // surrogate as U+FFFD, so no leaf was ever taken over one. Saying so beats the bare
    // `not_included` a silent mismatch would give. A matched pair is of course fine.
    expect(() => canonicalRecordJson({ ...plain(), reason: 'lone \uD83D' })).toThrow(
      AuditShapeError,
    );
    expect(() => canonicalRecordJson({ ...plain(), reason: 'lone \uDE00' })).toThrow(
      AuditShapeError,
    );
    expect(() => canonicalRecordJson({ ...plain(), reason: 'paired \u{1F600}' })).not.toThrow();
  });

  it('refuses a count too large for this runtime to carry exactly', () => {
    expect(() => canonicalRecordJson({ ...plain(), count: 2 ** 53 })).toThrow(AuditShapeError);
  });
});

describe('a record captured from a running control plane', () => {
  it.each(sealed.map((s) => [s.record.seq, s] as const))(
    'record %i proves itself into the root its checkpoint signed',
    async (_seq, { record, proof, checkpoint }) => {
      await expect(verifyAuditRecord(record, proof, checkpoint, ledger.jwks)).resolves.toEqual({
        ok: true,
      });
    },
  );

  it.each(
    sealed.flatMap(({ record, proof, checkpoint }) =>
      (['ts', 'event', 'agent_id', 'sponsor', 'audience', 'scope', 'jti', 'reason'] as const)
        .filter((field) => typeof record[field] === 'string')
        .map((field) => [`${record.seq}.${field}`, { record, proof, checkpoint, field }] as const),
    ),
  )(
    'fails when %s is changed by one character',
    async (_what, { record, proof, checkpoint, field }) => {
      const value = record[field] as string;
      // Every edit here leaves a record that still looks legitimate, so what fails is the leaf
      // and not the shape: a timestamp keeps its published form and loses a millisecond digit
      // rather than its `Z`, and everything else loses its last *code point* rather than its
      // last code unit — an audience ending in an emoji would otherwise be cut mid-pair.
      const edited = {
        ...record,
        [field]:
          field === 'ts'
            ? value.replace(
                /\.(\d)(\d\d)Z$/,
                (_m, a: string, rest: string) => `.${a === '9' ? '8' : '9'}${rest}Z`,
              )
            : [...value].slice(0, -1).join('') + ([...value].at(-1) === 'a' ? 'b' : 'a'),
      };
      expect(edited[field]).not.toBe(value);
      expectFault(await verifyAuditRecord(edited, proof, checkpoint, ledger.jwks), 'not_included');
    },
  );

  it('fails when a summary record loses its count', async () => {
    const summary = sealed.find(({ record }) => record.count !== undefined);
    expect(summary).toBeDefined();
    const { record, proof, checkpoint } = summary as (typeof sealed)[number];
    const { count: _count, ...without } = record;
    expectFault(await verifyAuditRecord(without, proof, checkpoint, ledger.jwks), 'not_included');
  });

  it('fails when a record is offered another record’s proof', async () => {
    const [first, second] = sealed as [(typeof sealed)[number], (typeof sealed)[number]];
    expectFault(
      await verifyAuditRecord(first.record, second.proof, first.checkpoint, ledger.jwks),
      'mismatched',
    );
  });

  it('fails when the proof carries a checkpoint other than the one held', async () => {
    const inOne = sealed.filter(({ record }) => record.checkpoint === 1);
    const other = ledger.checkpoints.find((c) => c.checkpoint_id !== 1) as AuditCheckpoint;
    const { record, proof } = inOne[0] as (typeof sealed)[number];
    expectFault(await verifyAuditRecord(record, proof, other, ledger.jwks), 'mismatched');
  });

  it('fails when the proof and the held checkpoint disagree on the root', async () => {
    const { record, proof, checkpoint } = sealed[0] as (typeof sealed)[number];
    const rewritten = {
      ...proof,
      checkpoint: { ...proof.checkpoint, root_hash: flip(checkpoint.root_hash) },
    };
    expectFault(await verifyAuditRecord(record, rewritten, checkpoint, ledger.jwks), 'mismatched');
  });

  it('refuses a record or a proof whose sequence number is not one', async () => {
    // Neither `seq` nor the checkpoint a record names is inside the canonical form, so nothing
    // else has looked at them — and a range check against a value that is not a number passes.
    const { record, proof, checkpoint } = sealed[0] as (typeof sealed)[number];
    expectFault(
      await verifyAuditRecord(
        { ...record, seq: undefined as never },
        proof,
        checkpoint,
        ledger.jwks,
      ),
      'malformed_record',
    );
    expectFault(
      await verifyAuditRecord(record, { ...proof, seq: '1' as never }, checkpoint, ledger.jwks),
      'malformed_proof',
    );
    expectFault(
      await verifyAuditRecord(
        { ...record, checkpoint: '1' as never },
        proof,
        checkpoint,
        ledger.jwks,
      ),
      'malformed_record',
    );
  });

  it('refuses a record the sealing pass has not reached', async () => {
    const { record, proof, checkpoint } = sealed[0] as (typeof sealed)[number];
    expectFault(
      await verifyAuditRecord({ ...record, checkpoint: null }, proof, checkpoint, ledger.jwks),
      'unsealed',
    );
  });

  it('fails when the audit path is reordered', async () => {
    const long = sealed.find(({ proof }) => proof.audit_path.length > 1) as (typeof sealed)[number];
    const reversed = { ...long.proof, audit_path: [...long.proof.audit_path].reverse() };
    expectFault(
      await verifyAuditRecord(long.record, reversed, long.checkpoint, ledger.jwks),
      'not_included',
    );
  });

  it('fails when the leaf is claimed at another position', async () => {
    const inSix = sealed.find(
      ({ proof, checkpoint }) => checkpoint.tree_size > 2 && proof.leaf_index === 0,
    ) as (typeof sealed)[number];
    const moved = { ...inSix.proof, leaf_index: 1 };
    expectFault(
      await verifyAuditRecord(inSix.record, moved, inSix.checkpoint, ledger.jwks),
      'not_included',
    );
  });
});

describe('a checkpoint captured from a running control plane', () => {
  it.each(ledger.checkpoints.map((c) => [c.checkpoint_id, c] as const))(
    'checkpoint %i is signed by a key the instance publishes',
    async (_id, checkpoint) => {
      await expect(verifyCheckpoint(checkpoint, ledger.jwks)).resolves.toEqual({ ok: true });
    },
  );

  it('takes its key from the JwksCache the tool server already has', async () => {
    let fetches = 0;
    const cache = new JwksCache({
      jwksUri: `${issuer}/.well-known/jwks.json`,
      fetch: () => {
        fetches++;
        return Promise.resolve(
          new Response(JSON.stringify(ledger.jwks), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        );
      },
      now: () => Date.now(),
    });
    for (const checkpoint of ledger.checkpoints) {
      await expect(verifyCheckpoint(checkpoint, cache)).resolves.toEqual({ ok: true });
    }
    // Every checkpoint here is signed by the one published key, so the set is fetched once and
    // the rest are checked against what is already cached.
    expect(fetches).toBe(1);
  });

  it.each((['closed_at', 'root_hash', 'prev_checkpoint_hash'] as const).map((f) => [f] as const))(
    'fails when %s is changed',
    async (field) => {
      const withLink = ledger.checkpoints.find(
        (c) => c.prev_checkpoint_hash !== null,
      ) as AuditCheckpoint;
      const value = withLink[field] as string;
      const edited = {
        ...withLink,
        [field]: field === 'closed_at' ? value.replace(/\.\d{3}Z$/, '.999Z') : flip(value),
      };
      expect(edited[field]).not.toBe(value);
      expectFault(await verifyCheckpoint(edited, ledger.jwks), 'bad_signature');
    },
  );

  it.each(
    (['checkpoint_id', 'first_seq', 'last_seq', 'tree_size'] as const).map((f) => [f] as const),
  )('fails when %s is changed', async (field) => {
    const [checkpoint] = ledger.checkpoints as [AuditCheckpoint];
    expectFault(
      await verifyCheckpoint({ ...checkpoint, [field]: checkpoint[field] + 1 }, ledger.jwks),
      'bad_signature',
    );
  });

  it('fails when the signature is another checkpoint’s', async () => {
    const [first, second] = ledger.checkpoints as [AuditCheckpoint, AuditCheckpoint];
    expectFault(
      await verifyCheckpoint({ ...first, signature: second.signature }, ledger.jwks),
      'bad_signature',
    );
  });

  it('refuses a checkpoint naming a key the set does not publish', async () => {
    const [checkpoint] = ledger.checkpoints as [AuditCheckpoint];
    expectFault(
      await verifyCheckpoint({ ...checkpoint, kid: 'retired-key' }, ledger.jwks),
      'unknown_key',
    );
    expectFault(await verifyCheckpoint(checkpoint, { keys: [] }), 'unknown_key');
  });

  it('does not call keys it could not fetch an unknown key', async () => {
    // An auditor told `unknown_key` when the control plane was merely unreachable would read a
    // network outage as a broken seal, so that refusal travels rather than being answered.
    const cache = new JwksCache({
      jwksUri: `${issuer}/.well-known/jwks.json`,
      fetch: () => Promise.reject(new TypeError('fetch failed')),
      now: () => Date.now(),
    });
    const [checkpoint] = ledger.checkpoints as [AuditCheckpoint];
    const refusal = await verifyCheckpoint(checkpoint, cache).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(refusal).toBeInstanceOf(SubactIdAuthError);
    expect((refusal as SubactIdAuthError).reason).toBe('keys_unavailable');
  });

  it('refuses a checkpoint carrying a key spec section 7.0 does not publish', () => {
    const [checkpoint] = ledger.checkpoints as [AuditCheckpoint];
    expect(() => checkpointSignedBytes({ ...checkpoint, note: 'hello' } as never)).toThrow(
      AuditShapeError,
    );
  });
});

describe('the checkpoint chain', () => {
  it('holds end to end over the captured ledger', async () => {
    await expect(verifyCheckpointChain(ledger.checkpoints, ledger.jwks)).resolves.toEqual({
      ok: true,
    });
  });

  it('breaks when a checkpoint is taken out of the middle', async () => {
    const cut = [...ledger.checkpoints];
    cut.splice(2, 1);
    expectFault(await verifyCheckpointChain(cut, ledger.jwks), 'broken_chain');
  });

  it('breaks when a checkpoint is replaced by one signing another root', async () => {
    const swapped = ledger.checkpoints.map((c, i) =>
      i === 1 ? { ...c, root_hash: flip(c.root_hash) } : c,
    );
    // The link the next checkpoint carries is over the replaced one's signed bytes, so the fault
    // shows at the one after it rather than at the edit.
    expectFault(await verifyCheckpointChain(swapped, 'links-only'), 'broken_chain');
  });

  it('breaks when a range does not begin where the one before it ended', async () => {
    const shifted = ledger.checkpoints.map((c, i) =>
      i === 1 ? { ...c, first_seq: c.first_seq + 1 } : c,
    );
    expectFault(await verifyCheckpointChain(shifted, ledger.jwks), 'broken_chain');
  });

  it('accepts a page that starts partway through, and refuses one that lies about it', async () => {
    const tail = ledger.checkpoints.slice(2);
    await expect(verifyCheckpointChain(tail, ledger.jwks)).resolves.toEqual({ ok: true });
    const [head] = tail as [AuditCheckpoint];
    expectFault(
      await verifyCheckpointChain(
        [{ ...head, prev_checkpoint_hash: null }, ...tail.slice(1)],
        ledger.jwks,
      ),
      'broken_chain',
    );
  });

  it('refuses the first checkpoint of the ledger carrying a link', async () => {
    const [first, ...rest] = ledger.checkpoints as [AuditCheckpoint, ...AuditCheckpoint[]];
    expect(first.prev_checkpoint_hash).toBeNull();
    expectFault(
      await verifyCheckpointChain(
        [{ ...first, prev_checkpoint_hash: first.root_hash }, ...rest],
        ledger.jwks,
      ),
      'broken_chain',
    );
  });

  it('refuses nothing at all', async () => {
    expectFault(await verifyCheckpointChain([], ledger.jwks), 'malformed_checkpoint');
  });

  it('checks every signature too when it is given the keys', async () => {
    await expect(verifyCheckpointChain(ledger.checkpoints, ledger.jwks)).resolves.toEqual({
      ok: true,
    });
    const forged = ledger.checkpoints.map((c, i) =>
      i === 1 ? { ...c, signature: `${'0'.repeat(127)}1` } : c,
    );
    expectFault(await verifyCheckpointChain(forged, ledger.jwks), 'bad_signature');
  });

  it('links a wholly forged chain to itself, which is why the keys matter', async () => {
    // Linkage alone is self-referential: a chain rebuilt end to end links perfectly to itself.
    // Without a key set this says the checkpoints agree with each other, not that they are the
    // control plane's — so the same run that passes here must fail once the keys are given.
    const forged: AuditCheckpoint[] = [];
    let previous: string | null = null;
    for (let id = 1; id <= 3; id++) {
      const checkpoint: AuditCheckpoint = {
        checkpoint_id: id,
        first_seq: id,
        last_seq: id,
        tree_size: 1,
        root_hash: `${id}`.repeat(64).slice(0, 64),
        prev_checkpoint_hash: previous,
        closed_at: `2026-09-21T10:0${id}:00.000Z`,
        kid: 'made-up',
        signature: '0'.repeat(128),
      };
      forged.push(checkpoint);
      previous = await sha256Hex(checkpointSignedBytes(checkpoint));
    }
    await expect(verifyCheckpointChain(forged, 'links-only')).resolves.toEqual({ ok: true });
    expectFault(await verifyCheckpointChain(forged, ledger.jwks), 'unknown_key');
    // Even saying `links-only` does not make a document with no signature on it a checkpoint.
    const unsigned = forged.map((c) => ({ ...c, signature: 'not-a-signature' }));
    expectFault(await verifyCheckpointChain(unsigned, 'links-only'), 'malformed_checkpoint');
  });
});

describe('the RFC 6962 fold, over every tree shape the server can build', () => {
  it.each(merkle.trees.map((t) => [t.tree_size, t] as const))(
    'accepts every leaf of a tree of %i',
    async (_size, tree) => {
      for (const proof of tree.proofs) {
        await expect(
          verifyInclusion(
            proof.leaf,
            proof.audit_path,
            proof.leaf_index,
            tree.tree_size,
            tree.root_hash,
          ),
        ).resolves.toEqual({ ok: true });
      }
    },
  );

  it.each(merkle.trees.filter((t) => t.tree_size > 1).map((t) => [t.tree_size, t] as const))(
    'accepts no leaf of a tree of %i at any position but its own',
    async (_size, tree) => {
      for (const proof of tree.proofs) {
        for (let position = 0; position < tree.tree_size; position++) {
          if (position === proof.leaf_index) continue;
          const result = await verifyInclusion(
            proof.leaf,
            proof.audit_path,
            position,
            tree.tree_size,
            tree.root_hash,
          );
          expect(result.ok, `size ${tree.tree_size}, leaf ${proof.leaf_index} at ${position}`).toBe(
            false,
          );
        }
      }
    },
  );
});

describe('verifyInclusion', () => {
  it('takes a one-leaf checkpoint’s empty path as a whole proof', async () => {
    const alone = sealed.find(
      ({ checkpoint }) => checkpoint.tree_size === 1,
    ) as (typeof sealed)[number];
    expect(alone.proof.audit_path).toEqual([]);
    await expect(
      verifyInclusion(await leafHash(alone.record), [], 0, 1, alone.checkpoint.root_hash),
    ).resolves.toEqual({ ok: true });
  });

  it('refuses a path with a step too many or too few', async () => {
    const long = sealed.find(({ proof }) => proof.audit_path.length > 1) as (typeof sealed)[number];
    const leaf = await leafHash(long.record);
    const { audit_path: path, leaf_index: index } = long.proof;
    const { tree_size: size, root_hash: root } = long.checkpoint;
    expectFault(await verifyInclusion(leaf, path.slice(1), index, size, root), 'not_included');
    expectFault(
      await verifyInclusion(leaf, [...path, path[0] as string], index, size, root),
      'not_included',
    );
  });

  it('refuses a position outside the tree', async () => {
    const { record, proof, checkpoint } = sealed[0] as (typeof sealed)[number];
    const leaf = await leafHash(record);
    expectFault(
      await verifyInclusion(
        leaf,
        proof.audit_path,
        checkpoint.tree_size,
        checkpoint.tree_size,
        checkpoint.root_hash,
      ),
      'malformed_proof',
    );
    expectFault(
      await verifyInclusion(leaf, proof.audit_path, -1, checkpoint.tree_size, checkpoint.root_hash),
      'malformed_proof',
    );
  });

  it('refuses hashes that are not lowercase hex', async () => {
    const { record, proof, checkpoint } = sealed[0] as (typeof sealed)[number];
    const leaf = await leafHash(record);
    expectFault(
      await verifyInclusion(
        leaf.toUpperCase(),
        proof.audit_path,
        proof.leaf_index,
        checkpoint.tree_size,
        checkpoint.root_hash,
      ),
      'malformed_proof',
    );
    expectFault(
      await verifyInclusion(
        leaf,
        ['nonsense'],
        proof.leaf_index,
        checkpoint.tree_size,
        checkpoint.root_hash,
      ),
      'malformed_proof',
    );
    expectFault(
      await verifyInclusion(
        leaf,
        proof.audit_path,
        proof.leaf_index,
        checkpoint.tree_size,
        'nonsense',
      ),
      'malformed_checkpoint',
    );
  });
});

describe('the endpoints of spec section 7.1', () => {
  it('walks the checkpoints a page at a time and verifies the run', async () => {
    const plane = new FakeControlPlane(() => Date.now());
    const checkpoints = [];
    let after: number | null = null;
    let pages = 0;
    do {
      const response = await plane.fetch(
        `${issuer}/audit/checkpoints?limit=2${after === null ? '' : `&after=${after}`}`,
        { signal: AbortSignal.timeout(1000) },
      );
      const page = (await response.json()) as {
        checkpoints: AuditCheckpoint[];
        next_after: number | null;
      };
      checkpoints.push(...page.checkpoints);
      after = page.next_after;
      pages++;
    } while (after !== null);

    expect(pages).toBeGreaterThan(1);
    expect(checkpoints).toEqual(ledger.checkpoints);
    await expect(verifyCheckpointChain(checkpoints, ledger.jwks)).resolves.toEqual({ ok: true });
  });

  it('has no proof for a sequence number nothing was written at', async () => {
    const plane = new FakeControlPlane(() => Date.now());
    const response = await plane.fetch(`${issuer}/audit/records/1000000/proof`, {
      signal: AbortSignal.timeout(1000),
    });
    expect(response.status).toBe(404);
  });
});

/** A plain record, in the shape the audit query publishes: no count and no detail. */
function plain(): AuditRecord {
  return {
    seq: 10428,
    checkpoint: 271,
    ts: '2026-09-09T14:03:41.882Z',
    event: 'token.issued',
    task_id: 'task_01HQZX9K4M',
    agent_id: 'jira-triage',
    sponsor: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    audience: 'https://jira.internal',
    scope: 'jira:read jira:comment',
    jti: 'tok_01HQZX9K5P',
    delegation_depth: 1,
    decision: 'allow',
    reason: null,
  };
}

/** SHA-256 as lowercase hex, for building the forged chain the keys are supposed to catch. */
async function sha256Hex(input: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The same hex with its last digit changed, which is one byte of a hash different. */
function flip(hex: string): string {
  return `${hex.slice(0, -1)}${hex.at(-1) === '0' ? '1' : '0'}`;
}
