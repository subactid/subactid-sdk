import { SubactIdAuthError } from './errors.js';
import { importP256 } from './jwks.js';

/**
 * Checking the audit ledger from outside the control plane that wrote it (spec section 7).
 *
 * The ledger seals itself in windows: a background pass builds a Merkle tree over each run of
 * records, signs the root, and links that checkpoint to the one before it. So a record is
 * provably in the ledger if its leaf folds along a published audit path to a root that a key in
 * the published JWKS signed — and none of that needs the server's word for anything. Everything
 * here works on exactly what `GET /audit`, `GET /audit/checkpoints`,
 * `GET /audit/records/{seq}/proof` and the JWKS return, so a tool server, an auditor or a CI job
 * can hold a checkpoint somewhere the control plane's database cannot reach and check the rest
 * against it later.
 *
 * Nothing here does any I/O: fetching the four documents is the caller's, which is what lets the
 * same functions run against a live instance, an archived export or a file kept off-site.
 */

/** The `keys` member of a JWKS, or anything that resolves a `kid` — `JwksCache` does. */
export interface CheckpointKeys {
  /** The verification key published under `kid`. Rejects when the key set has no such key. */
  get(kid: string): Promise<CryptoKey>;
}

/** Where a checkpoint's signing key comes from: a fetched-and-cached set, or a JWKS document. */
export type CheckpointKeySource = CheckpointKeys | { keys?: unknown };

/**
 * One ledger record exactly as the audit query and the audit sink publish it. The field names
 * are the wire's, not this SDK's, because these are the bytes the leaf was taken over: a record
 * renamed on the way in is a record that cannot be checked. `count` and `detail` are absent
 * rather than null on the records that do not carry them, and that difference is load-bearing —
 * see {@link canonicalRecordJson}.
 */
export interface AuditRecord {
  seq: number;
  /** The checkpoint sealing this record, or `null` while the sealing pass has not reached it. */
  checkpoint: number | null;
  /** UTC ISO 8601 with exactly three fractional digits, as published. */
  ts: string;
  event: string;
  task_id: string | null;
  agent_id: string | null;
  sponsor: string | null;
  audience: string | null;
  scope: string | null;
  jti: string | null;
  delegation_depth: number | null;
  decision: string | null;
  reason: string | null;
  /** Occurrences a summary record stands for. Absent on every other record, which counts as one. */
  count?: number;
  /** What the record is about where no other field holds it. Absent on every record but `audit.archived`. */
  detail?: string;
}

/** One signed checkpoint exactly as `GET /audit/checkpoints` publishes it. Hashes are lowercase hex. */
export interface AuditCheckpoint {
  checkpoint_id: number;
  first_seq: number;
  last_seq: number;
  /** Records the range held when it was sealed, which is the tree's leaf count. */
  tree_size: number;
  root_hash: string;
  /** SHA-256 of the previous checkpoint's signed bytes; `null` on the first checkpoint. */
  prev_checkpoint_hash: string | null;
  /** UTC ISO 8601 with exactly three fractional digits, as published. */
  closed_at: string;
  kid: string;
  signature: string;
}

/** The answer of `GET /audit/records/{seq}/proof`. */
export interface AuditProof {
  seq: number;
  checkpoint: AuditCheckpoint;
  /** The record's position among the checkpoint's leaves, counted from zero in sequence order. */
  leaf_index: number;
  /** Sibling hashes, closest first. Empty when the checkpoint sealed one record, which is a whole proof. */
  audit_path: string[];
}

/** Why a check failed. Stable strings, safe to log. */
export type AuditFault =
  /** The record is not the shape section 7 publishes, so its leaf cannot be rebuilt. */
  | 'malformed_record'
  /** The checkpoint is not the shape section 7 publishes, so its signed bytes cannot be rebuilt. */
  | 'malformed_checkpoint'
  /** The proof is not the shape section 7.1 publishes. */
  | 'malformed_proof'
  /** The record is in the ledger but no checkpoint covers it. */
  | 'unsealed'
  /** The documents do not describe each other: a proof for another record, or another checkpoint. */
  | 'mismatched'
  /** The checkpoint names a key the published set does not hold. */
  | 'unknown_key'
  /** The signature over the checkpoint's canonical bytes does not verify. */
  | 'bad_signature'
  /** A checkpoint does not follow on from the one before it. */
  | 'broken_chain'
  /** The audit path does not fold the leaf to the signed root. */
  | 'not_included';

/**
 * The outcome of a check. A failure says which, so a caller can log the fault and a person can
 * read the detail; neither is ever the thing that was being checked.
 *
 * It is an object rather than a boolean on purpose: every one of these is async, and
 * `if (verifyCheckpoint(c, keys))` on a boolean-returning promise is always true. `ok` on an
 * unawaited promise is `undefined`, so the same slip fails closed here.
 */
export type AuditVerification = { ok: true } | { ok: false; fault: AuditFault; detail: string };

/** A document handed to the verifier is not the shape spec section 7 publishes. */
export class AuditShapeError extends Error {
  readonly fault: 'malformed_record' | 'malformed_checkpoint' | 'malformed_proof';

  constructor(
    fault: 'malformed_record' | 'malformed_checkpoint' | 'malformed_proof',
    message: string,
  ) {
    super(message);
    this.name = 'AuditShapeError';
    this.fault = fault;
  }
}

const ok: AuditVerification = { ok: true };
const failed = (fault: AuditFault, detail: string): AuditVerification => ({
  ok: false,
  fault,
  detail,
});

/**
 * The keys of a record's canonical JSON, in the order they are written — lexicographic, which is
 * the order the control plane writes them in and the order they have to be rebuilt in.
 * `seq` and `checkpoint` are not among them: neither is a fact about the event.
 */
const recordKeys = [
  'agent_id',
  'audience',
  'count',
  'decision',
  'delegation_depth',
  'detail',
  'event',
  'jti',
  'reason',
  'scope',
  'sponsor',
  'task_id',
  'ts',
] as const;

/** The keys of a checkpoint's signed bytes: everything it publishes except the signature itself. */
const checkpointKeys = [
  'checkpoint_id',
  'closed_at',
  'first_seq',
  'kid',
  'last_seq',
  'prev_checkpoint_hash',
  'root_hash',
  'tree_size',
] as const;

/** The two keys written only when they have a value, rather than as an explicit null. */
const omittedWhenAbsent = new Set<string>(['count', 'detail']);

const stringKeys = new Set<string>([
  'agent_id',
  'audience',
  'decision',
  'detail',
  'event',
  'jti',
  'reason',
  'scope',
  'sponsor',
  'task_id',
  'ts',
  'closed_at',
  'kid',
  'prev_checkpoint_hash',
  'root_hash',
]);

/** UTC ISO 8601 with exactly three fractional digits, which is the only form either timestamp takes. */
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const hash = /^[0-9a-f]{64}$/;
const signature = /^[0-9a-f]{128}$/;
/** A high surrogate with no low one after it, or a low surrogate with no high one before it. */
const lonelySurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const encoder = new TextEncoder();

/**
 * The canonical JSON of a record: the bytes its leaf was taken over, and the only thing about a
 * published record that a verifier may not improvise. Keys in lexicographic order, no
 * whitespace, nulls written explicitly, the timestamp exactly as published, and strings escaped
 * the one fixed way section 7 sets out.
 *
 * `count` and `detail` are written only when the record carries them. That is not tidiness: a
 * record that does not carry them has no such key in its pre-image, and writing `"count":null`
 * for it gives a leaf that does not match the sealed one. A `null` arriving
 * where the key should be absent — some pipelines fill absent keys in — is read as absent, which
 * can only ever make a leaf fail to match, never make a wrong one match.
 *
 * A key the published shape does not have is refused rather than ignored, so no record passes
 * verification carrying a field that was never sealed.
 *
 * @throws {AuditShapeError} The record is not the shape section 7 publishes.
 */
export function canonicalRecordJson(record: AuditRecord): Uint8Array {
  return recordBytes(record);
}

/**
 * The bytes a checkpoint's signature was taken over: everything it publishes except the
 * signature, in the same canonical form as a record.
 *
 * @throws {AuditShapeError} The checkpoint is not the shape section 7.0 publishes.
 */
export function checkpointSignedBytes(checkpoint: AuditCheckpoint): Uint8Array {
  return signedBytes(checkpoint);
}

// The two above, typed as backed by an `ArrayBuffer`, which WebCrypto's types require. The public
// signatures say plain `Uint8Array`, so a consumer's TypeScript older than 5.7 can read them.
function recordBytes(record: AuditRecord): Uint8Array<ArrayBuffer> {
  const value = asObject(record, 'malformed_record', 'record');
  for (const key of Object.keys(value)) {
    if (key !== 'seq' && key !== 'checkpoint' && !(recordKeys as readonly string[]).includes(key)) {
      throw new AuditShapeError(
        'malformed_record',
        `The record carries ${key}, which spec section 7 does not publish.`,
      );
    }
  }
  return encoder.encode(canonical(value, recordKeys, 'malformed_record'));
}

function signedBytes(checkpoint: AuditCheckpoint): Uint8Array<ArrayBuffer> {
  const value = asObject(checkpoint, 'malformed_checkpoint', 'checkpoint');
  for (const key of Object.keys(value)) {
    if (key !== 'signature' && !(checkpointKeys as readonly string[]).includes(key)) {
      throw new AuditShapeError(
        'malformed_checkpoint',
        `The checkpoint carries ${key}, which spec section 7.0 does not publish.`,
      );
    }
  }
  return encoder.encode(canonical(value, checkpointKeys, 'malformed_checkpoint'));
}

/**
 * A record's leaf, as lowercase hex: `sha256(0x00 || canonical_json(record))`. The prefix is
 * RFC 6962's, and it is what stops an interior node being presented as a leaf.
 *
 * @throws {AuditShapeError} The record is not the shape section 7 publishes.
 */
export async function leafHash(record: AuditRecord): Promise<string> {
  return sha256(prefixed(0x00, recordBytes(record)));
}

/**
 * Whether `auditPath` folds `leaf` to `rootHash` at `leafIndex` of a tree of `treeSize` leaves:
 * RFC 6962 section 2.1.1, with `sha256(0x01 || left || right)` at every interior node.
 *
 * The tree's size is part of the proof, not decoration — the shape of the fold depends on it,
 * and it is what makes a path checkable rather than merely plausible. It is published on the
 * checkpoint as `tree_size`.
 */
export async function verifyInclusion(
  leaf: string,
  auditPath: readonly string[],
  leafIndex: number,
  treeSize: number,
  rootHash: string,
): Promise<AuditVerification> {
  if (!hash.test(leaf))
    return failed('malformed_proof', 'The leaf is not a SHA-256 hash in lowercase hex.');
  if (!hash.test(rootHash))
    return failed('malformed_checkpoint', 'The root is not a SHA-256 hash in lowercase hex.');
  if (
    !Array.isArray(auditPath) ||
    auditPath.some((step) => typeof step !== 'string' || !hash.test(step))
  ) {
    return failed('malformed_proof', 'An audit path step is not a SHA-256 hash in lowercase hex.');
  }
  if (!Number.isSafeInteger(treeSize) || treeSize <= 0) {
    return failed('malformed_checkpoint', 'The tree size is not a positive integer.');
  }
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
    return failed('malformed_proof', 'The leaf index is not a position in a tree of that size.');
  }

  // RFC 6962 section 2.1.1. `node` is the leaf's index and `last` the tree's, both shifted up a
  // level each step; a path that runs out early, or that has steps left when the tree does not,
  // is not a path for this position and size.
  let node = leafIndex;
  let last = treeSize - 1;
  let folded = leaf;
  for (const sibling of auditPath) {
    if (last === 0)
      return failed('not_included', 'The audit path has more steps than the tree has levels.');
    if (node % 2 === 1 || node === last) {
      folded = await sha256(concat(0x01, sibling, folded));
      while (node !== 0 && node % 2 === 0) {
        node = Math.floor(node / 2);
        last = Math.floor(last / 2);
      }
    } else {
      folded = await sha256(concat(0x01, folded, sibling));
    }
    node = Math.floor(node / 2);
    last = Math.floor(last / 2);
  }
  if (last !== 0)
    return failed('not_included', 'The audit path has fewer steps than the tree has levels.');
  return folded === rootHash
    ? ok
    : failed(
        'not_included',
        'The audit path does not fold the leaf to the root the checkpoint signed.',
      );
}

/**
 * Whether the checkpoint's signature verifies against the key it names, taken over its canonical
 * bytes. A checkpoint naming a key the set does not publish does not verify: the point of the
 * seal is that it was made by a key anyone can fetch, so one nobody can fetch is no better than
 * no signature at all. Retiring a key therefore makes every checkpoint it signed uncheckable,
 * which is why a rotation stops signing with a key but keeps it published.
 *
 * @throws The refusal from `keys` when the key set could not be fetched. A set that could not be
 * reached is not a seal that does not verify, and a caller has to be able to tell them apart.
 */
export async function verifyCheckpoint(
  checkpoint: AuditCheckpoint,
  keys: CheckpointKeySource,
): Promise<AuditVerification> {
  let signed: Uint8Array<ArrayBuffer>;
  try {
    signed = signedBytes(checkpoint);
  } catch (cause) {
    return shapeFault(cause);
  }
  if (!signature.test(checkpoint.signature)) {
    return failed('malformed_checkpoint', 'The signature is not 64 bytes of lowercase hex.');
  }

  const key = await resolveKey(keys, checkpoint.kid);
  if (key === undefined) {
    return failed(
      'unknown_key',
      `Checkpoint ${checkpoint.checkpoint_id} names a key the published set does not hold.`,
    );
  }
  const verified = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    fromHex(checkpoint.signature),
    signed,
  );
  return verified
    ? ok
    : failed(
        'bad_signature',
        `Checkpoint ${checkpoint.checkpoint_id} is not signed by the key it names.`,
      );
}

/**
 * Whether each checkpoint follows on from the one before it: its `prev_checkpoint_hash` is the
 * SHA-256 of that one's signed bytes, and its range begins exactly where that one's ended. A
 * checkpoint removed or replaced breaks the link at the one after it, which is what catches a
 * ledger with a piece taken out of the middle.
 *
 * This checks the run it is given. Whether that run is the whole ledger is what holding a
 * checkpoint somewhere the control plane cannot reach answers — so a run that starts at
 * checkpoint 1 must start with no link, and one that starts later must carry the link to
 * whatever came before, even though this cannot check that link itself.
 *
 * `keys` is required, and `'links-only'` is the way to say you have none. Linkage on its own is
 * self-referential — every value it compares is chosen by whoever served the checkpoints, and
 * `prev_checkpoint_hash` is a plain SHA-256 anyone can recompute, so a chain invented from
 * nothing links to itself perfectly. Without the key set this answers "these checkpoints agree
 * with each other", which is not "these are the control plane's checkpoints". That is a fine
 * question for a holder comparing a run kept off-site against a fresh one, and a useless one
 * for anyone asking whether the ledger was rewritten, so it is asked for by name rather than
 * arrived at by leaving an argument off.
 *
 * @throws The refusal from `keys` when a key set that was asked for could not be fetched.
 */
export async function verifyCheckpointChain(
  checkpoints: readonly AuditCheckpoint[],
  keys: CheckpointKeySource | 'links-only',
): Promise<AuditVerification> {
  if (!Array.isArray(checkpoints) || checkpoints.length === 0) {
    return failed('malformed_checkpoint', 'There are no checkpoints to check.');
  }

  let previous: AuditCheckpoint | undefined;
  // The link is taken over the bytes that were checked on the previous turn of the loop, not
  // over a second rebuild of them.
  let previousSigned: Uint8Array<ArrayBuffer> | undefined;
  for (const checkpoint of checkpoints) {
    let signed: Uint8Array<ArrayBuffer>;
    try {
      signed = signedBytes(checkpoint);
    } catch (cause) {
      return shapeFault(cause);
    }

    if (previous === undefined) {
      const first = checkpoint.checkpoint_id === 1;
      if (first !== (checkpoint.prev_checkpoint_hash === null)) {
        return failed(
          'broken_chain',
          first
            ? 'The first checkpoint of the ledger links to a checkpoint before it.'
            : `Checkpoint ${checkpoint.checkpoint_id} is not the first of the ledger but links to nothing.`,
        );
      }
    } else {
      if (checkpoint.checkpoint_id !== previous.checkpoint_id + 1) {
        return failed(
          'broken_chain',
          `Checkpoint ${previous.checkpoint_id} is followed by ${checkpoint.checkpoint_id}, so one is missing.`,
        );
      }
      if (checkpoint.first_seq !== previous.last_seq + 1) {
        return failed(
          'broken_chain',
          `Checkpoint ${checkpoint.checkpoint_id} does not begin where ${previous.checkpoint_id} ended.`,
        );
      }
      const link = await sha256(previousSigned as Uint8Array<ArrayBuffer>);
      if (checkpoint.prev_checkpoint_hash !== link) {
        return failed(
          'broken_chain',
          `Checkpoint ${checkpoint.checkpoint_id} does not link to checkpoint ${previous.checkpoint_id}.`,
        );
      }
    }

    if (checkpoint.last_seq < checkpoint.first_seq) {
      return failed(
        'malformed_checkpoint',
        `Checkpoint ${checkpoint.checkpoint_id} ends before it begins.`,
      );
    }
    // The signature's shape is checked even when nothing can be checked against the keys: a
    // document with no signature on it at all is not a checkpoint, however well it links.
    if (!signature.test(checkpoint.signature)) {
      return failed(
        'malformed_checkpoint',
        `Checkpoint ${checkpoint.checkpoint_id} carries no signature of 64 bytes of lowercase hex.`,
      );
    }
    if (keys !== 'links-only') {
      const sealed = await verifyCheckpoint(checkpoint, keys);
      if (!sealed.ok) return sealed;
    }
    previous = checkpoint;
    previousSigned = signed;
  }
  return ok;
}

/**
 * The whole check over one record: its leaf, its audit path, the checkpoint that seals it and
 * that checkpoint's signature — using only the four documents and nothing the server says about
 * them.
 *
 * `checkpoint` is passed separately from the one inside `proof` on purpose. A proof that carries
 * its own checkpoint proves nothing on its own: the checkpoint to check against is the one the
 * holder kept, from `GET /audit/checkpoints`, somewhere this database cannot reach. The two must
 * be the same document, and that they are is the first thing checked here.
 *
 * Chaining is a separate question, and {@link verifyCheckpointChain} is where it is asked: this
 * says the record is inside a signed root, not that the ledger around it is whole. A record that
 * proves itself into a root the control plane signed an hour ago proves nothing about a ledger
 * whose earlier checkpoints have since been rewritten, so an auditor asks both.
 *
 * @throws The refusal from `keys` when the key set could not be fetched.
 */
export async function verifyAuditRecord(
  record: AuditRecord,
  proof: AuditProof,
  checkpoint: AuditCheckpoint,
  keys: CheckpointKeySource,
): Promise<AuditVerification> {
  let leaf: string;
  let held: Uint8Array<ArrayBuffer>;
  let offered: Uint8Array<ArrayBuffer>;
  try {
    asObject(proof, 'malformed_proof', 'proof');
    leaf = await leafHash(record);
    held = signedBytes(checkpoint);
    offered = signedBytes(proof.checkpoint);
  } catch (cause) {
    return shapeFault(cause);
  }

  // `seq` and the checkpoint a record names are outside the canonical form, so nothing has
  // checked them yet — and a comparison against a value that is not a number quietly passes.
  if (!Number.isSafeInteger(record.seq)) {
    return failed('malformed_record', 'The record has no sequence number this runtime can carry.');
  }
  if (!Number.isSafeInteger(proof.seq)) {
    return failed('malformed_proof', 'The proof has no sequence number this runtime can carry.');
  }
  if (record.checkpoint !== null && !Number.isSafeInteger(record.checkpoint)) {
    return failed('malformed_record', 'The record names no checkpoint this runtime can carry.');
  }
  if (record.checkpoint === null) {
    return failed(
      'unsealed',
      `Record ${record.seq} is in the ledger but no checkpoint covers it yet.`,
    );
  }
  if (proof.seq !== record.seq) {
    return failed('mismatched', `The proof is for record ${proof.seq}, not record ${record.seq}.`);
  }
  if (record.checkpoint !== checkpoint.checkpoint_id) {
    return failed(
      'mismatched',
      `Record ${record.seq} names checkpoint ${record.checkpoint}, not checkpoint ${checkpoint.checkpoint_id}.`,
    );
  }
  if (!sameBytes(held, offered) || proof.checkpoint.signature !== checkpoint.signature) {
    return failed(
      'mismatched',
      'The checkpoint in the proof is not the checkpoint it is being checked against.',
    );
  }
  if (record.seq < checkpoint.first_seq || record.seq > checkpoint.last_seq) {
    return failed(
      'mismatched',
      `Record ${record.seq} is outside the range checkpoint ${checkpoint.checkpoint_id} covers.`,
    );
  }

  const signed = await verifyCheckpoint(checkpoint, keys);
  if (!signed.ok) return signed;

  return verifyInclusion(
    leaf,
    proof.audit_path,
    proof.leaf_index,
    checkpoint.tree_size,
    checkpoint.root_hash,
  );
}

/**
 * The canonical JSON of `value` over `keys`: no whitespace, the keys in the order given, nulls
 * written explicitly except for the two that are written only when present, and strings escaped
 * the one way a leaf can be rebuilt from.
 */
function canonical(
  value: Record<string, unknown>,
  keys: readonly string[],
  fault: 'malformed_record' | 'malformed_checkpoint',
): string {
  const parts: string[] = [];
  for (const key of keys) {
    const member = value[key];
    // A `null` where the key should simply be absent is read as absent: it is the same record,
    // and reading it the other way would only ever compute a leaf that fails to match.
    if (omittedWhenAbsent.has(key) && (member === undefined || member === null)) continue;
    if (member === undefined) {
      throw new AuditShapeError(
        fault,
        `The document has no ${key}, which its canonical form writes.`,
      );
    }
    if (member === null) {
      parts.push(`${escape(key)}:null`);
      continue;
    }
    if (stringKeys.has(key)) {
      if (typeof member !== 'string') throw new AuditShapeError(fault, `${key} is not a string.`);
      if (lonelySurrogate.test(member)) {
        // The one place this canonical form is knowably not the server's: .NET's encoder writes
        // an unpaired surrogate as U+FFFD, so a leaf can never have been taken over one. The
        // control plane cannot have published this, and saying so is worth more to whoever is
        // holding it than the `not_included` they would otherwise get.
        throw new AuditShapeError(
          fault,
          `${key} holds an unpaired surrogate, which the control plane does not publish.`,
        );
      }
      if ((key === 'ts' || key === 'closed_at') && !timestamp.test(member)) {
        // The one field a publisher can get subtly wrong: a general ISO 8601 writer trims the
        // trailing zero off `.330Z`, and the leaf is then taken over bytes nobody sealed.
        throw new AuditShapeError(
          fault,
          `${key} is not UTC ISO 8601 with exactly three fractional digits, so the sealed bytes cannot be rebuilt.`,
        );
      }
      if ((key === 'root_hash' || key === 'prev_checkpoint_hash') && !hash.test(member)) {
        throw new AuditShapeError(fault, `${key} is not a SHA-256 hash in lowercase hex.`);
      }
      parts.push(`${escape(key)}:${escape(member)}`);
      continue;
    }
    if (typeof member !== 'number' || !Number.isSafeInteger(member)) {
      throw new AuditShapeError(fault, `${key} is not an integer this runtime can carry exactly.`);
    }
    parts.push(`${escape(key)}:${member}`);
  }
  return `{${parts.join(',')}}`;
}

/**
 * A JSON string escaped the one fixed way spec section 7 sets out, which is not the way
 * `JSON.stringify` does it. A leaf is a hash of bytes, so two encoders that agree on a value but
 * not on its escaping compute two different leaves.
 *
 * The output is ASCII: `\` is written `\\`; backspace, tab, line feed, form feed and carriage
 * return take their short escapes; every other control character, everything outside printable
 * ASCII, and each of `"`, `&`, `'`, `+`, `<`, `>` and `` ` `` is written `\uXXXX` in uppercase
 * hex of its UTF-16 code unit, so a character above the basic plane is its surrogate pair. `/`
 * is written as it is.
 */
function escape(text: string): string {
  let out = '"';
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    switch (unit) {
      case 0x5c:
        out += '\\\\';
        continue;
      case 0x08:
        out += '\\b';
        continue;
      case 0x09:
        out += '\\t';
        continue;
      case 0x0a:
        out += '\\n';
        continue;
      case 0x0c:
        out += '\\f';
        continue;
      case 0x0d:
        out += '\\r';
        continue;
      // A quote has to be escaped in any JSON and is written `"` here rather than `\"`;
      // `&`, `'`, `+`, `<`, `>` and a backtick need no escaping at all in JSON and are escaped
      // anyway, so the bytes stay safe to embed in a document. Either way, what matters is that
      // it is the one form the leaf was taken over.
      case 0x22:
      case 0x26:
      case 0x27:
      case 0x2b:
      case 0x3c:
      case 0x3e:
      case 0x60:
        out += unicode(unit);
        continue;
      default:
        // Printable ASCII goes through as itself; a control character and anything above it does
        // not. Everything from U+007F up is a `\uXXXX` per UTF-16 code unit, which is what makes
        // a character above the basic plane two escapes rather than one.
        out += unit < 0x20 || unit > 0x7e ? unicode(unit) : String.fromCharCode(unit);
        continue;
    }
  }
  return `${out}"`;
}

function unicode(unit: number): string {
  return `\\u${unit.toString(16).toUpperCase().padStart(4, '0')}`;
}

async function sha256(input: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', input);
  return toHex(new Uint8Array(digest));
}

function prefixed(prefix: number, content: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const input = new Uint8Array(content.length + 1);
  input[0] = prefix;
  input.set(content, 1);
  return input;
}

/** `prefix || left || right`, with both children given as hex. */
function concat(prefix: number, left: string, right: string): Uint8Array<ArrayBuffer> {
  const input = new Uint8Array(1 + 64);
  input[0] = prefix;
  input.set(fromHex(left), 1);
  input.set(fromHex(right), 33);
  return input;
}

function toHex(bytes: Uint8Array<ArrayBuffer>): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function fromHex(text: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function sameBytes(left: Uint8Array<ArrayBuffer>, right: Uint8Array<ArrayBuffer>): boolean {
  return left.length === right.length && left.every((byte, i) => byte === right[i]);
}

function asObject(
  value: unknown,
  fault: 'malformed_record' | 'malformed_checkpoint' | 'malformed_proof',
  what: string,
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AuditShapeError(fault, `The ${what} is not an object.`);
  }
  return value as Record<string, unknown>;
}

function shapeFault(cause: unknown): AuditVerification {
  if (cause instanceof AuditShapeError) return failed(cause.fault, cause.message);
  throw cause;
}

/**
 * The key for `kid`, from a set that resolves them or from a JWKS document as published, and
 * nothing when the set has no such key.
 *
 * A set that could not be fetched is not a checkpoint that does not verify, so that refusal is
 * left to travel rather than reported as `unknown_key`, and an auditor does not read a network
 * outage as a broken seal.
 */
async function resolveKey(
  source: CheckpointKeySource,
  kid: string,
): Promise<CryptoKey | undefined> {
  if (typeof (source as CheckpointKeys).get === 'function') {
    try {
      return await (source as CheckpointKeys).get(kid);
    } catch (cause) {
      if (cause instanceof SubactIdAuthError && cause.reason === 'unknown_key') return undefined;
      throw cause;
    }
  }
  const keys = (source as { keys?: unknown }).keys;
  for (const jwk of Array.isArray(keys) ? keys : []) {
    const imported = await importP256(jwk);
    if (imported?.kid === kid) return imported.key;
  }
  return undefined;
}
