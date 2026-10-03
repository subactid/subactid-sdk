/**
 * An auditor's check, run away from the control plane: does this ledger record belong to a
 * checkpoint the control plane signed, and do the checkpoints still form one unbroken chain?
 *
 * It reads the documents the control plane publishes, saved as files in one directory:
 *   record.json       one record from GET /audit
 *   proof.json        GET /audit/records/{seq}/proof for that record
 *   checkpoint.json   the checkpoint that covers it, kept where the control plane cannot change it
 *   checkpoints.json  the checkpoints, from the first on: what GET /audit/checkpoints answers
 *   jwks.json         the control plane's key set, from /.well-known/jwks.json
 *
 *   AUDIT_DIR  the directory; the current one by default
 *
 * GET /audit/checkpoints answers one page, `{ "checkpoints": [...], "next_after": 271 }`, of at
 * most `limit` (1000 at most) checkpoints, oldest first. `next_after` is `null` on the last page;
 * otherwise ask again with `?after=<next_after>`. checkpoints.json may be that one page, the
 * pages saved in order and joined into one array, or a plain array of checkpoints. Name the pages
 * so they sort in the order they were fetched — zero-padded, page-001.json, page-002.json — or a
 * shell glob puts page-10.json before page-2.json; then `jq -s . page-*.json` joins them. The
 * chain is checked from the first checkpoint given, so save every page.
 *
 * Exit codes: 0 both checks pass; 1 a check failed.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  type AuditCheckpoint,
  type AuditProof,
  type AuditRecord,
  verifyAuditRecord,
  verifyCheckpointChain,
} from '@subactid/server/audit';

const dir = process.env['AUDIT_DIR'] ?? '.';
const read = async <T>(name: string): Promise<T> =>
  JSON.parse(await readFile(join(dir, name), 'utf8')) as T;

const record = await read<AuditRecord>('record.json');
const proof = await read<AuditProof>('proof.json');
const checkpoint = await read<AuditCheckpoint>('checkpoint.json');
const checkpoints = flatten(await read<unknown>('checkpoints.json'));
const jwks = await read<{ keys?: unknown }>('jwks.json');

const result = await verifyAuditRecord(record, proof, checkpoint, jwks);
if (!result.ok) throw new Error(`Record ${record.seq} does not verify: ${result.detail}`);

const chain = await verifyCheckpointChain(checkpoints, jwks);
if (!chain.ok) throw new Error(`The checkpoints do not form a chain: ${chain.detail}`);

console.log(`Record ${record.seq} is in a signed checkpoint, and the checkpoints form one chain.`);

/**
 * The checkpoints in a saved file: one page as the endpoint answers it, an array of such pages
 * in order, or a plain array of checkpoints.
 */
function flatten(saved: unknown): AuditCheckpoint[] {
  const pageOf = (value: unknown): AuditCheckpoint[] | undefined => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
    const page = (value as { checkpoints?: unknown }).checkpoints;
    return Array.isArray(page) ? (page as AuditCheckpoint[]) : undefined;
  };
  const page = pageOf(saved);
  if (page !== undefined) return page;
  if (!Array.isArray(saved)) {
    throw new Error('checkpoints.json is neither a page of GET /audit/checkpoints nor an array.');
  }
  const pages = saved.map(pageOf);
  if (saved.length > 0 && pages.every((p) => p !== undefined)) {
    return pages.flat() as AuditCheckpoint[];
  }
  return saved as AuditCheckpoint[];
}
