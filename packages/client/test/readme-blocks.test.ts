import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * A block in this package's README that names an example as its first line is that example, line
 * for line, indentation aside: a paraphrase drifts, and a reader copying it gets code that does
 * not run.
 */
describe('README blocks taken from the examples', () => {
  const root = new URL('../../../', import.meta.url);
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const blocks = [...readme.matchAll(/```ts\n\/\/ (examples\/[^\n]+)\n([\s\S]*?)```/g)].map(
    (m) => ({ path: m[1] as string, body: (m[2] as string).trimEnd() }),
  );

  it('has at least one', () => {
    expect(blocks.length).toBeGreaterThan(0);
  });

  it.each(blocks.map((b) => [b.path, b] as const))('quotes %s as it is', (_, block) => {
    const example = readFileSync(new URL(block.path, root), 'utf8')
      .split('\n')
      .map((line) => line.trim());
    const lines = block.body.split('\n').map((line) => line.trim());
    const found = example.some((_, i) => lines.every((line, k) => example[i + k] === line));
    expect(found, `not in ${block.path}:\n${block.body}`).toBe(true);
  });
});
