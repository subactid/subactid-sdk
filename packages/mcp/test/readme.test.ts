import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/** The README's integration is not a paraphrase of the example: it is the example, line for line. */
describe('README', () => {
  const readme = readFileSync(new URL('../../../README.md', import.meta.url), 'utf8');
  const example = readFileSync(
    new URL('../../../examples/mcp-jira/index.ts', import.meta.url),
    'utf8',
  );
  const blocks = [
    ...readme.matchAll(/```ts\n\/\/ examples\/mcp-jira\/index\.ts\n([\s\S]*?)```/g),
  ].map((m) => (m[1] as string).trimEnd());

  it('shows the short integration exactly as the example has it', () => {
    expect(blocks.length).toBeGreaterThanOrEqual(1);
    const integration = blocks[0] as string;
    // Ten lines of guard and server, plus the one that lets the quickstart's plain-http issuer in.
    expect(integration.split('\n').length).toBeLessThanOrEqual(11);
    expect(example).toContain(integration);
  });

  it('shows every other example block exactly as the example has it, indentation aside', () => {
    const exampleLines = example.split('\n').map((l) => l.trim());
    for (const block of blocks.slice(1)) {
      const lines = block.split('\n').map((l) => l.trim());
      const found = exampleLines.some((_, i) =>
        lines.every((line, k) => exampleLines[i + k] === line),
      );
      expect(found, `not in the example:\n${block}`).toBe(true);
    }
  });
});
