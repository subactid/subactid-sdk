<!-- One issue per pull request. Describe what changes and why; the issue holds the background. -->

Closes #

## What changed

## Checklist

- [ ] The pull request is linked to its issue above, and covers that issue and nothing else.
- [ ] Every commit is signed off (`git commit -s`, DCO) with a one-sentence conventional message.
- [ ] Tests are added or updated for the change, and `pnpm format`, `pnpm build`, `pnpm typecheck`
      and `pnpm test` pass.
- [ ] No new runtime dependency, and no authentication or crypto dependency, without asking first.

## Invariants

The change keeps all four:

- [ ] **Scope only narrows.** The client never asks for, and never keeps, a wider scope than the
      task holds. A refresh is for the same scope or a subset.
- [ ] **No secret is ever logged, returned in an error, or committed.** Tokens, task grants,
      subject tokens and private keys included.
- [ ] **A token handed to a caller has life left in it.** Refresh proactively; never hand out a
      token that is about to expire.
- [ ] **The agent is the actor, never the subject.** Nothing puts an agent in `sub`.
