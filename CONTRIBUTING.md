# Contributing

## Who contributes

Changes come from members of the subactid GitHub organization, on branches of this repository.
A pull request from outside the organization is closed by a workflow without review, and issues
and comments are limited to collaborators. These libraries sign the assertions that authenticate
an agent and verify the tokens that let it act, and the people who change them are known to the
maintainers.

From outside the organization:

- To report a bug, email support@subactid.com with the package and its version, what you did and
  what happened instead.
- To report a vulnerability, follow [`SECURITY.md`](SECURITY.md). Never open an issue for one.
- To ask about joining, email the same address and say what you would like to work on.

## Before you start

Open an issue before writing code for anything non-trivial. These packages sit on the security
boundary of an agent, and agreeing on the design first saves a rejected pull request.

## Sign-off and licensing

Sign off every commit (DCO). The `dco` workflow checks every commit in a pull request:

    git commit -s -m "fix: refresh before the token runs out"

There is no contributor licence agreement. Your sign-off certifies, under the
[Developer Certificate of Origin](https://developercertificate.org), that you may contribute the
change under the licence that covers the files it touches: Apache-2.0 for the SDKs, as
`REUSE.toml` records. Contributions stay under that licence and are not relicensed.

## Ground rules

- One issue per branch, one branch per pull request, one pull request per issue.
- Conventional commit messages, one short sentence, no body, no trailers but the sign-off. The
  types are `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:` and `chore:`, with an optional
  scope, as Dependabot's `chore(deps):` has. A `!` before the colon marks a breaking change. The
  release notes list `feat` under Added, `fix` under Fixed, `docs` under Documentation, a `!`
  under Breaking, and the rest together.
- Every change goes through a pull request; nothing is committed to `main` directly.
- CI runs `pnpm format`, `pnpm build`, `pnpm typecheck` and `pnpm test` on Node 22 and 24, and
  checks the tree for secrets (gitleaks) and for licensing information on every file (REUSE);
  all must pass.
- There is no linter, on purpose for now. The one worth having is typescript-eslint with its
  type-checked rules (`no-floating-promises`, `no-misused-promises`), and it does not support the
  TypeScript 7 this repository builds with. Until it does, a promise left unawaited in the token
  code is caught in review and by the tests, not by a tool.
- The client depends on nothing outside the platform: WebCrypto and `fetch`. Do not add a runtime
  dependency, and do not add a crypto dependency at all, without asking first. Ask by opening an
  issue that describes the dependency and why the platform is not enough, before the pull request.
- No token, grant, key or subject token is ever logged, put in an error message, or committed.
- Scope only narrows: the client never asks the control plane for more than a task holds.

## Trying a build of main

The packages on npm are the latest release. To try a change merged to `main` since, use the
build CI packs: every merge leaves the three packages packed on its CI run, under Artifacts, as
`sdk-<version>`. They are kept for thirty days and go nowhere near a registry. Any signed-in
GitHub user can download them from the run's page.

A dev build is versioned `<released>-dev.<run>.g<sha>`, a prerelease version that no release
carries, so it can neither be mistaken for a release nor satisfy a dependency on one.

Install all three together, even if you only want one:

    npm install ./subactid-client-0.1.0-dev.42.gab12cd3.tgz \
                ./subactid-server-0.1.0-dev.42.gab12cd3.tgz \
                ./subactid-mcp-0.1.0-dev.42.gab12cd3.tgz

`@subactid/mcp` depends on the `@subactid/server` packed beside it, at a version no registry has, so
installing it alone fails on a 404 for that version. Installed together, the sibling tarball
satisfies it.

## Cutting a release

The three packages carry one version between them. Bump all three in a pull request, land it,
then tag:

    git tag -s v0.1.1 -m "v0.1.1" && git push origin v0.1.1

`.github/workflows/release.yml` runs four jobs, each holding only what it needs:

- `ci` runs the whole `ci` workflow on the tagged commit, with a read-only token.
- `build` refuses a tag whose commit is not on `main`, refuses a version that any package does not
  carry or that npm already has, builds, and packs each package with `LICENSE` and `NOTICE`
  beside it. pnpm writes the version going out in place of each `workspace:*` dependency, so
  `@subactid/mcp` depends on the `@subactid/server` published beside it. The tarballs leave the
  job as an artifact of the run.
- `publish` has no checkout and installs nothing. It checks each tarball's name, version and
  sibling dependencies against the tag, then publishes them in dependency order with npm. It is
  the only job with an identity npm accepts, so no dependency ever runs where a publish
  credential can be minted. It waits in the `npm-release` environment for a required reviewer.
- `release` writes the notes from the commits since the previous tag and creates the GitHub
  release.

There is no npm token. npm accepts the publish job's short-lived OIDC identity only because each
`@subactid/*` package names this repository, `release.yml` and the `npm-release` environment as
its trusted publisher. The same identity signs the provenance attestation that npm shows beside
each version.

A prerelease tag such as `v0.2.0-rc.1` is published under the `next` dist-tag and never moves
`latest`.

The `package-check` workflow checks the latest stable release on npm every week. `latest` on each
of the three packages must be that release's version, the three installed together must pass
`npm audit signatures`, and each tarball's provenance attestation must verify with
`gh attestation verify` as signed by the release run for that tag. A failure means npm does not
serve what the release signed, and the log names which package: a dist-tag has been moved, or a
version has gone out that no release here signed. That is a security incident, not a flake:
nothing in this repository touches a version after its release, so find what did before anything
else is published. The same run scans `pnpm-lock.yaml`, the development dependencies that build
the release, with OSV-Scanner and reports the findings to code scanning without failing anything.
A finding there is a bump, which is Dependabot's pull request to make.

An npm version cannot be taken back and cannot be replaced, which is why the run checks before it
builds and builds before it publishes. A run that failed part way through can be run again: the
packages already on npm are left alone and the rest go out.
