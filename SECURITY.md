# Security policy

The Subact ID SDKs are the client side of security infrastructure: they mint the assertions that
authenticate an agent, hold task grants, verify task tokens and decide what a caller may do.
We take reports seriously and respond quickly.

## Reporting a vulnerability

Do not open a public issue or pull request for a security problem.

- **Preferred:** report it privately through GitHub's private vulnerability reporting, at
  <https://github.com/subactid/subactid-sdk/security/advisories/new>. The report, the discussion and
  the fix stay private until the advisory is published.
- **Otherwise:** email support@subactid.com.

Please include: the package (`@subactid/client`, `@subactid/server` or `@subactid/mcp`) and its version or
commit, a description of the issue, and reproduction steps if you have them.

## What to expect

- Acknowledgement within 3 working days
- An assessment and planned fix timeline within 10 working days
- Coordinated disclosure: we ask for 90 days before public disclosure, and usually publish
  sooner, once a fix is released

## Scope

In scope: assertion signing and key handling, token exchange and refresh, grant storage, token
verification, scope and delegation-depth enforcement, introspection, and anything a log line or
an error message carries.

Out of scope: the control plane itself, which has its own policy in the
[`subactid`](https://github.com/subactid/subactid) repository; the examples, which are not production
hardened; and findings that require an already-compromised host or the agent's private key.

## Supported versions

During 0.x, only the latest release receives security fixes.
