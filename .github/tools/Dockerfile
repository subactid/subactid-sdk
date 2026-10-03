# The images CI runs as tools, pinned here and nowhere else, so Dependabot's docker updater keeps
# them current. Nothing builds this file: .github/scripts/tool-image.sh reads the reference for a
# stage name.

# Checks that every file carries licensing information and every licence named has its text
# (REUSE.toml, LICENSES/). Run by the reuse job in ci.yml.
FROM fsfe/reuse:6.2.0@sha256:85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e AS reuse

# Scans the tree and a pull request's commits for secrets. Run by the gitleaks job in ci.yml.
FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
