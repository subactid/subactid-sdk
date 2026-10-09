#!/usr/bin/env bash
# Checks that what npm serves for a stable release is what the release workflow published and
# signed.
#
#   verify-published.sh <version>   checks the three packages at MAJOR.MINOR.PATCH
#
# The release publishes @subactid/client, @subactid/server and @subactid/mcp at one version, each
# with a provenance attestation signed by the release run, and npm points `latest` at it. A
# dist-tag can be moved, and a version can be published by anyone npm lets publish, so this reads
# `latest` on each package again and fails if any is not <version>, naming the package. It then
# downloads each tarball and the provenance attestation the registry holds for it, and verifies
# the two together with gh attestation verify against the identity the release run for this
# version had: release.yml in this repository, on the tag v<version>. An attestation from any
# other repository, workflow or tag does not count, and neither does a tarball with none. Last,
# it installs the three into an empty directory with npm ci, pinned to the hashes of the tarballs
# that verified, and has npm check the registry signature and the attestations of each. Nothing
# is installed before it has verified, and nothing installed runs.
#
# Needs npm 10 or later, which verifies attestations, tar, curl, and gh with GH_TOKEN set. Works
# in a directory of its own under RUNNER_TEMP, or under the temp directory when run by hand.
set -euo pipefail

version="${1:?usage: verify-published.sh <version>}"
if ! printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "::error title=Not a stable version::'$version' is not MAJOR.MINOR.PATCH. Only a stable release moves latest."
  exit 1
fi

repository=subactid/subactid-sdk
packages=(@subactid/client @subactid/server @subactid/mcp)
# The release run for this version, exactly: the workflow on its tag.
workflow="${repository}/.github/workflows/release.yml"
ref="refs/tags/v${version}"

# Prints one value out of a JSON file: json <file> <path>, as in json pack.json '[0].filename'.
json() {
  node -p "JSON.parse(require('node:fs').readFileSync(process.argv[1], 'utf8'))$2" "$1"
}

moved=0
for name in "${packages[@]}"; do
  latest=$(npm view "$name" dist-tags.latest)
  if [ "$latest" = "$version" ]; then
    echo "${name}: latest is ${latest}"
  else
    echo "::error title=Dist-tag moved::${name}: latest on npm is ${latest}, the latest release is ${version}."
    moved=1
  fi
done
if [ "$moved" -ne 0 ]; then
  exit 1
fi

dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/package-check.XXXXXX")
cd "$dir"

failed=0
for name in "${packages[@]}"; do
  # What the registry holds for the version: the tarball, and the attestations npm shows beside
  # it. A version published without provenance has none.
  npm view "${name}@${version}" dist --json > dist.json
  npm pack "${name}@${version}" --json > pack.json
  file=$(json pack.json '[0].filename')
  url=$(json dist.json '.attestations?.url ?? ""')
  if [ -z "$url" ]; then
    echo "::error title=No attestation::npm holds no attestation for ${name}@${version}, so it was not published with provenance."
    failed=1
    continue
  fi
  curl -fsS "$url" -o attestations.json
  node -e '
    const fs = require("node:fs");
    const { attestations } = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const provenance = attestations.find((a) => a.predicateType === "https://slsa.dev/provenance/v1");
    fs.writeFileSync(process.argv[2], provenance ? JSON.stringify(provenance.bundle) : "");
  ' attestations.json bundle.json
  if [ ! -s bundle.json ]; then
    echo "::error title=No provenance::npm holds attestations for ${name}@${version}, but none of them is build provenance."
    failed=1
    continue
  fi

  if ! gh attestation verify "$file" --bundle bundle.json --repo "$repository" \
    --signer-workflow "$workflow" --source-ref "$ref" --digest-alg sha512; then
    echo "::error title=The provenance does not verify::${name}@${version} carries no provenance attestation from ${workflow} on ${ref}, so it is not what the release published."
    failed=1
    continue
  fi
  echo "${name}@${version} is attested to ${workflow} on ${ref}"

  # One lockfile entry, pinned to the hash of the tarball that just verified, with the
  # dependencies its own manifest declares.
  tar -xOf "$file" package/package.json > manifest.json
  node -e '
    const fs = require("node:fs");
    const [name, version, file, resolved] = process.argv.slice(1);
    const manifest = JSON.parse(fs.readFileSync("manifest.json", "utf8"));
    const crypto = require("node:crypto");
    const hash = crypto.createHash("sha512").update(fs.readFileSync(file)).digest("base64");
    const entry = { name, version, resolved, integrity: `sha512-${hash}` };
    for (const key of ["dependencies", "peerDependencies"]) {
      if (manifest[key]) entry[key] = manifest[key];
    }
    fs.appendFileSync("verified.jsonl", JSON.stringify(entry) + "\n");
  ' "$name" "$version" "$file" "$(json dist.json '.tarball')"
done
if [ "$failed" -ne 0 ]; then
  exit 1
fi

# Installed only now, and only by hash: the lockfile pins each package to the tarball that
# verified, so npm ci installs that tarball or fails. The peer dependency of @subactid/mcp, the
# MCP SDK, is not under check and its tree cannot be pinned here, so npm is told to leave peers
# alone as npm 6 did. Nothing is built or run, so no install script runs either.
node -e '
  const fs = require("node:fs");
  const lines = fs.readFileSync("verified.jsonl", "utf8").trim().split("\n");
  const entries = lines.map((line) => JSON.parse(line));
  const dependencies = Object.fromEntries(entries.map((e) => [e.name, e.version]));
  const packages = { "": { name: "package-check", dependencies } };
  for (const { name, ...entry } of entries) packages[`node_modules/${name}`] = entry;
  const manifest = { name: "package-check", private: true, dependencies };
  const lockfile = { name: "package-check", lockfileVersion: 3, requires: true, packages };
  fs.writeFileSync("package.json", JSON.stringify(manifest, null, 2));
  fs.writeFileSync("package-lock.json", JSON.stringify(lockfile, null, 2));
'
npm ci --ignore-scripts --no-audit --no-fund --legacy-peer-deps
# Every package installed has a registry signature, and every attestation it carries verifies.
npm audit signatures
echo "latest on ${packages[*]} is ${version}, and each is what the release signed"
