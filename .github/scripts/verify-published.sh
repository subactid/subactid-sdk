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
# installs the three at <version> into an empty directory, as a user would, and has npm verify the
# registry signature and the attestations of everything installed, the MCP peer dependency and its
# tree included. Last, for each of the three, it fetches the provenance attestation from the
# registry and verifies it with gh attestation verify against the identity the release run for
# this version had: release.yml in this repository, on the tag v<version>. An attestation from any
# other repository, workflow or tag does not count, and neither does a tarball with none.
#
# Needs npm 10 or later, which verifies attestations, curl, and gh with GH_TOKEN set. Works in a
# directory of its own under RUNNER_TEMP, or under the temp directory when run by hand.
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
npm init -y > /dev/null
specs=()
for name in "${packages[@]}"; do specs+=("${name}@${version}"); done
# npm installs the peer dependency of @subactid/mcp, the MCP SDK, along with it. Nothing here is
# built or run, so no install script runs either.
npm install --ignore-scripts --no-audit --no-fund "${specs[@]}"
# Every package installed has a registry signature, and every attestation it carries verifies
# against the tarball that was installed. This says nothing about who signed: that is next.
npm audit signatures

failed=0
for name in "${packages[@]}"; do
  npm pack "${name}@${version}" --json > pack.json
  file=$(json pack.json '[0].filename')

  # The attestations npm shows beside the version, from the registry's own endpoint. A version
  # published without provenance has none.
  url="https://registry.npmjs.org/-/npm/v1/attestations/${name/\//%2F}@${version}"
  if ! curl -fsS "$url" -o attestations.json; then
    echo "::error title=No attestation::npm holds no attestation for ${name}@${version}, so it was not published with provenance."
    failed=1
    continue
  fi
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
done
if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "latest on ${packages[*]} is ${version}, and each is what the release signed"
