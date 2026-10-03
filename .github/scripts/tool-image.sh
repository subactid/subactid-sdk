#!/usr/bin/env bash
# Prints the pinned reference of a tool image declared in .github/tools/Dockerfile.
#
#   tool-image.sh trivy   ->   aquasec/trivy:0.74.0@sha256:...
set -euo pipefail

name="${1:?usage: tool-image.sh <stage name>}"
file="$(dirname "$0")/../tools/Dockerfile"

ref=$(awk -v name="$name" 'toupper($1) == "FROM" && toupper($3) == "AS" && $4 == name { print $2 }' "$file")
case "$ref" in
  *@sha256:*) printf '%s\n' "$ref" ;;
  "") echo "no tool image named '$name' in $file" >&2; exit 1 ;;
  *) echo "the tool image '$name' in $file is not pinned by digest" >&2; exit 1 ;;
esac
