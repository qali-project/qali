#!/usr/bin/env bash
# Rejects generated Go files outside the known generator outputs (REVIEW-009):
# a stray copy (for example from a mistyped -o path) would never be checked
# for staleness and would confuse maintenance and tooling.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

allowed=(
  internal/platform/httpserver/openapi/openapi.gen.go  # oapi-codegen (api/oapi-codegen.yaml)
  internal/authz/catalog_gen.go                         # tools/permgen
)
# sqlc writes every file of each configured output directory.
while read -r dir; do
  for f in "$dir"/*.go; do allowed+=("$f"); done
done < <(sed -n 's/^[[:space:]]*out:[[:space:]]*//p' sqlc.yaml)

stray=0
while IFS= read -r file; do
  ok=0
  for a in "${allowed[@]}"; do
    if [ "$file" = "$a" ]; then ok=1; break; fi
  done
  if [ $ok = 0 ]; then
    echo "unexpected generated file: $file" >&2
    stray=1
  fi
done < <(grep -rlE --include='*.go' '^// Code generated .*DO NOT EDIT\.$' cmd internal tools | sort)
exit $stray
