#!/usr/bin/env bash
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Run Renovate against this checkout without touching GitHub.
#
#   .github/scripts/renovate-local.sh validate            # schema + migration check of renovate.json5
#   .github/scripts/renovate-local.sh extract [paths…]    # which files/deps each manager detects (offline)
#   .github/scripts/renovate-local.sh lookup  [paths…]    # + version/digest lookups (network, read-only)
#   .github/scripts/renovate-local.sh full    [paths…]    # + compute file changes in memory (nothing written)
#
# Output: .renovate-local/<mode>.jsonl (JSON log lines) and a per-manager summary on stdout.
# Query examples:
#   jq -r 'select(.msg=="Extracted dependencies") | .packageFiles | keys[]' .renovate-local/extract.jsonl
#   jq -r 'select(.msg=="packageFiles with updates") | .. | .branchName? // empty' .renovate-local/lookup.jsonl | sort -u
#
# Needs the Renovate CLI: `npm install -g renovate@44.133.0`, or set RENOVATE_BIN to its path.
# lookup/full need GITHUB_COM_TOKEN (e.g. `export GITHUB_COM_TOKEN=$(gh auth token)`) for GitHub lookups.
set -euo pipefail

mode=${1:-}
case "$mode" in
  validate|extract|lookup|full) ;;
  *) echo "usage: $0 validate|extract|lookup|full [includePath…]" >&2; exit 2 ;;
esac
shift

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
bin=${RENOVATE_BIN:-renovate}
cd "$repo"

if [[ "$mode" == validate ]]; then
  exec "${bin}-config-validator" --strict renovate.json5
fi

out="$repo/.renovate-local"
mkdir -p "$out"
log="$out/$mode.jsonl"

if [[ $# -gt 0 ]]; then
  export RENOVATE_INCLUDE_PATHS
  RENOVATE_INCLUDE_PATHS=$(IFS=,; echo "$*")
fi

set +e
LOG_LEVEL=${LOG_LEVEL:-debug} LOG_FORMAT=json \
  RENOVATE_PLATFORM=local RENOVATE_DRY_RUN="$mode" \
  "$bin" >"$log.raw" 2>&1
status=$?
set -e

# Drop non-JSON noise (node warnings) so jq can read the file.
grep '^{' "$log.raw" >"$log" || true
rm -f "$log.raw"

echo "renovate exit code: $status  log: $log"
echo "errors/warnings:"
jq -r 'select(.level >= 40) | "  [\(.level)] \(.msg)\(if .err then " | " + (.err.message // "") else "" end)"' "$log" | sort | uniq -c | sort -rn | head -20
echo
printf 'manager\tfiles\tdeps\n'
jq -r 'select(.msg=="Dependency extraction complete") | .stats.managers | to_entries[] | "\(.key)\t\(.value.fileCount)\t\(.value.depCount)"' "$log"
exit "$status"
