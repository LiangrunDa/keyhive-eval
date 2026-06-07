#!/usr/bin/env bash
#
# verify_complexity.sh — classify the asymptotic complexity of the series in
# expected/ and check it against the paper's claimed O(1)/O(log N)/O(N)/O(N^2)
# classes. Reads only (no rebuild); run.sh first to confirm your machine reproduces it.
#
# Usage:  ./verify_complexity.sh [DIR] [--all]
#   DIR     series directory (default: expected/). Pass `results` to classify a
#           just-regenerated run (e.g. a custom-EVAL_GROUP_SIZES sweep).
#   --all   also print the non-asserted series.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the complexity analysis." >&2
  exit 2
fi

# An optional leading non-flag argument is the series directory; the rest (--all)
# pass through. Resolve a bare name like `results` relative to the repo root.
DIR="$ROOT/expected"
if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then
  case "$1" in /*) DIR="$1" ;; *) DIR="$ROOT/$1" ;; esac
  shift
fi
exec python3 "$ROOT/analyze_complexity.py" "$DIR" "$@"
