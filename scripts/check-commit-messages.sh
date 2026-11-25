#!/usr/bin/env bash
# Rejects AI attribution lines in commit messages.
# Usage: check-commit-messages.sh <base-ref> | --all
# A base ref that does not exist (first push, shallow clone) falls back to the whole history.
set -euo pipefail
base="${1:-origin/main}"
range="$base..HEAD"
if [ "$base" = "--all" ] || ! git rev-parse --verify -q "$base^{commit}" >/dev/null 2>&1; then
  range="HEAD"
fi
if git log --format=%B "$range" | grep -inE '^(co-authored-by:|claude-session:)|generated with' ; then
  echo "commit message contains an attribution line, remove it" >&2
  exit 1
fi
