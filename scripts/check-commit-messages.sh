#!/usr/bin/env bash
# Rejects AI attribution lines in commit messages. Usage: check-commit-messages.sh <base-ref>
set -euo pipefail
base="${1:-origin/main}"
range="$base..HEAD"
git rev-parse --verify -q "$base" >/dev/null || range="HEAD"
if git log --format=%B "$range" | grep -inE '^(co-authored-by:|claude-session:)|generated with' ; then
  echo "commit message contains an attribution line, remove it" >&2
  exit 1
fi
