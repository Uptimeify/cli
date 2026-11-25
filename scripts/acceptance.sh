#!/usr/bin/env bash
# End-to-end check against a NON-production instance.
# Needs: UPTIMEIFY_API_URL, UPTIMEIFY_TOKEN (and UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1 for http://127.0.0.1).
# Creates, reads, renames and deletes one tag. Refuses any host except 127.0.0.1 and localhost,
# unless UPTIMEIFY_ACCEPTANCE_ALLOW_HOST equals the URL's host exactly.
set -euo pipefail
: "${UPTIMEIFY_API_URL:?set UPTIMEIFY_API_URL}"
: "${UPTIMEIFY_TOKEN:?set UPTIMEIFY_TOKEN}"

# host of the URL: drop scheme, path/query/fragment, then port. Userinfo is refused.
rest="${UPTIMEIFY_API_URL#*://}"
rest="${rest%%[/?#]*}"
case "$rest" in *@*) echo "refusing: URL contains userinfo" >&2; exit 1;; esac
host="${rest%%:*}"
if [ "$host" != "127.0.0.1" ] && [ "$host" != "localhost" ] \
  && { [ -z "${UPTIMEIFY_ACCEPTANCE_ALLOW_HOST:-}" ] || [ "$host" != "$UPTIMEIFY_ACCEPTANCE_ALLOW_HOST" ]; }; then
  echo "refusing to run against host '$host' (only 127.0.0.1, localhost, or UPTIMEIFY_ACCEPTANCE_ALLOW_HOST)" >&2
  exit 1
fi

bin="${UPTIMEIFY_BIN:-./bin/uptimeify}"
export bin
pass=0; fail=0
check() { if "$@" >/dev/null; then pass=$((pass+1)); echo "  ok   ${desc}"; else fail=$((fail+1)); echo "  FAIL ${desc}"; fi; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

desc="doctor reaches the API"; check "$bin" doctor
desc="auth status hides the token"; check bash -c '! "$bin" auth status 2>&1 | grep -qF "$UPTIMEIFY_TOKEN"'

name="cli-acceptance-$$"
export name
id="$("$bin" tags create --field "name=$name" --json | json 'd.get("id") or d["tag"]["id"]' 2>/dev/null)" || id=""
export id
desc="tags create returns an id"; check test -n "$id"
desc="tags list shows the new tag"; check bash -c '"$bin" tags list --json | grep -q "$name"'
desc="tags update renames it"; check "$bin" tags update "$id" --field "name=$name-renamed" --json
desc="tags delete refuses without --yes when not interactive"; check bash -c '! "$bin" tags delete "$id" </dev/null >/dev/null 2>&1'
desc="tags delete with --yes works"; check "$bin" tags delete "$id" --yes
desc="deleted tag is gone from the list"; check bash -c '! "$bin" tags list --json | grep -q "$name"'

set +e
"$bin" websites get 999999999 >/dev/null 2>&1; code=$?
UPTIMEIFY_TOKEN=wrong "$bin" tags list >/dev/null 2>&1; authcode=$?
"$bin" no-such-command >/dev/null 2>&1; unkcode=$?
"$bin" tags delete .. --yes >/dev/null 2>&1; dotcode=$?
set -e
desc="unknown id exits with 4 (got $code)"; check test "$code" -eq 4
desc="wrong token exits with 3 (got $authcode)"; check test "$authcode" -eq 3
desc="unknown command exits with 2 (got $unkcode)"; check test "$unkcode" -eq 2
desc="path argument '..' exits with 2 (got $dotcode)"; check test "$dotcode" -eq 2

echo "passed: $pass, failed: $fail"
test "$fail" -eq 0
