#!/usr/bin/env bash
# End-to-end check of the browser sign-in of the BUILT binary against a NON-production instance,
# without a browser and without a test switch in the binary.
# Needs: UPTIMEIFY_API_URL=http://127.0.0.1:<port>, UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1,
# UPTIMEIFY_ACCEPTANCE_EMAIL and UPTIMEIFY_ACCEPTANCE_PASSWORD (an organization admin who signs in
# without a second factor) and a server with browser sign-in switched on.
# The CLI runs `auth login --no-browser`. This script plays the browser over HTTP: it signs in with
# the account, confirms the password, grants consent (only the api: scopes, never offline_access)
# and calls the CLI's loopback receiver with the redirect. It registers two devices (the server
# allows 5 registrations per hour per IP) and creates and deletes one tag.
# KEYCHAIN: the CLI keeps its sign-in in the system keyring, so this script WRITES TO YOUR REAL
# KEYCHAIN (macOS login keychain, service uptimeify-cli). It only ever uses the entries named
# `http://127.0.0.1:<port>` and `http://127.0.0.1:<port> access` (the origin of the instance under
# test, which never matches the entries of https://uptimeify.io), and removes them at the end in
# every case (auth logout, then a check that nothing is left, also on Ctrl-C). Every CLI call has a
# time limit, so a keychain dialog or a hang ends the run with a message instead of waiting.
# It never prints a token, an authorization code or the authorize address, and it never passes one
# of them, the e-mail or the password as an argument to another process.
# Refuses every URL except http://127.0.0.1:<port>.
set -euo pipefail
: "${UPTIMEIFY_API_URL:?set UPTIMEIFY_API_URL}"
: "${UPTIMEIFY_ACCEPTANCE_EMAIL:?set UPTIMEIFY_ACCEPTANCE_EMAIL}"
: "${UPTIMEIFY_ACCEPTANCE_PASSWORD:?set UPTIMEIFY_ACCEPTANCE_PASSWORD}"
export UPTIMEIFY_ACCEPTANCE_EMAIL UPTIMEIFY_ACCEPTANCE_PASSWORD
unset UPTIMEIFY_TOKEN

# Only http://127.0.0.1:<port>: the keyring entries are named by this origin, so a port of its own
# keeps this run away from every entry a person uses (https://uptimeify.io and others).
case "$UPTIMEIFY_API_URL" in
  http://127.0.0.1:[0-9]*) ;;
  *) echo "refusing: UPTIMEIFY_API_URL must be http://127.0.0.1:<port> (got a different host or no port)" >&2; exit 1 ;;
esac
rest="${UPTIMEIFY_API_URL#*://}"
case "${rest#127.0.0.1:}" in
  *[!0-9]*) echo "refusing: UPTIMEIFY_API_URL must be exactly http://127.0.0.1:<port>, nothing after the port" >&2; exit 1 ;;
esac
[ "${UPTIMEIFY_ALLOW_INSECURE_LOOPBACK:-}" = 1 ] || { echo "set UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1 for http://127.0.0.1" >&2; exit 1; }
export UPTIMEIFY_ALLOW_INSECURE_LOOPBACK

bin="${UPTIMEIFY_BIN:-./bin/uptimeify}"
export bin
[ -x "$bin" ] || { echo "no executable CLI at $bin: run make build or set UPTIMEIFY_BIN" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

# run_t SECONDS COMMAND...: runs the command and ends it after SECONDS (macOS has no timeout(1)).
# Returns 124 when it had to end it.
run_t() {
  local secs="$1" pid dog rc=0
  shift
  "$@" &
  pid=$!
  ( sleep "$secs"; kill "$pid" 2>/dev/null ) &
  dog=$!
  wait "$pid" || rc=$?
  kill "$dog" 2>/dev/null || true
  wait "$dog" 2>/dev/null || true
  # Ended by the time limit (SIGTERM). The CLI itself only exits with 0 to 3.
  case "$rc" in 143 | 137) rc=124 ;; esac
  return "$rc"
}

# cli ARGS...: the built binary with a limit of 60 seconds. A hang is almost always a keychain
# dialog that waits for a click, so the run stops with that hint.
cli() {
  local rc=0
  run_t 60 "$bin" "$@" || rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "ABORT: '$bin $*' did not finish within 60 s. A keychain dialog may be waiting; answer it or run again." >&2
    exit 1
  fi
  return "$rc"
}
export -f run_t cli

# The CLI keys its keyring entries by the origin: here always http://127.0.0.1:<port>.
origin="http://$rest"

cat >&2 <<EOF_BANNER
NOTE: this run signs in with the built CLI and WRITES TO YOUR REAL SYSTEM KEYCHAIN
      (service uptimeify-cli, entries for $origin only). It removes them at the end.
      If a keychain dialog appears, the run stops after 60 s.
EOF_BANNER

tmp="$(mktemp -d)"
chmod 700 "$tmp"
jar="$tmp/cookies"
login_pid=""
login_dog=""
kt=""
login_rc=0
authorize_url=""
redirect=""

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "$login_dog" ]; then kill "$login_dog" 2>/dev/null || true; fi
  if [ -n "$login_pid" ] && kill -0 "$login_pid" 2>/dev/null; then kill "$login_pid" 2>/dev/null || true; fi
  # Sign out (revokes on the server, removes both keyring entries), then prove nothing is left.
  run_t 60 "$bin" auth logout >/dev/null 2>&1 || true
  if [ -n "$kt" ] && ! no_keyring_entries; then
    keyring_entry delete "$origin" || true
    keyring_entry delete "$origin access" || true
    echo "WARNING: keychain entries for $origin were left behind and have been removed" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  rm -rf "$tmp"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass=0; fail=0; skipped=0
check() { if "$@" >/dev/null; then pass=$((pass+1)); echo "  ok   ${desc}"; else fail=$((fail+1)); echo "  FAIL ${desc}"; fi; }
skip() { skipped=$((skipped+1)); echo "  skip ${desc}"; }

# json EXPR: evaluates EXPR over the JSON document d read from stdin; prints '' on any error.
json() { python3 -c "import json,sys
try:
    d = json.load(sys.stdin)
    v = $1
except Exception:
    v = ''
print('' if v is None else v)"; }

# curl_url URL [curl args...]: the URL goes to curl through a config on a file descriptor, so a
# code or an authorize address never shows up in the process list.
curl_url() { local url="$1"; shift; curl -sS --max-time 30 -K <(printf 'url = "%s"\n' "$url") "$@"; }

# query_param NAME URL: prints parameter NAME of URL (URL reaches python through the environment).
query_param() { URL="$2" python3 -c 'import os,sys,urllib.parse as u; print(u.parse_qs(u.urlsplit(os.environ["URL"]).query).get(sys.argv[1], [""])[0])' "$1"; }

# file_lacks SECRET FILE: true when FILE exists and does not contain the non-empty SECRET.
file_lacks() { SECRET="$1" python3 -c 'import os,sys; s=os.environ["SECRET"]; d=open(sys.argv[1], encoding="utf-8", errors="replace").read(); sys.exit(0 if s and s not in d else 1)' "$2"; }

# show_login_err: the CLI's stderr for a failed login, without the line that carries the address.
show_login_err() { grep -v 'oauth2/authorize' "$tmp/login.err" 2>/dev/null | sed 's/^/    | /' || true; }

# post_json PATH: POSTs the JSON on stdin like the browser (session cookie, Origin), prints the status.
post_json() {
  curl -sS --max-time 30 -o "$tmp/post.body" -w '%{http_code}' -b "$jar" -c "$jar" \
    -H "Origin: $origin" -H 'Content-Type: application/json' --data-binary @- "$origin$1"
}

sign_in() {
  local status
  status="$(python3 -c 'import json,os; print(json.dumps({"email": os.environ["UPTIMEIFY_ACCEPTANCE_EMAIL"], "password": os.environ["UPTIMEIFY_ACCEPTANCE_PASSWORD"]}))' \
    | post_json /api/auth/sign-in/email)" || return 1
  [ "$status" = 200 ]
}

# step_up: the password confirmation the server demands before every consent.
step_up() {
  local status
  status="$(python3 -c 'import json,os; print(json.dumps({"password": os.environ["UPTIMEIFY_ACCEPTANCE_PASSWORD"]}))' \
    | post_json /api/account/mfa/step-up)" || return 1
  case "$status" in 2??) return 0 ;; esac
  return 1
}

# start_login: starts `auth login --no-browser` in the background and reads the authorize address
# from its stderr (at most 10 seconds).
start_login() {
  : >"$tmp/login.out"
  : >"$tmp/login.err"
  "$bin" auth login --no-browser >"$tmp/login.out" 2>"$tmp/login.err" &
  login_pid=$!
  # The wait for the browser has its own limit of 150 s (the CLI's own is 5 minutes).
  ( sleep 150; kill "$login_pid" 2>/dev/null ) &
  login_dog=$!
  authorize_url=""
  for _ in $(seq 100); do
    authorize_url="$(grep -Eo 'https?://[^[:space:]]+/api/auth/oauth2/authorize\?[^[:space:]]+' "$tmp/login.err" | head -n 1 || true)"
    [ -n "$authorize_url" ] && return 0
    kill -0 "$login_pid" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}

# consent GRANT: grants GRANT (comma-separated scopes) or, when empty, every scope the CLI asked
# for except offline_access. Sets redirect to the loopback address that carries code and state.
consent() {
  local target oauth_query status
  redirect=""
  step_up || return 1
  target="$(curl_url "$authorize_url" -o "$tmp/authorize.body" -w '%{redirect_url}' -b "$jar" -c "$jar" -H "Origin: $origin")" || return 1
  if [ -z "$target" ]; then target="$(json 'd.get("url") or ""' <"$tmp/authorize.body")"; fi
  case "$target" in *\?*) ;; *) return 1 ;; esac
  oauth_query="${target#*\?}"
  status="$(AUTH_URL="$authorize_url" GRANT="$1" OAUTH_QUERY="$oauth_query" python3 -c '
import json, os, urllib.parse as u
grant = [s for s in os.environ["GRANT"].split(",") if s]
if not grant:
    asked = u.parse_qs(u.urlsplit(os.environ["AUTH_URL"]).query).get("scope", [""])[0].split()
    grant = [s for s in asked if s != "offline_access"]
print(json.dumps({"accept": True, "scopes": grant, "oauth_query": os.environ["OAUTH_QUERY"]}))' \
    | post_json /api/oauth/consent)" || return 1
  [ "$status" = 200 ] || return 1
  redirect="$(json 'd.get("redirectURI") or ""' <"$tmp/post.body")"
  [ -n "$redirect" ]
}

stop_dog() {
  if [ -n "$login_dog" ]; then
    kill "$login_dog" 2>/dev/null || true
    wait "$login_dog" 2>/dev/null || true
  fi
  login_dog=""
}

abort_login() {
  stop_dog
  if [ -n "$login_pid" ]; then
    kill "$login_pid" 2>/dev/null || true
    wait "$login_pid" 2>/dev/null || true
  fi
  login_pid=""
  login_rc=130
}

wait_login() {
  login_rc=0
  wait "$login_pid" || login_rc=$?
  login_pid=""
  stop_dog
  if [ "$login_rc" -eq 143 ]; then echo "ABORT: auth login was ended after 150 s. A keychain dialog may be waiting." >&2; fi
}

# finish_login: calls the receiver with the redirect like the browser would, then waits for the CLI.
finish_login() {
  if [ -z "$redirect" ]; then abort_login; return 0; fi
  curl_url "$redirect" -o "$tmp/callback.html" || true
  wait_login
}

# login_flow GRANT: the whole browser sign-in; sets login_rc (0 on success).
login_flow() {
  redirect=""
  rm -f "$tmp/callback.html"
  if start_login; then
    consent "$1" || true
    finish_login
  else
    abort_login
  fi
  if [ "$login_rc" -ne 0 ]; then show_login_err; fi
}

connections() { curl -sS --max-time 30 -b "$jar" -c "$jar" -H "Origin: $origin" "$origin/api/oauth/connections?envelope=items"; }

case "$(uname -s)" in
  Darwin) command -v security >/dev/null 2>&1 && kt=security ;;
  Linux) command -v secret-tool >/dev/null 2>&1 && kt=secret-tool ;;
esac

# keyring_entry ACTION ACCOUNT: ACTION is delete or exists, on the CLI's entries (service
# uptimeify-cli). Never prints a secret. Returns 2 without a keyring tool.
keyring_entry() {
  case "$kt:$1" in
    security:delete) run_t 20 security delete-generic-password -s uptimeify-cli -a "$2" >/dev/null 2>&1 ;;
    security:exists) run_t 20 security find-generic-password -s uptimeify-cli -a "$2" >/dev/null 2>&1 ;;
    secret-tool:delete) run_t 20 secret-tool clear service uptimeify-cli username "$2" >/dev/null 2>&1 ;;
    secret-tool:exists) run_t 20 secret-tool lookup service uptimeify-cli username "$2" >/dev/null 2>&1 ;;
    *) return 2 ;;
  esac
}

no_keyring_entries() { ! keyring_entry exists "$origin" && ! keyring_entry exists "$origin access"; }

# A run that stopped early may have left a sign-in for this host.
cli auth logout >/dev/null 2>&1 || true

desc="L0 the account signs in (browser session for the consent step)"; check sign_in

cli auth status >"$tmp/status.out" 2>&1 || true
desc="L1 auth status before the login shows Token: not set"; check grep -qF 'Token: not set' "$tmp/status.out"

login_flow ""
desc="L2 auth login --no-browser with the default scopes exits 0 (got $login_rc)"; check test "$login_rc" -eq 0
desc="L2 auth login reports the sign-in"; check grep -qF 'Signed in to' "$tmp/login.out"

code="$(query_param code "$redirect")"
desc="L3 the receiver page says Signed in"; check grep -qF 'Signed in' "$tmp/callback.html"
desc="L3 the receiver page does not contain the authorization code"; check file_lacks "$code" "$tmp/callback.html"

desc="L4 the CLI printed the authorize address"; check grep -qF '/api/auth/oauth2/authorize?' "$tmp/login.err"
desc="L4 the CLI's stderr does not contain the authorization code"; check file_lacks "$code" "$tmp/login.err"
desc="L4 the CLI's stdout does not contain the authorization code"; check file_lacks "$code" "$tmp/login.out"

cli auth status >"$tmp/status.out" 2>&1 || true
desc="L5 auth status names the browser sign-in"; check grep -qF 'browser sign-in' "$tmp/status.out"
desc="L5 auth status shows the organization"; check awk '/^  Organization:/ { found = 1; if ($0 ~ /unavailable/) bad = 1 } END { exit !(found && !bad) }' "$tmp/status.out"
desc="L5 auth status lists api:monitors:write"; check grep -qF 'api:monitors:write' "$tmp/status.out"
desc="L5 auth status says when the sign-in ends"; check grep -qF 'Sign-in ends:' "$tmp/status.out"

# Tag names are limited to 24 characters and need a color.
name="cliacc-$$"
export name
id="$(cli tags create --field "name=$name" --field "color=green" --json 2>/dev/null | json 'd.get("id") or d["tag"]["id"]')" || id=""
export id
desc="L6 tags create returns an id"; check test -n "$id"
desc="L6 tags list shows the new tag"; check bash -c 'cli tags list --json | grep -q "$name"'
desc="L6 tags update renames it"; check cli tags update "$id" --field "name=$name-r" --json
desc="L6 tags delete with --yes works"; check cli tags delete "$id" --yes
desc="L6 the deleted tag is gone from the list"; check bash -c '! cli tags list --json | grep -q "$name"'

if [ -n "$kt" ]; then
  keyring_entry delete "$origin access" || true
  desc="L7 renewal against the server: tags list after dropping the cached access token"; check cli tags list --json
  desc="L7 the renewal stored a new access token in the keyring"; check keyring_entry exists "$origin access"
else
  desc="L7 renewal against the server (no keyring tool to drop the cached access token)"; skip
fi

if [ -n "$kt" ]; then
  keyring_entry delete "$origin access" || true
  pids=()
  for i in 1 2 3 4; do cli tags list --json >/dev/null 2>"$tmp/parallel-$i.err" & pids+=("$!"); done
  par_fail=0
  for p in "${pids[@]}"; do wait "$p" || par_fail=$((par_fail+1)); done
  desc="L8 four processes renew at the same time and all exit 0 ($par_fail failed)"; check test "$par_fail" -eq 0
  desc="L8 the refresh token family is still alive afterwards"; check cli tags list --json
else
  desc="L8 parallel renewal (no keyring tool to drop the cached access token)"; skip
fi

envrc=0
fake="$(printf 'wsm_%s' not-a-token)"
UPTIMEIFY_TOKEN="$fake" cli tags list >/dev/null 2>&1 || envrc=$?
desc="L9 UPTIMEIFY_TOKEN takes precedence over the stored sign-in (exit $envrc, expected 3)"; check test "$envrc" -eq 3

login_flow "api:monitors:read,api:organization:read"
desc="L10 a second login that grants only read scopes exits 0 (got $login_rc)"; check test "$login_rc" -eq 0
wrc=0
cli tags create --field "name=$name-w" --field "color=green" >/dev/null 2>"$tmp/scope.err" || wrc=$?
desc="L10 a write with the read-only sign-in exits 3 (got $wrc)"; check test "$wrc" -eq 3
desc="L10 the error suggests uptimeify auth login --scope api:monitors:write"; check grep -qF 'uptimeify auth login --scope api:monitors:write' "$tmp/scope.err"

client_id="$(connections | json 'd["items"][0]["client_id"] if len(d["items"]) == 1 and str(d["items"][0].get("client_id", "")).startswith("ucli_") else ""')" || client_id=""
desc="L11 Connected apps lists exactly one device, the reused ucli_ client"; check test -n "$client_id"

redirect=""
wrong_status=""
alive=0
if start_login; then
  callback="$(query_param redirect_uri "$authorize_url")"
  state="$(query_param state "$authorize_url")"
  # A forged answer without the right state: 404, and the CLI keeps waiting.
  wrong_status="$(curl_url "$callback?error=access_denied&error_description=forged-by-a-third-party&state=wrong-state" -o /dev/null -w '%{http_code}')" || wrong_status=""
  sleep 0.5
  if kill -0 "$login_pid" 2>/dev/null; then alive=1; fi
  # The browser's own refusal carries the right state and ends the login.
  curl_url "$callback?error=access_denied&state=$state" -o /dev/null || true
  wait_login
else
  abort_login
fi
desc="L12 a callback with a wrong state gets 404 (got $wrong_status)"; check test "$wrong_status" = 404
desc="L12 the login keeps waiting after a callback with a wrong state"; check test "$alive" -eq 1
desc="L12 the refusal with the right state ends the login with exit 3 (got $login_rc)"; check test "$login_rc" -eq 3
desc="L12 the CLI reports the refusal"; check grep -qF 'access_denied' "$tmp/login.err"
desc="L12 the forged error description never reached the terminal"; check file_lacks 'forged-by-a-third-party' "$tmp/login.err"
desc="L12 the earlier sign-in still works"; check cli tags list --json

step_up || true
delstatus="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -X DELETE -b "$jar" -c "$jar" -H "Origin: $origin" "$origin/api/oauth/connections/$client_id")" || delstatus=""
desc="L13 disconnecting the device under Connected apps answers 200 (got $delstatus)"; check test "$delstatus" = 200
rrc=0
cli tags list >/dev/null 2>"$tmp/revoked.err" || rrc=$?
desc="L13 the next command exits 3 (got $rrc)"; check test "$rrc" -eq 3
desc="L13 it asks for uptimeify auth login"; check grep -qF 'auth login' "$tmp/revoked.err"
cli auth status >"$tmp/status.out" 2>&1 || true
desc="L13 auth status shows Token: not set"; check grep -qF 'Token: not set' "$tmp/status.out"

login_flow ""
desc="L14 a new login after the disconnect exits 0 (got $login_rc)"; check test "$login_rc" -eq 0
lrc=0
cli auth logout >"$tmp/logout.out" 2>&1 || lrc=$?
desc="L14 auth logout exits 0 (got $lrc)"; check test "$lrc" -eq 0
desc="L14 auth logout reports the revocation on the server"; check grep -qF 'The server revoked the sign-in.' "$tmp/logout.out"
nrc=0
cli tags list >/dev/null 2>"$tmp/after-logout.err" || nrc=$?
desc="L14 after the logout a command exits 3 (got $nrc)"; check test "$nrc" -eq 3
desc="L14 it says not signed in"; check grep -qF 'not signed in' "$tmp/after-logout.err"

if [ -n "$kt" ]; then
  desc="L15 no keyring entry is left for $origin"; check no_keyring_entries
else
  desc="L15 keyring left empty (no keyring tool to look)"; skip
fi

echo "passed: $pass, failed: $fail, skipped: $skipped"
test "$fail" -eq 0
