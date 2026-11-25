#!/bin/sh
# Tests for scripts/install.sh. The script under test is the shipped file, unchanged: it has no
# test hooks. Everything it calls (uname, id, curl, cosign, gh) is replaced by a fake executable
# that comes first on PATH, and PATH holds nothing else but symlinks to the plain tools the script
# needs, so a cosign or gh on this machine can never leak into a run. No network.
# The fake curl serves fixture files for the URLs the script asks for and records every request.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
installer="$here/install.sh"
root="$(cd "$here/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail=0
count=0
pass() { count=$((count + 1)); printf 'ok   %s\n' "$1"; }
bad() { count=$((count + 1)); fail=1; printf 'FAIL %s\n' "$1"; }
skip() { printf 'skip %s\n' "$1"; }

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ---- fake tools -------------------------------------------------------------------------------
# tools/: plain tools the installer needs. The "nosha" variant has no sha256 tool.
tools="$work/tools"
tools_nosha="$work/tools-nosha"
mkdir -p "$tools" "$tools_nosha"
for t in awk grep tar gzip mktemp mkdir chmod mv rm cat wc tr; do
  p="$(command -v "$t")" || { echo "test needs $t" >&2; exit 2; }
  ln -s "$p" "$tools/$t"
  ln -s "$p" "$tools_nosha/$t"
done
for t in sha256sum shasum; do
  if p="$(command -v "$t" 2>/dev/null)"; then ln -s "$p" "$tools/$t"; fi
done
shbin="$(command -v sh)"

# stubs/: uname, id, curl. They read FAKE_* variables from the environment of the run.
stubs="$work/stubs"
mkdir -p "$stubs"
cat >"$stubs/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "${FAKE_UNAME_S:-Linux}" ;;
  -m) printf '%s\n' "${FAKE_UNAME_M:-x86_64}" ;;
  *) exit 2 ;;
esac
EOF
cat >"$stubs/id" <<'EOF'
#!/bin/sh
[ "$1" = "-u" ] || exit 2
printf '%s\n' "${FAKE_UID:-1000}"
EOF
cat >"$stubs/curl" <<'EOF'
#!/bin/sh
# Records "<proto>|<proto-redir>|<tls>|<head>|<url>" per call. Anything that is not HTTPS-only
# with TLS 1.2 is logged as VIOLATION and fails, so the tests can assert on it.
out=""; url=""; proto=""; redir=""; tls=0; head=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    --proto) proto="$2"; shift 2 ;;
    --proto-redir) redir="$2"; shift 2 ;;
    --tlsv1.2) tls=1; shift ;;
    --*) shift ;;
    -*I*) head=1; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s|%s|%s|%s|%s\n' "$proto" "$redir" "$tls" "$head" "$url" >>"$FAKE_LOG"
case "$url" in https://*) ;; *) echo "VIOLATION $url" >>"$FAKE_LOG"; exit 99 ;; esac
[ "$proto" = "=https" ] && [ "$redir" = "=https" ] && [ "$tls" = 1 ] || { echo "VIOLATION flags $url" >>"$FAKE_LOG"; exit 99; }
if [ "$head" = 1 ]; then
  [ "${FAKE_LATEST_FAIL:-}" != 1 ] || exit 22
  printf '%s' "${FAKE_LATEST_URL:-https://github.com/Uptimeify/cli/releases/tag/v1.2.3}"
  exit 0
fi
rel="${url#https://github.com/Uptimeify/cli/releases/download/}"
[ "$rel" != "$url" ] && [ -f "$FAKE_FIX/$rel" ] || exit 22
cat "$FAKE_FIX/$rel" >"$out"
EOF
chmod 755 "$stubs/uname" "$stubs/id" "$stubs/curl"

# mk_verifier DIR NAME VARPART: a fake cosign or gh. Records its arguments in $work/NAME.args.
# FAKE_<VARPART>_RC != 0 makes it fail with a message on stderr.
mk_verifier() {
  mkdir -p "$1"
  cat >"$1/$2" <<EOF
#!/bin/sh
printf '%s\\n' "\$@" >"$work/$2.args"
if [ "\${FAKE_${3}_RC:-0}" != 0 ]; then echo "$2 stub: verification failed (identity mismatch)" >&2; exit "\${FAKE_${3}_RC}"; fi
echo "$2 stub: ok" >&2
EOF
  chmod 755 "$1/$2"
}
mk_verifier "$work/v-cosign" cosign COSIGN
mk_verifier "$work/v-gh" gh GH

# ---- fixture release v1.2.3 -------------------------------------------------------------------
fix="$work/releases"
rel="$fix/v1.2.3"
mkdir -p "$rel" "$work/pkg"
printf '#!/bin/sh\necho uptimeify fixture\n' >"$work/pkg/uptimeify"
chmod 755 "$work/pkg/uptimeify"
: >"$rel/checksums.txt"
for t in linux_amd64 linux_arm64 darwin_arm64; do
  a="uptimeify_1.2.3_$t.tar.gz"
  tar -czf "$rel/$a" -C "$work/pkg" uptimeify
  printf '%s  %s\n' "$(sha "$rel/$a")" "$a" >>"$rel/checksums.txt"
done
printf '{"fixture":true}\n' >"$rel/checksums.txt.sigstore.json"

# ---- runner -----------------------------------------------------------------------------------
# run NAME EXPECT(0|1) [VAR=VALUE ...]: runs the installer into $work/bin-NAME.
# Globals: xpath (extra PATH dirs in front, e.g. a fake cosign), base (tools dir), noversion=1
# leaves UPTIMEIFY_VERSION unset. Output: $work/out. Requests: $work/curl.log.
xpath=""
base="$tools"
noversion=0
run() {
  name="$1"; expect="$2"; shift 2
  dir="$work/bin-$name"
  : >"$work/curl.log"
  rm -f "$work/cosign.args" "$work/gh.args"
  rc=0
  if [ "$noversion" = 1 ]; then ver="UPTIMEIFY_NOVERSION=1"; else ver="UPTIMEIFY_VERSION=1.2.3"; fi
  env -i PATH="$xpath$stubs:$base" HOME="$work/home" TMPDIR="$work" \
    FAKE_FIX="$fix" FAKE_LOG="$work/curl.log" "$ver" \
    UPTIMEIFY_INSTALL_DIR="$dir" "$@" "$shbin" "$installer" >"$work/out" 2>&1 || rc=$?
  if { [ "$expect" = 0 ] && [ "$rc" = 0 ]; } || { [ "$expect" = 1 ] && [ "$rc" != 0 ]; }; then
    return 0
  fi
  bad "$name: exit code $rc, expected $expect"
  sed 's/^/     | /' "$work/out"
  return 1
}
# shellcheck disable=SC2329 # called through check()
installed() { [ -x "$work/bin-$1/uptimeify" ]; }
# shellcheck disable=SC2329 # called through check()
said() { grep -q -- "$1" "$work/out"; }
# shellcheck disable=SC2329 # called through check()
no_download() { [ ! -s "$work/curl.log" ]; }
check() { # NAME CONDITION-COMMAND...
  n="$1"; shift
  if "$@"; then pass "$n"; else bad "$n"; fi
}
with_cosign() { xpath="$work/v-cosign:"; }
with_gh() { xpath="$work/v-gh:"; }
with_both() { xpath="$work/v-cosign:$work/v-gh:"; }
with_none() { xpath=""; }

# 1. no verifier installed
with_none
if run noverifier 1; then
  check "no cosign, no gh: aborts" said "neither cosign nor gh is installed"
  check "no cosign, no gh: explains how to get cosign" said "https://docs.sigstore.dev/cosign/installation/"
  check "no cosign, no gh: names UPTIMEIFY_ALLOW_UNSIGNED and its limit" said "gives no protection against a replaced release"
  check "no cosign, no gh: nothing installed" sh -c "! [ -e '$work/bin-noverifier/uptimeify' ]"
fi
if run unsigned 0 UPTIMEIFY_ALLOW_UNSIGNED=1; then
  check "UPTIMEIFY_ALLOW_UNSIGNED=1 without a verifier: installs" installed unsigned
  check "UPTIMEIFY_ALLOW_UNSIGNED=1: checksum verified" said "checksum of uptimeify_1.2.3_linux_amd64.tar.gz verified"
  check "UPTIMEIFY_ALLOW_UNSIGNED=1: warns that the signature was not verified" said "the signature is not"
  check "no temp dirs left behind" sh -c "! ls '$work' | grep -q '^uptimeify-install\.'"
  check "no staged file left behind" sh -c "! ls -A '$work/bin-unsigned' | grep -q '^\.uptimeify\.'"
  check "installed file is executable and has the archive content" sh -c "[ \"\$('$work/bin-unsigned/uptimeify')\" = 'uptimeify fixture' ]"
fi
if run unsigned2 1 UPTIMEIFY_ALLOW_UNSIGNED=yes; then
  check "UPTIMEIFY_ALLOW_UNSIGNED=yes is not 1: aborts" said "neither cosign nor gh is installed"
fi

# 2. cosign
with_cosign
if run cosignok 0; then
  check "cosign ok: installed" installed cosignok
  check "cosign ok: identity pinned to the release workflow and tag" \
    grep -qx 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/v1.2.3' "$work/cosign.args"
  check "cosign ok: issuer pinned" grep -qx 'https://token.actions.githubusercontent.com' "$work/cosign.args"
  check "cosign ok: verifies the bundle of checksums.txt" grep -q 'checksums.txt.sigstore.json' "$work/cosign.args"
  check "cosign ok: no checksum-only warning" sh -c "! grep -q 'only the SHA-256' '$work/out'"
fi
if run cosignfail 1 FAKE_COSIGN_RC=1; then
  check "cosign failure: says so" said "cosign could not verify"
  check "cosign failure: shows the tool's own error" said "cosign stub: verification failed"
  check "cosign failure: names the tested cosign version" said "tested with cosign v3.1.6"
  check "cosign failure: nothing installed" sh -c "! [ -e '$work/bin-cosignfail/uptimeify' ]"
fi
if run cosignfail2 1 FAKE_COSIGN_RC=1 UPTIMEIFY_ALLOW_UNSIGNED=1; then
  check "UPTIMEIFY_ALLOW_UNSIGNED=1 never skips a failed cosign check" sh -c "! [ -e '$work/bin-cosignfail2/uptimeify' ]"
fi
want="$(sed -n 's/^ *cosign-release: *//p' "$root/.github/workflows/release.yml")"
check "COSIGN_TESTED in install.sh equals cosign-release in release.yml" \
  sh -c "[ -n '$want' ] && grep -qx 'COSIGN_TESTED=\"$want\"' '$installer'"

# 3. gh (no cosign)
with_gh
if run ghok 0; then
  check "gh ok: installed" installed ghok
  check "gh ok: verifies the archive" grep -q 'uptimeify_1.2.3_linux_amd64.tar.gz' "$work/gh.args"
  check "gh ok: repo pinned" sh -c "grep -qx -- '--repo' '$work/gh.args' && grep -qx 'Uptimeify/cli' '$work/gh.args'"
  check "gh ok: signer workflow pinned" grep -qx 'Uptimeify/cli/.github/workflows/release.yml' "$work/gh.args"
  check "gh ok: source ref pinned to the tag" grep -qx 'refs/tags/v1.2.3' "$work/gh.args"
  check "gh ok: self-hosted runners denied" grep -qx -- '--deny-self-hosted-runners' "$work/gh.args"
  check "gh ok: subcommand is attestation verify" sh -c "[ \"\$(sed -n 1p '$work/gh.args')\" = attestation ] && [ \"\$(sed -n 2p '$work/gh.args')\" = verify ]"
fi
if run ghfail 1 FAKE_GH_RC=1; then
  check "gh failure: says so" said "gh could not verify"
  check "gh failure: shows the tool's own error" said "gh stub: verification failed"
  check "gh failure: nothing installed" sh -c "! [ -e '$work/bin-ghfail/uptimeify' ]"
fi
if run ghfail2 1 FAKE_GH_RC=1 UPTIMEIFY_ALLOW_UNSIGNED=1; then
  check "UPTIMEIFY_ALLOW_UNSIGNED=1 never skips a failed gh check" sh -c "! [ -e '$work/bin-ghfail2/uptimeify' ]"
fi

# 4. both: cosign wins, gh is not asked
with_both
if run both 0; then
  check "cosign and gh present: cosign is used" test -f "$work/cosign.args"
  check "cosign and gh present: gh is not called" sh -c "! [ -e '$work/gh.args' ]"
fi

# 5. checksum problems (a verifier is present so the signature never hides them)
with_cosign
mm="$work/releases-mm"
cp -R "$fix" "$mm"
sed 's/^[0-9a-f]\{64\}/0000000000000000000000000000000000000000000000000000000000000000/' "$rel/checksums.txt" >"$mm/v1.2.3/checksums.txt"
if run mismatch 1 FAKE_FIX="$mm"; then
  check "mismatch: says checksum mismatch" said "checksum mismatch"
  check "mismatch: nothing installed" sh -c "! [ -e '$work/bin-mismatch/uptimeify' ]"
  check "mismatch: no verifier was reached" sh -c "! [ -e '$work/cosign.args' ]"
fi
nl="$work/releases-nl"
cp -R "$fix" "$nl"
grep -v linux_amd64 "$rel/checksums.txt" >"$nl/v1.2.3/checksums.txt"
if run notlisted 1 FAKE_FIX="$nl"; then
  check "not listed: says so" said "is not listed in checksums.txt"
fi
dup="$work/releases-dup"
cp -R "$fix" "$dup"
{ cat "$rel/checksums.txt"; grep linux_amd64 "$rel/checksums.txt"; } >"$dup/v1.2.3/checksums.txt"
if run dup 1 FAKE_FIX="$dup"; then
  check "duplicated line: says so" said "listed more than once"
  check "duplicated line: nothing installed" sh -c "! [ -e '$work/bin-dup/uptimeify' ]"
fi
base="$tools_nosha"
if run nosha 1; then
  check "no sha256 tool: says so" said "neither sha256sum nor shasum"
  check "no sha256 tool: nothing installed" sh -c "! [ -e '$work/bin-nosha/uptimeify' ]"
fi
base="$tools"

# 6. platforms
if run bados 1 FAKE_UNAME_S=FreeBSD; then
  check "unsupported OS: message" said "unsupported operating system"
  check "unsupported OS: nothing downloaded" no_download
fi
if run badarch 1 FAKE_UNAME_M=riscv64; then
  check "unsupported arch: message" said "unsupported CPU architecture"
fi
if run arm 0 FAKE_UNAME_M=aarch64; then
  check "arm64 is mapped" installed arm
fi
if run mac 0 FAKE_UNAME_S=Darwin FAKE_UNAME_M=arm64; then
  check "darwin/arm64 is mapped" installed mac
fi

# 7. root
if run root 1 FAKE_UID=0; then
  check "root: refused" said "refusing to run as root"
  check "root: nothing downloaded" no_download
fi
if run rootok 0 FAKE_UID=0 UPTIMEIFY_ALLOW_ROOT=1; then
  check "root with UPTIMEIFY_ALLOW_ROOT=1: allowed" installed rootok
fi

# 8. versions: hostile values stop before any download
if run relpath 1 UPTIMEIFY_INSTALL_DIR=relative/dir; then
  check "relative install dir: refused" said "absolute path"
fi
nl_value="$(printf '1.2.3\nv9.9.9')"
# shellcheck disable=SC2016 # '$(id)' must stay literal: it is the hostile value
for v in '../../x' '1.2' '1.2.3/../../x' '1.2.3;id' 'latest' 'v1.0.0;rm -rf' '' '1.2.3 ' '$(id)' '1.2.3&&id' "$nl_value"; do
  shown="$(printf '%s' "$v" | tr '\n' '~')"
  if run badver 1 UPTIMEIFY_VERSION="$v"; then
    check "bad version '$shown': refused" said "not a version"
    check "bad version '$shown': nothing downloaded" no_download
  fi
done
# the variable unset means "latest": one HEAD request to the releases page, then the download
noversion=1
if run latest 0; then
  check "no UPTIMEIFY_VERSION: resolves the latest release" installed latest
  check "no UPTIMEIFY_VERSION: asks releases/latest first" sh -c "head -n 1 '$work/curl.log' | grep -q '|1|https://github.com/Uptimeify/cli/releases/latest\$'"
fi
if run latesthostile 1 FAKE_LATEST_URL='https://github.com/Uptimeify/cli/releases/tag/v1.0.0;id'; then
  check "hostile redirect target: refused" said "not a version"
fi
if run latestnone 1 FAKE_LATEST_FAIL=1; then
  check "no release yet: clear message" said "could not look up the latest release"
fi
noversion=0

# 9. HTTPS only: every request of a full run
if run https 0; then
  check "https: at least archive, checksums and bundle were requested" sh -c "[ \$(wc -l <'$work/curl.log') -ge 3 ]"
  check "https: every request had --proto =https, --proto-redir =https, --tlsv1.2 and an https URL" \
    sh -c "! grep -v '^=https|=https|1|[01]|https://' '$work/curl.log' && ! grep -q VIOLATION '$work/curl.log'"
  check "https: all requests go to github.com/Uptimeify/cli" sh -c "! grep -v 'https://github.com/Uptimeify/cli/' '$work/curl.log'"
fi

# 10. install directory
# a symlink at a predictable staging path is not followed (the old name was .uptimeify.<pid>.new)
victim="$work/victim"
printf 'precious\n' >"$victim"
dir="$work/bin-symlink"
mkdir -p "$dir"
i=1
while [ "$i" -le 40 ]; do ln -s "$victim" "$dir/.uptimeify.$i.new"; i=$((i + 1)); done
ln -s "$victim" "$dir/.uptimeify.new"
ln -s "$victim" "$dir/uptimeify"
if run symlink 0; then
  check "predictable staging symlinks: victim file untouched" sh -c "[ \"\$(cat '$victim')\" = precious ]"
  check "predictable staging symlinks: binary installed in place of the link" sh -c "[ ! -L '$dir/uptimeify' ] && [ \"\$('$dir/uptimeify')\" = 'uptimeify fixture' ]"
fi
# shellcheck disable=SC2016 # the pattern contains a literal $install_dir
check "staging file comes from mktemp" grep -q 'mktemp "\$install_dir/.uptimeify.XXXXXX"' "$installer"
check "staging name does not use the process id" sh -c "! grep -v '^ *#' '$installer' | grep -q '\\\$\\\$'"
# an install dir owned by someone else is refused. /usr/bin exists everywhere and is not ours
# unless this runs as root, in which case the case cannot be simulated.
# shellcheck disable=SC3067 # -O works in dash, bash and macOS sh
if [ -O /usr/bin ]; then
  skip "foreign install dir: /usr/bin is owned by this user (running as root), cannot simulate without a second user"
else
  if run foreign 1 UPTIMEIFY_INSTALL_DIR=/usr/bin; then
    check "foreign install dir: refused with the reason" said "is not a directory you own"
    check "foreign install dir: nothing was written there" sh -c "! ls -A /usr/bin | grep -q '^\.uptimeify\.'"
  fi
fi

# 11. a truncated download runs nothing: drop the last line (the call of main)
sed '$d' "$installer" >"$work/truncated.sh"
rc=0
env -i PATH="$stubs:$tools" HOME="$work/home" UPTIMEIFY_INSTALL_DIR="$work/bin-trunc" "$shbin" "$work/truncated.sh" >"$work/out" 2>&1 || rc=$?
check "truncated script: exits 0, prints nothing, installs nothing" \
  sh -c "[ $rc = 0 ] && [ ! -s '$work/out' ] && ! [ -e '$work/bin-trunc' ]"
check "main is called on the last line" sh -c "[ \"\$(tail -n 1 '$installer')\" = 'main \"\$@\"' ]"

# 12. static properties of the shipped script
check "no test hooks or redirect variables in the installer" \
  sh -c "! grep -n 'UPTIMEIFY_TEST\|UPTIMEIFY_COSIGN\|UPTIMEIFY_BASE_URL\|UPTIMEIFY_UNAME\|UPTIMEIFY_REQUIRE_SIGNATURE\|file://' '$installer'"
check "the only UPTIMEIFY_ variables are the documented four" \
  sh -c "[ \"\$(grep -o 'UPTIMEIFY_[A-Z_]*' '$installer' | sort -u | tr '\n' ' ')\" = 'UPTIMEIFY_ALLOW_ROOT UPTIMEIFY_ALLOW_UNSIGNED UPTIMEIFY_INSTALL_DIR UPTIMEIFY_VERSION ' ]"
check "no eval in the installer" sh -c "! grep -v '^ *#' '$installer' | grep -Eq '(^|[^a-z_])eval[ (]'"
check "no sudo in the installer" sh -c "! grep -v '^ *#' '$installer' | grep -Eq '(^|[^a-z_])sudo( |$)'"
check "no plain http:// URL in the installer" sh -c "! grep -v '^ *#' '$installer' | grep -q 'http://'"

if [ "$fail" = 0 ]; then echo "all $count install checks passed"; else echo "install tests FAILED ($count checks)"; fi
exit "$fail"
