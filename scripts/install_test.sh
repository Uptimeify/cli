#!/bin/sh
# Tests for scripts/install.sh. No network: releases are local fixtures read over file://,
# which install.sh only allows with UPTIMEIFY_TEST=1. Runs locally and in CI.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
installer="$here/install.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/install-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail=0
pass() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# Fixture release v1.2.3 for linux/amd64, linux/arm64 and darwin/arm64.
rel="$work/releases/v1.2.3"
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

# Stub cosigns. Each records its arguments.
stubs="$work/stubs"
mkdir -p "$stubs"
printf '#!/bin/sh\nprintf "%%s\\n" "$@" >"%s/cosign.args"\nexit 0\n' "$work" >"$stubs/cosign-ok"
printf '#!/bin/sh\nexit 1\n' >"$stubs/cosign-fail"
chmod 755 "$stubs/cosign-ok" "$stubs/cosign-fail"

# run NAME EXPECT(0|1) [VAR=VALUE ...]: runs the installer into a fresh install dir.
# Output goes to $work/out. The install dir is $work/bin-NAME.
run() {
  name="$1"; expect="$2"; shift 2
  dir="$work/bin-$name"
  rc=0
  env -i PATH="$PATH" HOME="$work/home" TMPDIR="$work" \
    UPTIMEIFY_TEST=1 UPTIMEIFY_BASE_URL="file://$work/releases" UPTIMEIFY_VERSION=1.2.3 \
    UPTIMEIFY_UNAME_S=Linux UPTIMEIFY_UNAME_M=x86_64 UPTIMEIFY_COSIGN=/nonexistent/cosign \
    UPTIMEIFY_INSTALL_DIR="$dir" "$@" sh "$installer" >"$work/out" 2>&1 || rc=$?
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
check() { # NAME CONDITION-COMMAND...
  n="$1"; shift
  if "$@"; then pass "$n"; else bad "$n"; fi
}

# 1. happy path, no cosign: installs, says the signature was not verified
if run happy 0; then
  check "happy: binary installed" installed happy
  check "happy: checksum verified" said "checksum of uptimeify_1.2.3_linux_amd64.tar.gz verified"
  check "happy: warns that only the checksum was verified" said "only the SHA-256 checksum is verified"
  check "happy: tells how to verify by hand" said "cosign verify-blob"
  check "happy: no temp dirs left behind" sh -c "! ls '$work' | grep -q '^uptimeify-install\.'"
  check "happy: no staged file left behind" sh -c "! ls -A '$work/bin-happy' | grep -q '^\.uptimeify\.'"
fi

# 2. checksum mismatch: abort, nothing installed
mm="$work/releases-mm"
cp -R "$work/releases" "$mm"
sed 's/^[0-9a-f]\{64\}/0000000000000000000000000000000000000000000000000000000000000000/' "$work/releases/v1.2.3/checksums.txt" >"$mm/v1.2.3/checksums.txt"
if run mismatch 1 UPTIMEIFY_BASE_URL="file://$mm"; then
  check "mismatch: says checksum mismatch" said "checksum mismatch"
  check "mismatch: nothing installed" sh -c "! [ -e '$work/bin-mismatch/uptimeify' ]"
fi

# 3. archive not listed in checksums.txt
nl="$work/releases-nl"
cp -R "$work/releases" "$nl"
grep -v linux_amd64 "$work/releases/v1.2.3/checksums.txt" >"$nl/v1.2.3/checksums.txt"
if run notlisted 1 UPTIMEIFY_BASE_URL="file://$nl"; then
  check "not listed: says so" said "is not listed in checksums.txt"
fi

# 4. unsupported platforms
if run bados 1 UPTIMEIFY_UNAME_S=FreeBSD; then
  check "unsupported OS: message" said "unsupported operating system"
  check "unsupported OS: nothing installed" sh -c "! [ -e '$work/bin-bados/uptimeify' ]"
fi
if run badarch 1 UPTIMEIFY_UNAME_M=riscv64; then
  check "unsupported arch: message" said "unsupported CPU architecture"
fi
if run arm 0 UPTIMEIFY_UNAME_M=aarch64; then
  check "arm64 is mapped" installed arm
fi
if run mac 0 UPTIMEIFY_UNAME_S=Darwin UPTIMEIFY_UNAME_M=arm64; then
  check "darwin/arm64 is mapped" installed mac
fi

# 5. cosign present
if run cosignok 0 UPTIMEIFY_COSIGN="$stubs/cosign-ok"; then
  check "cosign ok: installed" installed cosignok
  check "cosign ok: identity pinned to the release workflow and tag" \
    grep -qx 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/v1.2.3' "$work/cosign.args"
  check "cosign ok: issuer pinned" grep -qx 'https://token.actions.githubusercontent.com' "$work/cosign.args"
  check "cosign ok: no checksum-only warning" sh -c "! grep -q 'only the SHA-256' '$work/out'"
fi
if run cosignfail 1 UPTIMEIFY_COSIGN="$stubs/cosign-fail"; then
  check "cosign failure: says so" said "does not verify"
  check "cosign failure: nothing installed" sh -c "! [ -e '$work/bin-cosignfail/uptimeify' ]"
fi
if run reqsig 1 UPTIMEIFY_REQUIRE_SIGNATURE=1; then
  check "require signature without cosign: aborts" said "UPTIMEIFY_REQUIRE_SIGNATURE"
fi

# 6. root
if run root 1 UPTIMEIFY_TEST_UID=0; then
  check "root: refused" said "refusing to run as root"
fi
if run rootok 0 UPTIMEIFY_TEST_UID=0 UPTIMEIFY_ALLOW_ROOT=1; then
  check "root with UPTIMEIFY_ALLOW_ROOT=1: allowed" installed rootok
fi

# 7. inputs
if run relpath 1 UPTIMEIFY_INSTALL_DIR=relative/dir; then
  check "relative install dir: refused" said "absolute path"
fi
for v in '../../x' '1.2' '1.2.3/../../x' '1.2.3;id' 'latest'; do
  if run badver 1 UPTIMEIFY_VERSION="$v"; then
    check "bad version '$v': refused" said "not a version"
  fi
done
rc=0
env -i PATH="$PATH" HOME="$work/home" UPTIMEIFY_BASE_URL="file://$work/releases" UPTIMEIFY_VERSION=1.2.3 \
  UPTIMEIFY_INSTALL_DIR="$work/bin-nobase" sh "$installer" >"$work/out" 2>&1 || rc=$?
check "UPTIMEIFY_BASE_URL without UPTIMEIFY_TEST: refused" sh -c "[ $rc != 0 ] && grep -q 'only honoured with UPTIMEIFY_TEST=1' '$work/out'"
check "UPTIMEIFY_BASE_URL without UPTIMEIFY_TEST: nothing installed" sh -c "! [ -e '$work/bin-nobase/uptimeify' ]"

# 8. a truncated download runs nothing: drop the last line (the call of main)
sed '$d' "$installer" >"$work/truncated.sh"
rc=0
env -i PATH="$PATH" HOME="$work/home" UPTIMEIFY_INSTALL_DIR="$work/bin-trunc" sh "$work/truncated.sh" >"$work/out" 2>&1 || rc=$?
check "truncated script: exits 0, prints nothing, installs nothing" \
  sh -c "[ $rc = 0 ] && [ ! -s '$work/out' ] && ! [ -e '$work/bin-trunc' ]"
check "main is called on the last line" sh -c "[ \"\$(tail -n 1 '$installer')\" = 'main \"\$@\"' ]"

# 9. no eval, no sudo
check "no eval in the installer" sh -c "! grep -v '^ *#' '$installer' | grep -Eq '(^|[^a-z_])eval[ (]'"
check "no sudo in the installer" sh -c "! grep -v '^ *#' '$installer' | grep -Eq '(^|[^a-z_])sudo( |$)'"

if [ "$fail" = 0 ]; then echo "all install tests passed"; else echo "install tests FAILED"; fi
exit "$fail"
