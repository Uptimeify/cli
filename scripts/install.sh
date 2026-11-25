#!/bin/sh
# Installer for the Uptimeify CLI (Linux and macOS). Intended to be served from
# https://uptimeify.io/install.sh. Read it before you run it: it is short.
#
# What it does:
#   1. picks the release (UPTIMEIFY_VERSION, default: the latest release)
#   2. downloads the archive and checksums.txt over HTTPS
#   3. verifies the SHA-256 of the archive against checksums.txt
#   4. verifies the signature: cosign (signature of checksums.txt) if installed, else the
#      GitHub CLI (`gh attestation verify` of the archive), else it stops
#   5. installs the binary into ${UPTIMEIFY_INSTALL_DIR:-$HOME/.local/bin}, without sudo
#
# Environment:
#   UPTIMEIFY_VERSION         X.Y.Z or vX.Y.Z. Default (variable not set): latest release.
#   UPTIMEIFY_INSTALL_DIR     absolute path to a directory you own. Default: $HOME/.local/bin.
#   UPTIMEIFY_ALLOW_UNSIGNED  1 = continue with the checksum only when neither cosign nor gh is
#                             installed. Never skips a verification that ran and failed.
#   UPTIMEIFY_ALLOW_ROOT      1 = allow running as root.
# There is no variable that changes where this script downloads from or which verifier it runs.
# Only PATH decides which cosign, gh, curl and tar are used.
#
# Everything lives in main(), which is called on the last line. A download that is cut off
# before that line defines functions and runs nothing.
set -eu

REPO="Uptimeify/cli"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
SIGNER_WORKFLOW="$REPO/.github/workflows/release.yml"
# The cosign version the release workflow signs with and this script is tested against
# (cosign-release in .github/workflows/release.yml; scripts/install_test.sh keeps them equal).
COSIGN_TESTED="v3.1.6"
BASE="https://github.com/$REPO/releases/download"

TMP_DIR=""
STAGED=""

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "$STAGED" ]; then rm -f "$STAGED"; fi
  if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
}

# fetch URL FILE: HTTPS only, TLS 1.2 or newer, redirects must stay on HTTPS.
fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$2" "$1"
}

detect_os() {
  os_raw="$(uname -s)"
  case "$os_raw" in
    Linux) printf 'linux' ;;
    Darwin) printf 'darwin' ;;
    *) die "unsupported operating system: $os_raw. Linux and macOS only. Releases for other systems: https://github.com/$REPO/releases" ;;
  esac
}

detect_arch() {
  arch_raw="$(uname -m)"
  case "$arch_raw" in
    x86_64 | amd64) printf 'amd64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *) die "unsupported CPU architecture: $arch_raw. amd64 and arm64 only." ;;
  esac
}

# The grep alone would accept "1.2.3<newline>anything", it works line by line. The case
# pattern rejects every character a version does not need, including newline.
valid_version() {
  case "$1" in
    *[!0-9A-Za-z.+_-]*) return 1 ;;
  esac
  printf '%s' "$1" | grep -Eq '^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
}

# Prints the tag (vX.Y.Z) to install. A set but empty UPTIMEIFY_VERSION is an error, not "latest".
resolve_tag() {
  if [ "${UPTIMEIFY_VERSION+set}" = "set" ]; then
    version="$UPTIMEIFY_VERSION"
  else
    # /releases/latest redirects to /releases/tag/<tag>. Prereleases are not "latest".
    final="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
      die "could not look up the latest release. There may be no release yet: https://github.com/$REPO/releases"
    version="${final##*/}"
  fi
  valid_version "$version" || die "not a version (expected X.Y.Z or vX.Y.Z, nothing else)"
  case "$version" in
    v*) printf '%s' "$version" ;;
    *) printf 'v%s' "$version" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "neither sha256sum nor shasum found, cannot verify the download"
  fi
}

# verify_signature TAG DIR ARCHIVE. DIR has checksums.txt and the archive.
# cosign first, then gh. With neither, stop unless UPTIMEIFY_ALLOW_UNSIGNED=1. A verifier that
# ran and said no always stops the install, UPTIMEIFY_ALLOW_UNSIGNED does not change that.
verify_signature() {
  tag="$1"; dir="$2"; archive="$3"
  if command -v cosign >/dev/null 2>&1; then
    fetch "$BASE/$tag/checksums.txt.sigstore.json" "$dir/checksums.txt.sigstore.json" ||
      die "could not download checksums.txt.sigstore.json"
    if ! out="$(cosign verify-blob \
      --certificate-identity "https://github.com/$SIGNER_WORKFLOW@refs/tags/$tag" \
      --certificate-oidc-issuer "$OIDC_ISSUER" \
      --bundle "$dir/checksums.txt.sigstore.json" \
      "$dir/checksums.txt" 2>&1)"; then
      printf '%s\n' "$out" >&2
      die "cosign could not verify the signature of checksums.txt against the release workflow. Nothing was installed. If cosign complains about the bundle, it may be too old: this installer is tested with cosign $COSIGN_TESTED."
    fi
    info "signature of checksums.txt verified with cosign"
  elif command -v gh >/dev/null 2>&1; then
    if ! out="$(gh attestation verify "$dir/$archive" \
      --repo "$REPO" \
      --signer-workflow "$SIGNER_WORKFLOW" \
      --source-ref "refs/tags/$tag" \
      --deny-self-hosted-runners 2>&1)"; then
      printf '%s\n' "$out" >&2
      die "gh could not verify the build attestation of $archive. Nothing was installed. You may need to run gh auth login, or update gh. For the cosign check instead, install cosign $COSIGN_TESTED or newer."
    fi
    info "build attestation of $archive verified with gh"
  elif [ "${UPTIMEIFY_ALLOW_UNSIGNED:-}" = "1" ]; then
    warn "neither cosign nor gh is installed: only the SHA-256 checksum is verified, the signature is not."
    warn "That gives no protection against a replaced release: the checksum comes from the same place as the archive."
  else
    die "neither cosign nor gh is installed, so the signature cannot be verified. Nothing was installed.
Install cosign (https://docs.sigstore.dev/cosign/installation/, tested with $COSIGN_TESTED) or the GitHub CLI (https://cli.github.com/) and run this again.
To continue with the SHA-256 checksum only, set UPTIMEIFY_ALLOW_UNSIGNED=1. The checksum comes from the same place as the archive, so this gives no protection against a replaced release."
  fi
}

main() {
  uid="$(id -u)"
  if [ "$uid" = "0" ] && [ "${UPTIMEIFY_ALLOW_ROOT:-}" != "1" ]; then
    die "refusing to run as root. Run as a normal user, or set UPTIMEIFY_ALLOW_ROOT=1."
  fi

  install_dir="${UPTIMEIFY_INSTALL_DIR:-}"
  if [ -z "$install_dir" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set and UPTIMEIFY_INSTALL_DIR is empty"
    install_dir="$HOME/.local/bin"
  fi
  case "$install_dir" in
    /*) ;;
    *) die "UPTIMEIFY_INSTALL_DIR must be an absolute path: $install_dir" ;;
  esac

  os="$(detect_os)"
  arch="$(detect_arch)"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v tar >/dev/null 2>&1 || die "tar is required"

  tag="$(resolve_tag)"
  version="${tag#v}"
  archive="uptimeify_${version}_${os}_${arch}.tar.gz"

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptimeify-install.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP

  info "installing uptimeify $tag for $os/$arch"
  fetch "$BASE/$tag/$archive" "$TMP_DIR/$archive" || die "could not download $archive"
  fetch "$BASE/$tag/checksums.txt" "$TMP_DIR/checksums.txt" || die "could not download checksums.txt"

  expected="$(awk -v f="$archive" '$2 == f { print $1 }' "$TMP_DIR/checksums.txt")"
  [ -n "$expected" ] || die "$archive is not listed in checksums.txt"
  [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = "1" ] || die "$archive is listed more than once in checksums.txt"
  printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die "malformed checksum for $archive"
  actual="$(sha256_of "$TMP_DIR/$archive")"
  [ "$actual" = "$expected" ] || die "checksum mismatch for $archive (expected $expected, got $actual). Nothing was installed."
  info "checksum of $archive verified"

  verify_signature "$tag" "$TMP_DIR" "$archive"

  mkdir "$TMP_DIR/extract"
  tar -xzf "$TMP_DIR/$archive" -C "$TMP_DIR/extract" uptimeify || die "archive does not contain uptimeify"
  [ -f "$TMP_DIR/extract/uptimeify" ] && [ ! -L "$TMP_DIR/extract/uptimeify" ] || die "uptimeify in the archive is not a regular file"

  mkdir -p "$install_dir" || die "could not create $install_dir"
  # A directory someone else owns (or a symlink to one) lets that user swap or redirect what is
  # written here. -O follows symlinks, so a link into a foreign directory is refused too.
  # shellcheck disable=SC3067 # -O is not POSIX but dash, bash, busybox ash and macOS sh all have it
  [ -d "$install_dir" ] && [ -O "$install_dir" ] ||
    die "$install_dir is not a directory you own. Nothing was installed. Choose one you own with UPTIMEIFY_INSTALL_DIR."
  # Staging file: unpredictable name, created exclusively by mktemp, content written through a
  # plain redirect. No fixed name for another user to pre-create as a symlink.
  STAGED="$(mktemp "$install_dir/.uptimeify.XXXXXX")" || die "could not create a file in $install_dir"
  cat "$TMP_DIR/extract/uptimeify" >"$STAGED"
  chmod 755 "$STAGED"
  mv -f "$STAGED" "$install_dir/uptimeify"
  STAGED=""

  info "installed $install_dir/uptimeify"
  case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) info "$install_dir is not in your PATH. Add it, for example: export PATH=\"$install_dir:\$PATH\"" ;;
  esac
  info "check with: uptimeify --version"
}

main "$@"
