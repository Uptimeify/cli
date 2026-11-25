#!/bin/sh
# Installer for the Uptimeify CLI (Linux and macOS). Intended to be served from
# https://uptimeify.io/install.sh. Read it before you run it: it is short.
#
# What it does:
#   1. picks the release (UPTIMEIFY_VERSION, default: the latest release)
#   2. downloads the archive and checksums.txt over HTTPS
#   3. verifies the signature of checksums.txt with cosign, if cosign is installed
#   4. verifies the SHA-256 of the archive against checksums.txt
#   5. installs the binary into ${UPTIMEIFY_INSTALL_DIR:-$HOME/.local/bin}, without sudo
#
# Environment:
#   UPTIMEIFY_VERSION            X.Y.Z or vX.Y.Z. Default: latest release.
#   UPTIMEIFY_INSTALL_DIR        absolute path. Default: $HOME/.local/bin.
#   UPTIMEIFY_REQUIRE_SIGNATURE  1 = abort if cosign is not installed.
#   UPTIMEIFY_ALLOW_ROOT         1 = allow running as root.
#
# Everything lives in main(), which is called on the last line. A download that is cut off
# before that line defines functions and runs nothing.
set -eu

REPO="Uptimeify/cli"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

TMP_DIR=""
STAGED=""

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "$STAGED" ]; then rm -f "$STAGED"; fi
  if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
}

# Test hooks. They only exist when UPTIMEIFY_TEST=1, so they cannot redirect a normal run.
testing() { [ "${UPTIMEIFY_TEST:-}" = "1" ]; }

# fetch URL FILE: HTTPS only, TLS 1.2 or newer, redirects must stay on HTTPS.
# In test mode a file:// URL is allowed instead.
fetch() {
  if testing && [ -n "${UPTIMEIFY_BASE_URL:-}" ]; then
    curl --proto '=file' -fsSL -o "$2" "$1"
  else
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$2" "$1"
  fi
}

detect_os() {
  os_raw="$(uname -s)"
  if testing && [ -n "${UPTIMEIFY_UNAME_S:-}" ]; then os_raw="$UPTIMEIFY_UNAME_S"; fi
  case "$os_raw" in
    Linux) printf 'linux' ;;
    Darwin) printf 'darwin' ;;
    *) die "unsupported operating system: $os_raw. Linux and macOS only. Releases for other systems: https://github.com/$REPO/releases" ;;
  esac
}

detect_arch() {
  arch_raw="$(uname -m)"
  if testing && [ -n "${UPTIMEIFY_UNAME_M:-}" ]; then arch_raw="$UPTIMEIFY_UNAME_M"; fi
  case "$arch_raw" in
    x86_64 | amd64) printf 'amd64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *) die "unsupported CPU architecture: $arch_raw. amd64 and arm64 only." ;;
  esac
}

valid_version() {
  printf '%s' "$1" | grep -Eq '^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
}

# Prints the tag (vX.Y.Z) to install.
resolve_tag() {
  if [ -n "${UPTIMEIFY_VERSION:-}" ]; then
    version="$UPTIMEIFY_VERSION"
  else
    if testing && [ -n "${UPTIMEIFY_BASE_URL:-}" ]; then die "UPTIMEIFY_VERSION is required in test mode"; fi
    # /releases/latest redirects to /releases/tag/<tag>. Prereleases are not "latest".
    final="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" ||
      die "could not look up the latest release. There may be no release yet: https://github.com/$REPO/releases"
    version="${final##*/}"
  fi
  valid_version "$version" || die "not a version: $version (expected X.Y.Z or vX.Y.Z)"
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

verify_signature() {
  # $1 = tag, $2 = directory with checksums.txt and checksums.txt.sigstore.json
  cosign_cmd="cosign"
  if testing && [ -n "${UPTIMEIFY_COSIGN:-}" ]; then cosign_cmd="$UPTIMEIFY_COSIGN"; fi
  if ! command -v "$cosign_cmd" >/dev/null 2>&1; then
    if [ "${UPTIMEIFY_REQUIRE_SIGNATURE:-}" = "1" ]; then
      die "cosign is not installed and UPTIMEIFY_REQUIRE_SIGNATURE=1"
    fi
    warn "cosign is not installed: only the SHA-256 checksum is verified, the signature is not."
    warn "A checksum from the same server only catches a damaged download, not a replaced release."
    warn "To verify the signature yourself, install cosign (https://docs.sigstore.dev/cosign/) and run:"
    warn "  cosign verify-blob --certificate-identity 'https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$1' \\"
    warn "    --certificate-oidc-issuer '$OIDC_ISSUER' \\"
    warn "    --bundle checksums.txt.sigstore.json checksums.txt"
    return 0
  fi
  fetch "$BASE/$1/checksums.txt.sigstore.json" "$2/checksums.txt.sigstore.json" ||
    die "could not download checksums.txt.sigstore.json"
  "$cosign_cmd" verify-blob \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$1" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --bundle "$2/checksums.txt.sigstore.json" \
    "$2/checksums.txt" >/dev/null 2>&1 ||
    die "signature of checksums.txt does not verify against the expected release workflow. Nothing was installed."
  info "signature of checksums.txt verified"
}

main() {
  uid="$(id -u)"
  if testing && [ -n "${UPTIMEIFY_TEST_UID:-}" ]; then uid="$UPTIMEIFY_TEST_UID"; fi
  if [ "$uid" = "0" ] && [ "${UPTIMEIFY_ALLOW_ROOT:-}" != "1" ]; then
    die "refusing to run as root. Run as a normal user, or set UPTIMEIFY_ALLOW_ROOT=1."
  fi

  if [ -n "${UPTIMEIFY_BASE_URL:-}" ] && ! testing; then
    die "UPTIMEIFY_BASE_URL is only honoured with UPTIMEIFY_TEST=1"
  fi
  BASE="https://github.com/$REPO/releases/download"
  if testing && [ -n "${UPTIMEIFY_BASE_URL:-}" ]; then BASE="$UPTIMEIFY_BASE_URL"; fi

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

  verify_signature "$tag" "$TMP_DIR"

  expected="$(awk -v f="$archive" '$2 == f { print $1 }' "$TMP_DIR/checksums.txt")"
  [ -n "$expected" ] || die "$archive is not listed in checksums.txt"
  [ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = "1" ] || die "$archive is listed more than once in checksums.txt"
  printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die "malformed checksum for $archive"
  actual="$(sha256_of "$TMP_DIR/$archive")"
  [ "$actual" = "$expected" ] || die "checksum mismatch for $archive (expected $expected, got $actual). Nothing was installed."
  info "checksum of $archive verified"

  mkdir "$TMP_DIR/extract"
  tar -xzf "$TMP_DIR/$archive" -C "$TMP_DIR/extract" uptimeify || die "archive does not contain uptimeify"
  [ -f "$TMP_DIR/extract/uptimeify" ] && [ ! -L "$TMP_DIR/extract/uptimeify" ] || die "uptimeify in the archive is not a regular file"

  mkdir -p "$install_dir"
  STAGED="$install_dir/.uptimeify.$$.new"
  cp "$TMP_DIR/extract/uptimeify" "$STAGED"
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
