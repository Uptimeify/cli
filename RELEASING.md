# Releasing

This file describes how a release is cut. No release has been made yet. Everything below is
configured but has not run against GitHub, GHCR or the Homebrew tap.

## What a release contains

For a tag `vX.Y.Z` the workflow publishes:

- archives for linux, darwin and windows on amd64 and arm64 (`.tar.gz`, `.zip` on windows), each with
  the binary, `LICENSE` and `README.md`
- `checksums.txt` (SHA-256) and `checksums.txt.sigstore.json`, a keyless Sigstore signature of it
- one SBOM (SPDX JSON, made with syft) per archive
- the container image `ghcr.io/uptimeify/cli:X.Y.Z` (and `latest`, not for prereleases) for linux/amd64
  and linux/arm64, signed with cosign (keyless)
- build provenance attestations (GitHub, SLSA) for the files in `checksums.txt` and for the image
- an updated cask in `Uptimeify/homebrew-tap`

A tag with a suffix such as `v1.0.0-rc.1` becomes a GitHub prerelease, does not move `latest` and
is not pushed to the tap.

## Preconditions

1. `main` is green (CI: `checks`, `release-chain`) and contains everything to ship.
2. `go.mod` states a Go version without known standard library vulnerabilities. The workflow runs
   `govulncheck` and stops if it finds one.
3. The one-time setup below is done.
4. Locally, on the commit you tag: `go test -race ./...` and `goreleaser check`.

## Cutting a release

    git checkout main
    git pull --ff-only origin main
    git tag -s vX.Y.Z -m "vX.Y.Z"      # signed, annotated. Use -a if you have no signing key.
    git push origin vX.Y.Z             # starts the workflow

The tag must be annotated and its commit must be on `main`. Never move or reuse a tag. A bad release
is replaced by a new version.

## What the workflow does (`.github/workflows/release.yml`)

Only tags matching `v*.*.*` start it. Two releases cannot run at the same time.

Job `verify` (read-only token, no secrets):

1. Checks the tag is `vX.Y.Z` (with an optional prerelease suffix), is an annotated tag object,
   points at the commit the run started with, and that commit is reachable from `main`.
2. Runs `go vet`, `go test -race -count=1 ./...` and `govulncheck` (pinned).

Job `release` (waits for `verify`, uses the `release` environment, so a required reviewer can
approve before it starts):

1. Checks out the verified commit without storing credentials, checks the tag did not move.
2. Installs cosign and syft (pinned actions, pinned tool versions), logs in to GHCR with `GITHUB_TOKEN`.
3. Runs GoReleaser (pinned version): builds, archives, checksums, SBOMs, signs `checksums.txt`,
   pushes and signs the image, creates the GitHub release, updates the Homebrew cask. Notarizes the
   macOS binaries only if all five Apple secrets exist.
4. Creates build provenance attestations for `dist/checksums.txt` and `dist/digests.txt`.

Permissions: `verify` has `contents: read`. `release` has `contents: write` (create the release),
`id-token: write` (keyless signing and attestations), `packages: write` (GHCR) and
`attestations: write`.

## One-time setup (the repository owner)

Repository `Uptimeify/cli`:

- Environment `release` (Settings, Environments): add at least one required reviewer, restrict
  deployment to tags `v*`. Store the secrets below in this environment, not as repository secrets.
- Secret `HOMEBREW_TAP_TOKEN`: a fine-grained personal access token, resource owner `Uptimeify`,
  repository access limited to `Uptimeify/homebrew-tap` only, permission Contents: read and write,
  nothing else. Set an expiry and renew it.
- Tag protection (Settings, Rules, Rulesets): target tags `v*`, block deletion and updates, restrict
  creation to the maintainers.
- Branch protection on `main` with required checks `checks` and `release-chain`.
- Actions: default `GITHUB_TOKEN` permission set to read-only.
- Optional, for macOS notarization (all five or none; with any missing, notarization stays off):
  `MACOS_SIGN_P12` (base64 of the Developer ID Application `.p12`), `MACOS_SIGN_PASSWORD`,
  `MACOS_NOTARY_KEY` (base64 of the App Store Connect API key `.p8`), `MACOS_NOTARY_KEY_ID`,
  `MACOS_NOTARY_ISSUER_ID`. An Apple Developer account is required.

Other repositories and registries:

- `Uptimeify/homebrew-tap` exists and has a `main` branch.
- After the first image push, set the GHCR package `cli` to public and link it to the repository
  (a new package starts private).

## Verifying a release

Replace `vX.Y.Z` and `X.Y.Z`. Download `checksums.txt`, `checksums.txt.sigstore.json` and the archive
into one directory.

Signature of the checksum file with cosign:

    cosign verify-blob \
      --certificate-identity 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      --bundle checksums.txt.sigstore.json checksums.txt

Only after that succeeds, check the archive against the file:

    sha256sum --check --ignore-missing checksums.txt      # macOS: shasum -a 256 --check --ignore-missing checksums.txt

Build provenance with the GitHub CLI:

    gh attestation verify uptimeify_X.Y.Z_linux_amd64.tar.gz \
      --repo Uptimeify/cli --signer-workflow Uptimeify/cli/.github/workflows/release.yml

Image:

    cosign verify \
      --certificate-identity 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      ghcr.io/uptimeify/cli:X.Y.Z
    gh attestation verify oci://ghcr.io/uptimeify/cli:X.Y.Z \
      --repo Uptimeify/cli --signer-workflow Uptimeify/cli/.github/workflows/release.yml

## Yanking a bad release

Do not delete the tag and do not re-tag. Users and tools may already hold the checksums.

1. GitHub release: edit it, mark it as a prerelease, put a warning at the top of the notes. If it is
   a security problem, publish an advisory. To stop the install script from picking it, make the
   previous release the latest: `gh release edit vPREVIOUS --latest`.
2. Homebrew: in `Uptimeify/homebrew-tap`, revert the commit that updated `Casks/uptimeify.rb`.
3. Image: point `latest` back at the previous version
   (`docker buildx imagetools create -t ghcr.io/uptimeify/cli:latest ghcr.io/uptimeify/cli:PREVIOUS`) and
   delete the bad version tag in the GHCR package settings.
4. Ship a fixed version under a new tag. Security fixes go out as their own release.

## Local dry run

    goreleaser check
    goreleaser release --snapshot --clean --skip=publish,sign,notarize

This builds everything into `dist/` (including the images, which Docker keeps locally) and pushes
nothing. It needs Docker and syft. The CI job `release-chain` does the same.
