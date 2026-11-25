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
  and linux/arm64, signed with cosign (keyless). The image has no BuildKit SBOM attestation: that
  would pull `docker/buildkit-syft-scanner` by tag, and GoReleaser cannot pin it by digest (see
  Known limits). The archive SBOMs from syft are the SBOMs of this release.
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
2. Sets up Go with `cache: false`: a tag run never restores a build cache that a pull request or
   branch run saved, so a poisoned cache cannot reach a signed release.
3. Installs cosign and syft (pinned actions, pinned tool versions), sets up buildx with the BuildKit
   image pinned by digest (`moby/buildkit:v0.35.1@sha256:baf6138e...`), logs in to GHCR with `GITHUB_TOKEN`.
4. Installs GoReleaser with `go install github.com/goreleaser/goreleaser/v2@v2.20.3` in the runner
   temp directory (not in the checkout), with `GOFLAGS` empty and no `GONOSUMDB`/`GONOSUMCHECK`/
   `GOPRIVATE` set, so the Go checksum database (sum.golang.org) verifies the module and the
   install fails closed. `goreleaser-action` is not used: it only warns when its own checksum or
   bundle download fails, and verifies with cosign only when cosign happens to be on PATH.
5. Runs GoReleaser by absolute path: builds, archives, checksums, SBOMs, signs `checksums.txt`,
   pushes and signs the image, creates the GitHub release, updates the Homebrew cask. Notarizes the
   macOS binaries only if all five Apple secrets exist.
6. Creates build provenance attestations for `dist/checksums.txt` and `dist/digests.txt`.

Which tools see the secrets: the GoReleaser step gets `GITHUB_TOKEN`, `HOMEBREW_TAP_TOKEN` and the
optional Apple secrets in its environment. GoReleaser starts `cosign`, `syft` and `docker` as
subprocesses, and subprocesses inherit that whole environment, so cosign sees `HOMEBREW_TAP_TOKEN`
too. Every tool that runs in that step is therefore trusted with all of them. No other step has the
secrets.

Permissions: `verify` has `contents: read`. `release` has `contents: write` (create the release),
`id-token: write` (keyless signing and attestations), `packages: write` (GHCR) and
`attestations: write`.

## Reviewer step (every release)

Before approving the `release` environment, check that the run's commit is on `main` and that the
tag was created by a maintainer (tag object, tagger, signature if there is one). The workflow
checks the first part itself, but the approval is the last human gate before secrets are used.

## One-time setup (the repository owner)

Do these in this order. Each step assumes the earlier ones.

1. Repository Settings, Actions, General: workflow permissions read-only; Actions may not create or
   approve pull requests; approval required for workflows from all outside contributors; allow only
   selected actions, with "require actions to be pinned to a full-length commit SHA" on.
2. Settings, Rules, Rulesets: a tag ruleset for `v*` that restricts creation, update and deletion,
   with the owner as the only bypass actor.
3. Settings, General: immutable releases on.
4. Repository `Uptimeify/homebrew-tap` with a `main` branch, and a fine-grained personal access token
   for that repository only: resource owner `Uptimeify`, Contents read and write, nothing else, with an
   expiry that you renew.
5. Environment `release` (Settings, Environments): required reviewers, "allow administrators to
   bypass" off, deployment branches and tags limited to tags `v*`. Store the secrets in this
   environment, not as repository secrets: `HOMEBREW_TAP_TOKEN` and, optional for macOS
   notarization (all five or none; with any missing, notarization stays off), `MACOS_SIGN_P12`
   (base64 of the Developer ID Application `.p12`), `MACOS_SIGN_PASSWORD`, `MACOS_NOTARY_KEY`
   (base64 of the App Store Connect API key `.p8`), `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER_ID`.
   An Apple Developer account is required for those.
6. Let the CI job `release-chain` run once on a pull request, then add it as a required check next to
   `checks` (branch protection or ruleset for `main`).
7. First tag as a prerelease, `v0.1.0-rc.1`. Run every command under "Verifying a release" against it.
   After the first image push, set the GHCR package `cli` to public and link it to the repository (a
   new package starts private). Only then cut the stable tag.

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

Build provenance with the GitHub CLI. Always pin the signer workflow, the tag and runner type:

    gh attestation verify uptimeify_X.Y.Z_linux_amd64.tar.gz \
      --repo Uptimeify/cli \
      --signer-workflow Uptimeify/cli/.github/workflows/release.yml \
      --source-ref refs/tags/vX.Y.Z \
      --deny-self-hosted-runners

Image. Resolve the digest once, verify that digest, and use that digest from then on (a tag can be
moved, a digest cannot):

    digest="$(docker buildx imagetools inspect ghcr.io/uptimeify/cli:X.Y.Z --format '{{.Manifest.Digest}}')"
    cosign verify \
      --certificate-identity 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      "ghcr.io/uptimeify/cli@$digest"
    gh attestation verify "oci://ghcr.io/uptimeify/cli@$digest" \
      --repo Uptimeify/cli \
      --signer-workflow Uptimeify/cli/.github/workflows/release.yml \
      --source-ref refs/tags/vX.Y.Z \
      --deny-self-hosted-runners
    docker run --rm "ghcr.io/uptimeify/cli@$digest" --version

The install script does the checksum check and then one signature check: `cosign verify-blob` if
cosign is installed, else `gh attestation verify` on the archive, else it stops (override with
`UPTIMEIFY_ALLOW_UNSIGNED=1`, checksum only). cosign `v3.1.6` is the version the release is signed
and tested with; the install script prints that when a check fails.

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

    (cd "$(mktemp -d)" && GOFLAGS= go install github.com/goreleaser/goreleaser/v2@v2.20.3)
    "$(go env GOPATH)/bin/goreleaser" check
    "$(go env GOPATH)/bin/goreleaser" release --snapshot --clean --skip=publish,sign,notarize

This builds everything into `dist/` (including the images, which Docker keeps locally) and pushes
nothing. It needs Docker and syft. The CI job `release-chain` does the same.

## Known limits

- Not verified in CI: the signature of the release tag (the runner has no keys; the verify job only
  reports whether a signature block exists), so the reviewer step above matters.
- `anchore/sbom-action/download-syft` runs syft's `install.sh` pinned to the tag. That script checks
  the SHA-256 of the syft archive against the release's `checksums.txt` only. Its optional
  signature check (`-v`) is not switched on by the action, so syft is protected by a checksum from
  the same release page, not by a signature.
- `cosign-installer` and `setup-buildx-action` download cosign and the buildx binary at run time;
  how they verify those downloads was not examined. The action versions themselves are pinned by SHA.
- No BuildKit SBOM attestation on the image (see "What a release contains"). GoReleaser's `flags`
  reach the `--load` builds as well, and `dockers_v2.sbom` adds `--attest=type=sbom` without a
  generator option, so the scanner image (`docker/buildkit-syft-scanner`) cannot be pinned by
  digest through GoReleaser.
- Go modules and the GoReleaser binary are verified through the Go checksum database. The base image
  of the Dockerfile and the shellcheck image are pinned by digest and need a manual or bot update.

