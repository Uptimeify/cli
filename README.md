# Uptimeify CLI

Command line interface for [Uptimeify](https://uptimeify.io). Each operation of the public API
is a command.

Status: early development, not released. Nothing is published yet.

## Install

There is no release yet. No binary, Homebrew formula, container image or hosted install script
exists today, and the commands below will fail until the first release is published. They show what
the commands will be. The only way to get the CLI now is to build it from source.

### Homebrew (macOS, planned)

    brew install --cask uptimeify/tap/uptimeify

Until the binary is notarized by Apple, macOS may refuse to start it.

### Install script (Linux and macOS, planned)

The script will be served from `https://uptimeify.io/install.sh`. It installs the latest release
(or `UPTIMEIFY_VERSION=X.Y.Z`) into `~/.local/bin` (or `UPTIMEIFY_INSTALL_DIR`), without sudo and not
as root. It downloads over HTTPS only and checks the SHA-256 of the archive against `checksums.txt`.
If `cosign` is installed it also verifies the signature of `checksums.txt`; if not, it says so and
only the checksum is checked, which catches a damaged download but not a replaced release. Set
`UPTIMEIFY_REQUIRE_SIGNATURE=1` to make a missing `cosign` an error.

To read it before running it, instead of piping it into a shell:

    curl --proto '=https' --tlsv1.2 -fsSL -o install.sh https://uptimeify.io/install.sh
    less install.sh
    sh install.sh

The same script is in this repository as [scripts/install.sh](scripts/install.sh).

### Docker (planned)

    docker run --rm -e UPTIMEIFY_TOKEN ghcr.io/uptimeify/cli:X.Y.Z websites list

The image is `linux/amd64` and `linux/arm64`, runs as a non-root user and contains only the binary
and CA certificates.

### Build from source

Go is required.

    make build

The binary is written to `bin/uptimeify`.

## Verifying a release

Once releases exist, each one is signed and attested. The checksum file is signed with cosign
(keyless, GitHub Actions identity), the image is signed the same way, and GitHub build provenance
attestations exist for the archives and the image.

    cosign verify-blob \
      --certificate-identity 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      --bundle checksums.txt.sigstore.json checksums.txt
    sha256sum --check --ignore-missing checksums.txt
    gh attestation verify uptimeify_X.Y.Z_linux_amd64.tar.gz --repo Uptimeify/cli

The full list of checks, including the image, is in [RELEASING.md](RELEASING.md).

## Usage

    export UPTIMEIFY_TOKEN=...        # an API token from Settings, API Tokens
    uptimeify doctor
    uptimeify auth status
    uptimeify websites list
    uptimeify websites get 123 --json
    uptimeify tags create --field name=production
    uptimeify tags update 7 --field name=staging
    uptimeify tags delete 7 --yes

Run `uptimeify --help` or `uptimeify <group> --help` for the full list.

Request bodies:

- `--field key=value` sends a JSON string: `--field name=production`.
- `--field key:=json` sends parsed JSON (numbers, booleans, objects): `--field interval:=60`.
- `--body file.json` reads the whole body from a file, or from standard input with `--body -`.
  The body must be valid JSON and at most 10 MB.

Path arguments such as `<id>` must not contain `/` or `\`, also not in encoded form (`%2F`,
`%5C`). The command exits with code 2 and sends nothing.

Output:

- `--json` prints the response as JSON. Piped, it is byte-exact. On a terminal it is sanitised.
- A binary response (for example a PDF report) is refused on a terminal. Redirect it to a file:
  `uptimeify <command> > report.pdf`.

Delete commands and a named set of other irreversible operations (rotating tokens, MFA reset,
bulk actions, merging incidents, cancelling a maintenance) ask for confirmation on stderr, but
only when stdin is a terminal. Without a terminal, scripts must pass `--yes`; without it the
command exits with code 2 and sends nothing.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `UPTIMEIFY_TOKEN` | API token. Required for every command that calls the API. |
| `UPTIMEIFY_API_URL` | API base URL. Default `https://uptimeify.io`. The token is sent to this host, so anyone who can set this variable for your shell or CI job receives your token. |
| `UPTIMEIFY_ALLOW_INSECURE_LOOPBACK` | Set to `1` to allow plain `http://127.0.0.1`. Nothing else may use http. |
| `UPTIMEIFY_DEBUG` | Set to `1` to print method, URL and status to stderr. Headers are never printed. |

## Handling the token

`export UPTIMEIFY_TOKEN=...` typed on a command line lands in your shell history, and every
program started from that shell inherits the variable. To avoid the history entry, read it
without echo:

    read -rs UPTIMEIFY_TOKEN && export UPTIMEIFY_TOKEN

For CI, create a dedicated token with the smallest permissions the job needs. If a token leaked,
revoke it in the dashboard.

## Security

What is implemented today:

- The token is read from the environment only. There is no token flag.
- The token is sent only to the host in `UPTIMEIFY_API_URL` (default `https://uptimeify.io`).
  Anyone who can set that variable for your shell or CI job receives your token. Treat it like the
  token itself.
- Requests use HTTPS. The one exception is `http://127.0.0.1` with
  `UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1`.
- A redirect to another host is not followed.
- Output printed to a terminal is sanitised.
- Path arguments that are empty, `.`, `..` or contain `/` or `\` (also encoded) are rejected.
- Request bodies are limited to 10 MB.
- No telemetry and no self-update.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | general error |
| 2 | invalid input: unknown command or flag, bad argument, delete without confirmation |
| 3 | not signed in or not allowed |
| 4 | not found |
| 5 | rate limited after retries |

## Development

    make build
    make test
    make generate   # after updating spec/openapi.json
    make check      # tests, go vet, vulnerability scan
    scripts/install_test.sh   # tests of the install script, no network

`scripts/acceptance.sh` runs the built binary against a non-production instance. It creates and
deletes one tag. It refuses any host except `127.0.0.1` and `localhost`, unless
`UPTIMEIFY_ACCEPTANCE_ALLOW_HOST` names the host exactly:

    UPTIMEIFY_API_URL=http://127.0.0.1:3001 UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1 \
      UPTIMEIFY_TOKEN=... scripts/acceptance.sh

## License

MPL-2.0, see [LICENSE](LICENSE).
