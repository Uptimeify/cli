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
as root. It downloads over HTTPS only, checks the SHA-256 of the archive against `checksums.txt`, and
then verifies the signature: with `cosign` if it is installed (signature of `checksums.txt`), else with
the GitHub CLI (`gh attestation verify` of the archive). If neither is installed it stops and says how
to install one. `UPTIMEIFY_ALLOW_UNSIGNED=1` continues with the checksum only, which catches a damaged
download but gives no protection against a replaced release. It never skips a verification that
failed. The install directory must be one you own.

To read it before running it, instead of piping it into a shell:

    curl --proto '=https' --tlsv1.2 -fsSL -o install.sh https://uptimeify.io/install.sh
    less install.sh
    sh install.sh

The same script is in this repository as [scripts/install.sh](scripts/install.sh).

### Docker (planned)

    docker run --rm -e UPTIMEIFY_TOKEN ghcr.io/uptimeify/cli:X.Y.Z websites list

The image is `linux/amd64` and `linux/arm64`, runs as a non-root user and contains only the binary
and CA certificates. To run exactly the image you verified, run it by digest (see below):
`docker run --rm -e UPTIMEIFY_TOKEN ghcr.io/uptimeify/cli@sha256:<digest> websites list`.

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
    gh attestation verify uptimeify_X.Y.Z_linux_amd64.tar.gz --repo Uptimeify/cli \
      --signer-workflow Uptimeify/cli/.github/workflows/release.yml \
      --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners

Image: resolve the digest once, verify that digest, and run that digest. A tag can move, a digest
cannot.

    digest="$(docker buildx imagetools inspect ghcr.io/uptimeify/cli:X.Y.Z --format '{{.Manifest.Digest}}')"
    cosign verify \
      --certificate-identity 'https://github.com/Uptimeify/cli/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      "ghcr.io/uptimeify/cli@$digest"
    docker run --rm "ghcr.io/uptimeify/cli@$digest" --version

The full list of checks, including the image, is in [RELEASING.md](RELEASING.md).

## Usage

    uptimeify auth login              # signs in with the browser, see "Signing in"
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

## Signing in

    uptimeify auth login

`auth login` opens your browser on the Uptimeify consent page and prints the same address on
stderr. After you agree, the browser returns to the CLI on `http://127.0.0.1` (a random port that
only this computer can reach), and the CLI keeps the sign-in in the system keyring: the macOS
Keychain, the Windows Credential Manager, or the Secret Service on Linux (for example GNOME
Keyring or KWallet). With `--no-browser` the CLI opens nothing and only prints the address. Open it
in a browser on the same computer.

Over SSH the browser runs on another machine and cannot reach `127.0.0.1` of the machine with the
CLI. Forward the port shown in the address (for example with a second session
`ssh -L <port>:127.0.0.1:<port> <host>`), or use an API token.

By default the CLI asks for read access only: the `:read` scopes of every area except users,
billing, audit and status page subscribers. `--write` adds the `:write` scopes of the same areas.
`--scope <scope>` adds single scopes and can be repeated. It also covers the separate ones
(`api:users:read`, `api:users:write`, `api:billing:read`, `api:billing:write`, `api:audit:read`,
`api:statuspage-subscribers:read`). An unknown scope exits with code 2 and sends nothing:

    uptimeify auth login --write
    uptimeify auth login --scope api:billing:write

`--device-name <name>` sets the name under which the device appears in Connected apps (1 to 64
characters, no control characters). The default is `uptimeify CLI on <hostname>`.

The consent page can grant fewer scopes than requested. `uptimeify auth login --help` lists every
scope. When a command needs a scope that the sign-in lacks, the error says which one and how to add
it.

How long a sign-in lasts:

- The access token is valid for 15 minutes. The CLI renews it on its own.
- A sign-in that is not used for 7 days ends.
- Every sign-in ends at the latest 30 days after `auth login`. Then run `auth login` again.
- `uptimeify auth status` shows the device, user ID, organisation, scopes and both limits.

`uptimeify auth logout` revokes the sign-in on the server and removes it from the keyring. You can
also disconnect the device in the dashboard under Connected apps; the CLI notices on its next
request. The device is listed there as `uptimeify CLI on <hostname>`.

Each API host has its own sign-in. With another `UPTIMEIFY_API_URL`, run `auth login` again. A
sign-in is never sent to another host.

`UPTIMEIFY_TOKEN` takes precedence. While it is set, the CLI uses the API token and neither reads
nor writes the keyring; `auth status` says so, and `auth login` stops and asks you to unset it.
Servers, CI jobs and containers usually have no keyring. There `auth login` fails with an error, and
`UPTIMEIFY_TOKEN` is the only way to sign in. The CLI never falls back to a file.

The browser sign-in works only at the main host, `https://uptimeify.io`. The list is fixed in the
program: no flag and no environment variable adds a host, because an injected `UPTIMEIFY_API_URL`
would otherwise open an attacker's page as "Uptimeify login". Any other host makes `auth login` stop
with exit code 2; there, and on customer domains and white-label hosts, keep using
`UPTIMEIFY_TOKEN`. The one exception is `http://127.0.0.1:<port>` together with
`UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1`, which is for acceptance runs. `auth login` names the host in
the first line on stderr before it opens anything. `auth status` and `UPTIMEIFY_TOKEN` work at every
host as before.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `UPTIMEIFY_TOKEN` | API token for CI and servers. Takes precedence over the browser sign-in. |
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
- A browser sign-in (client ID, refresh token, access token) is kept only in the system keyring:
  the macOS Keychain, the Windows Credential Manager, or the Secret Service on Linux. It is never
  written to a file. Without a keyring there is no browser sign-in, only `UPTIMEIFY_TOKEN`.
- The keyring protects the sign-in from other users of the computer and from plain text on disk. It
  does not protect it from your own processes: on macOS the entries are created through
  `/usr/bin/security`, and any process running as the same user can read them without a prompt.
  Treat a computer where untrusted programs run as your user as unsafe for a browser sign-in.
- A keyring entry has a size limit (about 1.9 KB on macOS, 2560 bytes on Windows). The access token
  is a separate entry; if a long one does not fit, the CLI keeps it in memory for that command,
  prints one note on stderr and renews it again with the next command. The record with the refresh
  token must fit: if it does not, `auth login` fails with a clear message and ends the refresh token
  it was given on the server.
- No secret appears in the process list. There is no token flag. On macOS the keyring entry is
  passed to `/usr/bin/security` on standard input, not as an argument. The browser is started
  without a shell and receives only the sign-in address, which is useless without the PKCE
  verifier that stays in the memory of the CLI.
- The browser's answer is accepted only on `127.0.0.1`, only as one request to `/callback` with the
  matching `state`, and only for 5 minutes. Every other request gets a 404.
- Sign-in requests (device registration, token, revocation) never follow a redirect.
- Refresh tokens are single use, and the server ends the whole sign-in when an old one comes back.
  A lock file per host in the user cache directory makes sure only one CLI process renews at a
  time. The lock file is empty. After a network failure in the middle of a renewal the CLI does not
  retry with the old refresh token; it removes the sign-in and asks you to sign in again.
- On Linux the keyring library opens its Secret Service session with the `plain` algorithm, so the
  secret crosses your own D-Bus session bus (a local socket) unencrypted.
- The device name contains the hostname of this computer. The admins of your organisation see it
  under Connected apps and in the audit log.

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
