# Uptimeify CLI

Command line interface for [Uptimeify](https://uptimeify.io). Each operation of the public API
is a command.

Status: early development, not released. Nothing is published yet.

## Install

Build from source (Go required):

    make build

The binary is written to `bin/uptimeify`.

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

Output:

- `--json` prints the response as JSON. Piped, it is byte-exact. On a terminal it is sanitised.
- A binary response (for example a PDF report) is refused on a terminal. Redirect it to a file:
  `uptimeify <command> > report.pdf`.

Delete commands ask for confirmation on stderr, but only when stdin is a terminal. Without a
terminal and without `--yes` they exit with code 2 and send nothing.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `UPTIMEIFY_TOKEN` | API token. Required for every command that calls the API. |
| `UPTIMEIFY_API_URL` | API base URL. Default `https://uptimeify.io`. |
| `UPTIMEIFY_ALLOW_INSECURE_LOOPBACK` | Set to `1` to allow plain `http://127.0.0.1`. Nothing else may use http. |
| `UPTIMEIFY_DEBUG` | Set to `1` to print method, URL and status to stderr. Headers are never printed. |

## Security

What is implemented today:

- The token is read from the environment only. There is no token flag.
- Requests use HTTPS. The one exception is `http://127.0.0.1` with
  `UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1`.
- A redirect to another host is not followed.
- Output printed to a terminal is sanitised.
- Path arguments that are empty, `.` or `..` are rejected.
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

`scripts/acceptance.sh` runs the built binary against a non-production instance. It creates and
deletes one tag. It refuses any host except `127.0.0.1` and `localhost`, unless
`UPTIMEIFY_ACCEPTANCE_ALLOW_HOST` names the host exactly:

    UPTIMEIFY_API_URL=http://127.0.0.1:3001 UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1 \
      UPTIMEIFY_TOKEN=... scripts/acceptance.sh

## License

MPL-2.0, see [LICENSE](LICENSE).
