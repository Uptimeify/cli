# Security

Please report vulnerabilities privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue.

We confirm receipt within two working days. Security fixes ship as their own release.

The CLI never stores a token in a plain file, never accepts a token on the command line and
only sends it to the host in `UPTIMEIFY_API_URL` (default `https://uptimeify.io`).

Browser sign-ins (`uptimeify auth login`)

- Where tokens live: only in the system keyring (macOS Keychain, Windows Credential Manager,
  Secret Service on Linux), under the service `uptimeify-cli`. Per host there are two entries: the
  account `<origin>` holds the client ID and refresh token, the account `<origin> access` holds the
  short-lived access token. A sign-in is bound to its host and never sent to another one.
- What the keyring does not do: it keeps other users and plain text on the disk away from the
  tokens, not your own processes. On macOS the entries are created through `/usr/bin/security`,
  and any process of the same user can read them without a prompt. Size limit: about 1.9 KB per
  entry on macOS, 2560 bytes on Windows. An access token that does not fit stays in memory for one
  command; a refresh-token record that does not fit makes `auth login` fail and revoke the token.
- Hosts: the browser sign-in works only at `https://uptimeify.io` (and, for acceptance runs with
  `UPTIMEIFY_ALLOW_INSECURE_LOOPBACK=1`, `http://127.0.0.1:<port>`). The list is a constant, not a
  setting. Other hosts use `UPTIMEIFY_TOKEN`.
- What never happens: no token in a plain file, no token or refresh-token flag on the command
  line, no token, authorization code or PKCE verifier in output, logs or `UPTIMEIFY_DEBUG`.
  Without a keyring there is no browser sign-in and no fallback to a file; set `UPTIMEIFY_TOKEN`
  to an API token instead.
- Loopback receiver: during `auth login` the CLI listens on `127.0.0.1` on a random port for at
  most 5 minutes. It accepts one request to `/callback` with the matching `state` (PKCE, S256);
  everything else gets a 404.
- Revoking a device: `uptimeify auth logout` revokes the sign-in on the server and clears the
  keyring. You can also disconnect the device under Connected apps in the dashboard.


Anyone who can set `UPTIMEIFY_API_URL` for your shell or CI job receives your token. Treat that
variable like the token itself.
