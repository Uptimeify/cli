# Security

Please report vulnerabilities privately through GitHub Security Advisories on this repository
("Report a vulnerability"). Do not open a public issue.

We confirm receipt within two working days. Security fixes ship as their own release.

The CLI never stores a token in a plain file, never accepts a token on the command line and
only sends it to the host in `UPTIMEIFY_API_URL` (default `https://uptimeify.io`).

Anyone who can set `UPTIMEIFY_API_URL` for your shell or CI job receives your token. Treat that
variable like the token itself.
