# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Contact the repository
owner privately with a minimal reproduction, affected version, and impact. Do
not include access tokens, telemetry, private keys, or customer data.

## Supported deployment

Use HTTPS for every remote agent-to-server connection. Plain HTTP is supported
only for loopback development. Keep the server API token secret; prefer distinct
per-host tokens where host attribution matters. Bind the server only to networks
that need it and keep the host firewall restrictive.

## Release integrity

Release archives include SHA-256 checksums. They detect download corruption but
are not a signature or an independent provenance guarantee. Signed release
artifacts are planned; until then, pin the release version and checksum for
production installs.
