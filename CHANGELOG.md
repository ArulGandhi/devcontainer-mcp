# Changelog

## Unreleased

- `repl`: TypeScript with bun in a podman container, home directory as working directory. Runs with `timeout_seconds` are killed when they exceed it; runs without it are backgrounded after 30 seconds.
- OAuth 2.1 with PKCE and a pre-registered client ID and secret. Login is password plus TOTP. Refresh tokens rotate. Dynamic client registration is not offered.
- Static bearer token removed.
- `devbox/Containerfile`: Debian slim with bun 1.4.5 (SHA-256 verified), non-root user.
