# Changelog

## Unreleased

- With `-tunnel tailscale` the server shows the link that enables Funnel and waits up to 5 minutes for it, then prints the URLs to enter in the client.
- `-tunnel tailscale|ngrok`: public HTTPS address without a public IP; the URL is stable across restarts. Tailscale: the server refuses to overwrite an existing serve config and confirms Funnel is on; errors name the fix. ngrok: the server logs whether the public URL answers.
- `init`: one command for the login file, authenticator secret and client credentials. Generates the password unless `-password-stdin` is given.
- `container up`: builds the embedded Containerfile (x64 and arm64; the architecture is passed to the build explicitly because Debian 12's podman does not set it) and runs the container with memory, process and no-new-privileges limits.
- `-container` defaults to `devbox`. `-public-url` is optional with `-tunnel`.
- `version` subcommand.
- Fixed: after a timeout, cleanup ran as the container's default user, so with `-user root` timed-out processes kept running.
- Module renamed to `github.com/ArulGandhi/devcontainer-mcp`. Minimum Go is 1.24.
- MIT license, CI, release workflow, SECURITY.md, CONTRIBUTING.md.
- `repl`: TypeScript with bun in a podman container, home directory as working directory. Runs with `timeout_seconds` are killed when they exceed it; runs without it are backgrounded after 30 seconds.
- OAuth 2.1 with PKCE and a pre-registered client ID and secret. Login is password plus TOTP. Refresh tokens rotate. Dynamic client registration is not offered.
- Static bearer token removed.
