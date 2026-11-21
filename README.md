# devcontainer-mcp

An MCP server that gives an LLM one tool, `repl`, to run TypeScript (bun) inside a long-running podman container. It serves MCP over Streamable HTTP (protocol 2025-06-18) and protects it with OAuth 2.1 (authorization code + PKCE, pre-registered client).

## The tool

`repl` takes `code` and an optional `timeout_seconds`. Each call is a fresh bun program with the container's `$HOME` as working directory. Nothing carries over between calls.

- With `timeout_seconds`: the run is killed, with its children, when it exceeds it.
- Without it: a run still going after 30 seconds is moved to the background and the call returns early. Output goes to `~/.repl-jobs/<id>/` (`stdout`, `stderr`, `exit`). Backgrounded runs are capped at `-exec-timeout`.

## Container

    podman build -t devbox:latest devbox/
    podman run -d --name devbox --init --restart=unless-stopped devbox:latest

## Setup

1. Build: `go build -o devcontainer-mcp ./cmd/devcontainer-mcp`
2. Set the login (password read from stdin, TOTP secret printed once for your authenticator app):

       read -rs PW; printf '%s\n' "$PW" | devcontainer-mcp init-auth; unset PW

3. Issue the client ID and secret for clients that need a pre-registered pair (Gemini):

       devcontainer-mcp issue-client

   The pair is written to `~/.config/devcontainer-mcp/client.txt` (mode 600), not printed. Re-running replaces it. Allowed redirect URIs default to `https://vertexaisearch.cloud.google.com/oauth-redirect`; change with `-redirect-uri`.
4. Run (TLS is required off loopback):

       devcontainer-mcp -container devbox -public-url https://HOST \
         -listen 0.0.0.0:443 -tls-cert cert.pem -tls-key key.pem

## Endpoints

- `/mcp`: the MCP endpoint. Requires `Authorization: Bearer <access token>`; otherwise 401 with `resource_metadata` pointing at the protected-resource document.
- `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`: discovery.
- `/authorize`: login page (password + TOTP). PKCE S256 is required.
- `/token`: authorization code and refresh grants. Client authentication with `client_secret_basic` or `client_secret_post`. Access tokens last 1 hour; refresh tokens 30 days and rotate on every use.

## Security model

- Login: one operator password (PBKDF2-SHA256, 600k iterations) plus a TOTP code. Five failed attempts lock login for 15 minutes.
- Tokens are bound to the MCP resource URL (RFC 8707). Only hashes are stored.
- Anyone with a valid token can run code in the container. The container is the blast radius: its mounts and network define what the model can reach.
- Every call is written to the audit log.

## Flags

See `devcontainer-mcp -h`. Notable: `-public-url` (required), `-container` (required), `-auth-file`, `-state-file`, `-exec-timeout`, `-rate-limit`, `-audit-log`.
