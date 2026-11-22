# devcontainer-mcp

An MCP server that gives an LLM one tool, `repl`, which runs TypeScript (bun) inside a long-running podman container. It speaks MCP over Streamable HTTP and protects it with OAuth 2.1 (authorization code + PKCE, pre-registered client, password + TOTP login). Written in Go, standard library only.

Made for connecting Gemini (Gemini Enterprise custom MCP server) to a sandbox you control. Any MCP client that supports OAuth 2.1 with a pre-registered client works.

## Quickstart

You need [podman](https://podman.io/docs/installation) (rootless).

    curl -fsSL https://raw.githubusercontent.com/ArulGandhi/devcontainer-mcp/master/install.sh | bash

This downloads the release binary for your OS and CPU, checks its SHA-256, installs it to `~/.local/bin`, then runs `init` and `container up` for you (no sudo). [Read the script](install.sh) first if you like. `DCM_NO_SETUP=1` installs only the binary; `DCM_VERSION` and `DCM_INSTALL_DIR` pick the release and location. Or build it yourself with Go 1.24+: `go install github.com/ArulGandhi/devcontainer-mcp/cmd/devcontainer-mcp@latest`.

Then, if you installed only the binary, run the steps by hand:

    devcontainer-mcp init               # login + authenticator secret + client ID/secret
    devcontainer-mcp container up       # builds and starts the sandbox container "devbox"
    devcontainer-mcp -tunnel tailscale  # serves it on a public HTTPS address

`init` prints a generated password and an `otpauth://` URI once. Add the URI to your authenticator app and keep the password. The client ID and secret are written to `~/.config/devcontainer-mcp/client.txt` (mode 600).

The last command prints the public URL (for Tailscale: `https://<machine>.<tailnet>.ts.net`). It stays the same across restarts, so you only configure your client once.

## Reaching it from the internet

The server listens on `127.0.0.1:8787` and the client has to reach it over HTTPS. Pick one:

| Option | URL | Needs |
|---|---|---|
| `-tunnel tailscale` | stable `*.ts.net` | free Tailscale account, `tailscale` installed and logged in, Funnel enabled for your tailnet ([docs](https://tailscale.com/docs/features/tailscale-funnel)), and `sudo tailscale set --operator=$USER` run once so you can start Funnel without sudo |
| `-tunnel ngrok -tunnel-domain NAME.ngrok-free.dev` | stable, the free static domain of your ngrok account | free ngrok account, `ngrok` installed with your authtoken |
| `-public-url https://HOST` | yours | a public IP or your own reverse proxy; add `-tls-cert`/`-tls-key` to terminate TLS here |

With a tunnel the server refuses to listen on a non-loopback address. Tailscale is checked at startup (Funnel must show as on); with ngrok the server also logs whether the public URL answers. The tunnel is taken down when the server stops.

## Connecting Gemini

In the Google Cloud console: Gemini Enterprise, Data stores, create a data store, choose Custom MCP Server, Add MCP server, OAuth 2.0. Labels may differ from this list; use these values.

- MCP server URL: `<public URL>/mcp`
- Authorization URL: `<public URL>/authorize`
- Token URL: `<public URL>/token`
- Client ID and secret: from `client.txt`
- Redirect URI (already allowed by default): `https://vertexaisearch.cloud.google.com/oauth-redirect`

Then click Login, sign in with the password and a TOTP code, and enable the `repl` tool. An organization policy may block custom MCP data stores until an admin overrides it.

For another client, pass its redirect URI: `devcontainer-mcp init -redirect-uri https://client.example/callback` (or run `issue-client -redirect-uri ...` later).

## The tool

`repl` takes `code` and an optional `timeout_seconds`. Each call is a fresh bun program with the container's `$HOME` as working directory. Nothing carries over between calls.

- With `timeout_seconds`: the run is killed, with its children, when it exceeds it.
- Without it: a run still going after 30 seconds is moved to the background and the call returns early. Output goes to `~/.repl-jobs/<id>/` (`stdout`, `stderr`, `exit`). Backgrounded runs are capped at `-exec-timeout`.

## Container

`container up` builds an embedded Containerfile (Debian slim, bun with a verified checksum, non-root user `dev`, x64 and arm64) and starts it with `--init`, `--restart=unless-stopped`, `--memory 2g`, `--pids-limit 512` and `no-new-privileges`. Flags: `-name`, `-image`, `-memory`, `-pids-limit`, `-rebuild`. Running again keeps a running container and starts a stopped one.

To run as root inside the container, pass `-user root` to the server. With rootless podman, container root is an unprivileged user on the host.

## Endpoints

- `/mcp`: the MCP endpoint. Requires `Authorization: Bearer <access token>`; otherwise 401 with `resource_metadata` pointing at the protected-resource document.
- `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`: discovery.
- `/authorize`: login page (password + TOTP). PKCE S256 is required.
- `/token`: authorization code and refresh grants. Client authentication with `client_secret_basic` or `client_secret_post`. Access tokens last 1 hour; refresh tokens 30 days and rotate on every use.

## Security model

- Anyone with a valid token can run code in the container. The container is the blast radius: its mounts, network and limits define what the model can reach. Do not mount anything you would not hand to the model.
- Login: one operator password (PBKDF2-SHA256, 600k iterations) plus a TOTP code. Five failed attempts lock login for 15 minutes.
- Tokens are bound to the MCP resource URL (RFC 8707). Only hashes are stored.
- Requests are rate limited, size limited and origin checked. Every call is written to the audit log (`-audit-log`, default stderr).
- Dynamic client registration is not offered. Re-running `issue-client` invalidates the old client secret.
- A tunnel makes the login page reachable from the whole internet. Use a long password.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Troubleshooting

- `container "devbox" is exited, not running`: `devcontainer-mcp container up`.
- `tailscale is not connected`: run `tailscale up`.
- `Funnel is not enabled on your tailnet`: open the link in the message, enable it, start again.
- `tailscale will not let this user change its serve config`: run `sudo tailscale set --operator=$USER` once.
- `tailscale already serves something`: the connector will not overwrite it. Remove it with `tailscale funnel reset` or expose the connector yourself and use `-public-url`.
- ngrok: log says the public URL is not reachable: the tunnel is up but not forwarding; check `ngrok`'s own output.
- Client says the token is invalid after changing the public URL: tokens are bound to the URL, so log in again in the client.

## Flags

See `devcontainer-mcp -h`. Subcommands: `init`, `container up`, `issue-client`, `init-auth`, `version`. Notable flags: `-tunnel`, `-tunnel-domain`, `-public-url`, `-container`, `-user`, `-auth-file`, `-state-file`, `-exec-timeout`, `-rate-limit`, `-audit-log`.

## Development

    go vet ./... && go test -race ./...

Tests use a fake podman and fake tunnel programs; no root, network or containers needed. To also test against real podman: `DEVCONTAINER_MCP_TEST_CONTAINER=<running container> go test ./internal/podman`.

## License

MIT, see [LICENSE](LICENSE).
