# devcontainer-mcp

An MCP server with one tool, `repl`, that runs TypeScript (bun) inside a podman container you control. It speaks MCP over Streamable HTTP and is protected by OAuth 2.1 (PKCE, pre-registered client) with a password plus authenticator code. Go, standard library only. Built for Gemini's custom MCP servers; any MCP client with OAuth works.

## Install

Linux with [rootless podman](https://podman.io/docs/installation) (macOS is untested).

1. Podman:

       sudo apt install podman uidmap   # Debian, Ubuntu
       sudo dnf install podman          # Fedora
       sudo pacman -S podman            # Arch
       sudo zypper install podman       # openSUSE

2. The binary: download it for your system from the Releases page and put it on your `PATH`, or build it with Go 1.24+:

       go install github.com/ArulGandhi/devcontainer-mcp/cmd/devcontainer-mcp@latest

3. Set up the login and the sandbox:

       devcontainer-mcp init            # password, authenticator entry, client ID and secret (shown once)
       devcontainer-mcp container up    # builds and starts the container "devbox"

   `init` prints a generated password and an `otpauth://` URI: save the password and add the URI to your authenticator app. The client ID and secret go to `~/.config/devcontainer-mcp/client.txt` (mode 600).

4. A public HTTPS link, no public IP needed. With [Tailscale](https://tailscale.com/download) (free, the link stays the same across restarts):

       sudo tailscale up                       # prints a login link: approve this machine
       sudo tailscale set --operator=$USER     # once, so the next step needs no sudo
       devcontainer-mcp -tunnel tailscale

   If Funnel is not enabled on your Tailscale account, the server prints the link to enable it and waits up to 5 minutes. When ready it prints the three URLs for your client.

   Without Tailscale: `-tunnel ngrok -tunnel-domain NAME.ngrok-free.dev` (free static domain), or `-public-url https://HOST -listen 0.0.0.0:443 -tls-cert cert.pem -tls-key key.pem` with your own address.

## Connect Gemini

Google Cloud console: Gemini Enterprise, Data stores, Custom MCP Server, OAuth 2.0 (labels may differ). Use the values the server printed:

- MCP server URL: `<link>/mcp`
- Authorization URL: `<link>/authorize`, Token URL: `<link>/token`
- Client ID and secret: from `client.txt`. The redirect URI `https://vertexaisearch.cloud.google.com/oauth-redirect` is allowed by default.

Log in with the password and an authenticator code, then enable the `repl` tool. An organization policy may block custom MCP data stores until an admin allows them. For another client: `devcontainer-mcp init -redirect-uri https://client.example/callback`.

## The tool

`repl` takes `code` and optional `timeout_seconds`. Each call is a fresh bun program with the container's home as working directory.

- With `timeout_seconds` the run is killed, with its children, when it exceeds it.
- Without it, a run still going after 30 seconds moves to the background and the call returns early. Output goes to `~/.repl-jobs/<id>/` and is capped at `-exec-timeout`.

## Container

`container up` builds an embedded Containerfile (Debian slim, bun with a verified checksum, non-root user `dev`, x64 and arm64) and starts it with `--init`, `--restart=unless-stopped`, `--memory 2g`, `--pids-limit 512` and `no-new-privileges`. Flags: `-name`, `-image`, `-memory`, `-pids-limit`, `-rebuild`. To run as root inside it, pass `-user root` to the server: under rootless podman, container root is an unprivileged user on the host.

## Security model

- Anyone with a valid token can run code in the container. The container is the blast radius: do not mount anything you would not hand to the model.
- Login is one password (PBKDF2-SHA256, 600k iterations) plus a TOTP code; five failures lock it for 15 minutes.
- Tokens are bound to the MCP URL and stored only as hashes. Access tokens last 1 hour, refresh tokens 30 days and rotate on use.
- Requests are rate limited, size limited and origin checked. Every call goes to the audit log (`-audit-log`).
- A tunnel makes the login page reachable from the internet: use a long password. Report vulnerabilities as in [SECURITY.md](SECURITY.md).

## Troubleshooting

- `container "devbox" is exited`: `devcontainer-mcp container up`.
- `cannot reach tailscale` / `not connected`: `sudo systemctl enable --now tailscaled`, then `sudo tailscale up`.
- `will not let this user change its serve config`: `sudo tailscale set --operator=$USER`.
- `tailscale already serves something`: the server will not overwrite it; `tailscale funnel reset` or use `-public-url`.
- Client says the token is invalid after the link changed: tokens are bound to the link, so log in again.

## Development

    go vet ./... && go test -race ./...

Tests use a fake podman and fake tunnel programs, so they need no root, network or containers. Against real podman: `DEVCONTAINER_MCP_TEST_CONTAINER=<running container> go test ./internal/podman`. Flags: `devcontainer-mcp -h`.

MIT, see [LICENSE](LICENSE).
