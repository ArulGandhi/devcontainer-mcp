#!/usr/bin/env bash
# Installs devcontainer-mcp from a GitHub release, then runs first-time setup.
#
#   curl -fsSL https://raw.githubusercontent.com/ArulGandhi/devcontainer-mcp/master/install.sh | bash
#
# Read it first if you like; it never uses sudo. Environment:
#   DCM_VERSION      release tag to install (default: latest)
#   DCM_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   DCM_NO_SETUP=1   only install the binary; skip init and container up
#   DCM_BASE_URL     download base URL (default: the GitHub release); file:// works
set -euo pipefail

repo="ArulGandhi/devcontainer-mcp"
install_dir="${DCM_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); build from source: go install github.com/$repo/cmd/devcontainer-mcp@latest" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac

if [ "${DCM_NO_SETUP:-}" != 1 ] && ! command -v podman >/dev/null 2>&1; then
  die "podman is required to run the sandbox container: https://podman.io/docs/installation (or set DCM_NO_SETUP=1 to install only the binary)"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required to verify the download"
fi

tag="${DCM_VERSION:-}"
if [ -z "$tag" ] && [ -z "${DCM_BASE_URL:-}" ]; then
  final="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")" \
    || die "could not look up the latest release of $repo"
  tag="${final##*/}"
  case "$tag" in v[0-9]*) ;; *) die "no release found for $repo (got '$tag'); set DCM_VERSION" ;; esac
fi
base="${DCM_BASE_URL:-https://github.com/$repo/releases/download/$tag}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

asset="devcontainer-mcp-$os-$arch"
say "downloading $asset${tag:+ $tag}"
curl -fsSL "$base/$asset" -o "$tmp/$asset" || die "download failed: $base/$asset"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

want="$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no entry for $asset"
[ "$(sha256 "$tmp/$asset")" = "$want" ] || die "checksum mismatch for $asset; refusing to install"

mkdir -p "$install_dir"
chmod 0755 "$tmp/$asset"
mv "$tmp/$asset" "$install_dir/devcontainer-mcp.new"
mv -f "$install_dir/devcontainer-mcp.new" "$install_dir/devcontainer-mcp"
bin="$install_dir/devcontainer-mcp"
say "installed $("$bin" version) to $bin"

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) say "note: $install_dir is not on your PATH; add it to your shell profile" ;;
esac

if [ "${DCM_NO_SETUP:-}" = 1 ]; then
  say "skipping setup (DCM_NO_SETUP=1). Next: devcontainer-mcp init && devcontainer-mcp container up"
  exit 0
fi

config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/devcontainer-mcp"
if [ -e "$config_dir/auth.json" ]; then
  say "login already set up in $config_dir; keeping it (devcontainer-mcp init -force replaces it)"
else
  say
  "$bin" init
fi

say
"$bin" container up

say
say "Setup done. Start the server so clients can reach it:"
if command -v tailscale >/dev/null 2>&1; then
  say "  devcontainer-mcp -tunnel tailscale"
else
  say "  devcontainer-mcp -tunnel tailscale   (needs Tailscale: https://tailscale.com/download)"
  say "  devcontainer-mcp -tunnel ngrok -tunnel-domain YOUR.ngrok-free.dev"
fi
say "or, with your own public address: devcontainer-mcp -public-url https://HOST -listen 0.0.0.0:443 -tls-cert cert.pem -tls-key key.pem"
