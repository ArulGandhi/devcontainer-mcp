#!/usr/bin/env bash
# Installs devcontainer-mcp from a GitHub release and sets everything up: podman, the sandbox
# container, login, and (optionally) a public HTTPS link through Tailscale.
#
#   curl -fsSL https://raw.githubusercontent.com/ArulGandhi/devcontainer-mcp/master/install.sh | bash
#
# Run it as a normal user. Anything that needs root (installing podman or Tailscale) is shown
# first and only run through sudo after you say yes. Environment:
#   DCM_YES=1        answer yes to every question (for automation)
#   DCM_TUNNEL=      tailscale | other | none: skip the "how will clients reach this?" question
#   DCM_DRY_RUN=1    print what would be installed and exit; changes nothing
#   DCM_NO_SETUP=1   only install the binary
#   DCM_VERSION      release tag to install (default: latest)
#   DCM_INSTALL_DIR  where the binary goes (default: ~/.local/bin)
#   DCM_BASE_URL     download base URL (default: the GitHub release); file:// works
set -euo pipefail

main() {
  local repo="ArulGandhi/devcontainer-mcp"
  local install_dir="${DCM_INSTALL_DIR:-$HOME/.local/bin}"
  local os arch pm tag base asset want bin config_dir mode

  say() { printf '%s\n' "$*"; }
  die() { printf 'install: %s\n' "$*" >&2; exit 1; }
  dry() { [ "${DCM_DRY_RUN:-}" = 1 ]; }

  tty_ok() { ( exec </dev/tty ) 2>/dev/null; }

  # ask QUESTION: yes with DCM_YES=1 or when the user answers yes on the terminal; no otherwise.
  ask() {
    [ "${DCM_YES:-}" = 1 ] && return 0
    tty_ok || return 1
    local reply
    printf '%s [Y/n] ' "$1" >/dev/tty
    read -r reply </dev/tty || return 1
    case "$reply" in "" | y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
  }

  # run_root CMD...: show the command, then run it with root rights.
  run_root() {
    say "  \$ sudo $*"
    dry && return 0
    if [ "$(id -u)" = 0 ]; then
      "$@"
    elif command -v sudo >/dev/null 2>&1; then
      sudo "$@"
    elif command -v doas >/dev/null 2>&1; then
      doas "$@"
    else
      die "need root to run: $*  (install sudo, or run that command as root yourself)"
    fi
  }

  if [ "$(id -u)" = 0 ] && ! dry; then
    die "run this as a normal user, not root: the sandbox relies on rootless podman. It asks for sudo itself when needed."
  fi
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) die "unsupported OS $(uname -s); build from source: go install github.com/$repo/cmd/devcontainer-mcp@latest" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "unsupported CPU $(uname -m)" ;;
  esac

  pm=
  for candidate in apt-get dnf zypper pacman; do
    if command -v "$candidate" >/dev/null 2>&1; then
      pm="$candidate"
      break
    fi
  done

  install_packages() {
    case "$pm" in
      apt-get) run_root apt-get update && run_root apt-get install -y "$@" ;;
      dnf) run_root dnf install -y "$@" ;;
      zypper) run_root zypper --non-interactive install "$@" ;;
      pacman) run_root pacman -S --needed --noconfirm "$@" ;;
    esac
  }

  ensure_podman() {
    if ! command -v podman >/dev/null 2>&1; then
      say "podman is not installed. The sandbox container runs in it."
      if [ "$os" = darwin ]; then
        die "install podman first (untested on macOS): brew install podman && podman machine init && podman machine start"
      fi
      local pkgs=(podman)
      [ "$pm" = apt-get ] && pkgs+=(uidmap)
      if [ -z "$pm" ]; then
        die "no supported package manager (apt, dnf, zypper, pacman) found; install podman yourself: https://podman.io/docs/installation"
      fi
      if dry; then
        say "would install:"
      elif ! ask "Install ${pkgs[*]} with $pm (uses sudo)?"; then
        die "podman is required. Install it (https://podman.io/docs/installation) and run this again, or answer yes (DCM_YES=1 skips the question)."
      fi
      install_packages "${pkgs[@]}"
    fi
    dry && return 0
    local info
    if ! info="$(podman info 2>&1 >/dev/null)"; then
      die "podman is installed but does not work for your user:
$info
Rootless podman needs subuid/subgid ranges for you (see 'man subuid' and https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md)."
    fi
  }

  ensure_podman

  if dry && [ "${DCM_TUNNEL:-}" != tailscale ]; then
    say "dry run: nothing else to show (set DCM_TUNNEL=tailscale to see the Tailscale steps)"
    exit 0
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
  elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
  else
    die "sha256sum or shasum is required to verify the download"
  fi

  bin="$install_dir/devcontainer-mcp"
  if ! dry; then
    command -v curl >/dev/null 2>&1 || die "curl is required"
    tag="${DCM_VERSION:-}"
    if [ -z "$tag" ] && [ -z "${DCM_BASE_URL:-}" ]; then
      local final
      final="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")" \
        || die "could not look up the latest release of $repo"
      tag="${final##*/}"
      case "$tag" in v[0-9]*) ;; *) die "no release found for $repo (got '$tag'); set DCM_VERSION" ;; esac
    fi
    base="${DCM_BASE_URL:-https://github.com/$repo/releases/download/$tag}"

    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp:-}"' EXIT

    asset="devcontainer-mcp-$os-$arch"
    say "downloading $asset${tag:+ $tag}"
    curl -fsSL "$base/$asset" -o "$tmp/$asset" || die "download failed: $base/$asset"
    curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"
    want="$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")"
    [ -n "$want" ] || die "SHA256SUMS has no entry for $asset"
    [ "$(sha256 "$tmp/$asset")" = "$want" ] || die "checksum mismatch for $asset; refusing to install"

    mkdir -p "$install_dir"
    chmod 0755 "$tmp/$asset"
    mv "$tmp/$asset" "$bin.new"
    mv -f "$bin.new" "$bin"
    say "installed $("$bin" version) to $bin"
    case ":$PATH:" in
      *":$install_dir:"*) ;;
      *) say "note: $install_dir is not on your PATH; add it to your shell profile" ;;
    esac
  fi

  if [ "${DCM_NO_SETUP:-}" = 1 ]; then
    say "skipping setup (DCM_NO_SETUP=1). Next: devcontainer-mcp init && devcontainer-mcp container up"
    exit 0
  fi

  if ! dry; then
    config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/devcontainer-mcp"
    if [ -e "$config_dir/auth.json" ]; then
      say "login already set up in $config_dir; keeping it (devcontainer-mcp init -force replaces it)"
    else
      say
      "$bin" init
      if tty_ok && [ "${DCM_YES:-}" != 1 ]; then
        printf 'Save the password and add the authenticator entry now. Press Enter to continue. ' >/dev/tty
        read -r _ </dev/tty || true
      fi
    fi
    say
    "$bin" container up
  fi

  mode="${DCM_TUNNEL:-}"
  if [ -z "$mode" ]; then
    if tty_ok; then
      {
        say
        say "How will clients (like Gemini) reach this machine over the internet?"
        say "  1) Tailscale Funnel: free, stable https link, no router setup (recommended)"
        say "  2) I will provide a public address or another tunnel"
        say "  3) Decide later"
        printf 'Choose [1]: '
      } >/dev/tty
      read -r choice </dev/tty || choice=3
      case "${choice:-1}" in 1) mode=tailscale ;; 2) mode=other ;; *) mode=none ;; esac
    else
      mode=none
    fi
  fi

  case "$mode" in
    tailscale) setup_tailscale ;;
    other)
      say
      say "Start the server with one of:"
      say "  devcontainer-mcp -tunnel ngrok -tunnel-domain YOUR.ngrok-free.dev   (ngrok installed, free static domain)"
      say "  devcontainer-mcp -public-url https://HOST -listen 0.0.0.0:443 -tls-cert cert.pem -tls-key key.pem"
      ;;
    none)
      say
      say "Setup done. When you are ready: devcontainer-mcp -tunnel tailscale   (see the README for other options)"
      ;;
    *) die "DCM_TUNNEL must be tailscale, other or none" ;;
  esac
}

# setup_tailscale installs and logs in Tailscale if needed, then runs the server on a Funnel link.
setup_tailscale() {
  if [ "$os" = darwin ]; then
    die "install and log in to Tailscale yourself on macOS (https://tailscale.com/download), then run: devcontainer-mcp -tunnel tailscale"
  fi

  if ! command -v tailscale >/dev/null 2>&1; then
    say
    say "Tailscale is not installed. It gives this machine a public https link without opening ports."
    say "The official installer is https://tailscale.com/install.sh (it asks for sudo itself)."
    if dry; then
      say "would run:"
      say "  \$ curl -fsSL https://tailscale.com/install.sh | sh"
    elif ask "Install Tailscale with its official installer?"; then
      curl -fsSL https://tailscale.com/install.sh | sh
      command -v tailscale >/dev/null 2>&1 || die "Tailscale installer finished but 'tailscale' is not on PATH"
    else
      die "Tailscale is needed for this option. Install it (https://tailscale.com/download), then run: devcontainer-mcp -tunnel tailscale"
    fi
  fi

  if dry; then
    say "would then run:"
    run_root tailscale up
    run_root tailscale set "--operator=$(id -un)"
    say "  \$ devcontainer-mcp -tunnel tailscale"
    exit 0
  fi

  local state
  state="$(tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState": *"\([^"]*\)".*/\1/p' | head -1 || true)"
  if [ "$state" != Running ]; then
    say
    say "Log in to Tailscale. A link appears below: open it in a browser and approve this machine."
    run_root tailscale up
    state="$(tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState": *"\([^"]*\)".*/\1/p' | head -1 || true)"
    [ "$state" = Running ] || die "Tailscale is not connected (state '${state:-unknown}'); run 'sudo tailscale up' and try again"
  fi

  if ask "Let your user control Tailscale, so the server can open the public link without sudo? (sudo tailscale set --operator=$(id -un))"; then
    run_root tailscale set "--operator=$(id -un)"
  fi

  say
  if tty_ok; then
    say "Starting the server. If Funnel is not enabled on your Tailscale account yet, a link appears: open it and enable it."
    exec "$bin" -tunnel tailscale
  fi
  say "Setup done. Start the server: devcontainer-mcp -tunnel tailscale"
}

main "$@"
