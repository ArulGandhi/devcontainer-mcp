package podmantest

import (
	"os"
	"path/filepath"
	"testing"
)

const script = `#!/bin/sh
echo "$*" >> "$FAKE_PODMAN_LOG"
case "$*" in
  "container inspect"*) printf '%s\n' "$FAKE_PODMAN_STATE"; exit 0 ;;
esac
shift
while :; do
  case "$1" in
    --interactive|-i) shift ;;
    --user) shift 2 ;;
    --env) export "$2"; shift 2 ;;
    --workdir) cd "$2" || exit 125; shift 2 ;;
    *) break ;;
  esac
done
shift
exec "$@"
`

type Fake struct {
	Binary string
	Log    string
}

// Install writes a stand-in podman that runs the command on the host, records every call,
// and reports FAKE_PODMAN_STATE for container inspect. Tests can override the state with t.Setenv.
func Install(t *testing.T) Fake {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "podman")
	logPath := filepath.Join(dir, "calls.log")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_PODMAN_LOG", logPath)
	t.Setenv("FAKE_PODMAN_STATE", "running")
	return Fake{Binary: bin, Log: logPath}
}
