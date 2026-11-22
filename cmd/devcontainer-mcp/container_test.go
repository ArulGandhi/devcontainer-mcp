package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakePodmanScript = `#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1 $2" in
  "image exists") [ "$FAKE_IMAGE" = "yes" ] && exit 0 || exit 1 ;;
  "container inspect") [ -z "$FAKE_STATE" ] && { echo "no such container" >&2; exit 125; }; echo "$FAKE_STATE"; exit 0 ;;
esac
[ "$1" = "build" ] && [ -n "$FAKE_BUILD_FAIL" ] && { echo "build exploded" >&2; exit 1; }
exit 0
`

func fakePodman(t *testing.T) (spec containerSpec, log string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "podman")
	log = filepath.Join(dir, "calls.log")
	if err := os.WriteFile(bin, []byte(fakePodmanScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_LOG", log)
	t.Setenv("FAKE_IMAGE", "")
	t.Setenv("FAKE_STATE", "")
	return containerSpec{podman: bin, name: "devbox", image: "localhost/devbox:latest", memory: "2g", pidsLimit: "512"}, log
}

func logText(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

func TestContainerUpBuildsAndCreatesWithLimits(t *testing.T) {
	spec, log := fakePodman(t)
	var out bytes.Buffer
	if err := containerUp(context.Background(), spec, &out); err != nil {
		t.Fatal(err)
	}
	calls := logText(t, log)
	for _, want := range []string{"build --tag localhost/devbox:latest", "run --detach --name devbox --init --restart=unless-stopped --memory 2g --pids-limit 512 --security-opt no-new-privileges localhost/devbox:latest"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call %q in:\n%s", want, calls)
		}
	}
}

func TestContainerUpSkipsBuildWhenImageExists(t *testing.T) {
	spec, log := fakePodman(t)
	t.Setenv("FAKE_IMAGE", "yes")
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logText(t, log), "build ") {
		t.Fatal("rebuilt an existing image")
	}
	spec.rebuild = true
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logText(t, log), "build ") {
		t.Fatal("-rebuild did not build")
	}
}

func TestContainerUpLeavesRunningContainerAndStartsStopped(t *testing.T) {
	spec, log := fakePodman(t)
	t.Setenv("FAKE_IMAGE", "yes")
	t.Setenv("FAKE_STATE", "running")
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logText(t, log), "run --detach") || strings.Contains(logText(t, log), "start ") {
		t.Fatalf("touched a running container:\n%s", logText(t, log))
	}
	t.Setenv("FAKE_STATE", "exited")
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logText(t, log), "start devbox") {
		t.Fatalf("did not start the stopped container:\n%s", logText(t, log))
	}
}

func TestContainerUpFailsLoud(t *testing.T) {
	spec, _ := fakePodman(t)
	t.Setenv("FAKE_BUILD_FAIL", "1")
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "build exploded") {
		t.Fatalf("build failure: %v", err)
	}
	spec.podman = "/nonexistent/podman"
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "podman.io") {
		t.Fatalf("missing podman: %v", err)
	}
	spec.name = "-rm"
	if err := containerUp(context.Background(), spec, &bytes.Buffer{}); err == nil {
		t.Fatal("flag-like container name accepted")
	}
}

func TestContainerfileIsEmbeddedAndMultiArch(t *testing.T) {
	text := string(containerfile)
	for _, want := range []string{"bun-linux-aarch64", "bun-linux-x64", "sha256sum -c"} {
		if !strings.Contains(text, want) {
			t.Errorf("Containerfile lacks %q", want)
		}
	}
}

func TestInitGeneratesPasswordAndWritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	authPath, clientPath := filepath.Join(dir, "cfg", "auth.json"), filepath.Join(dir, "cfg", "client.txt")
	var out bytes.Buffer
	if err := initAll([]string{"-auth-file", authPath, "-client-file", clientPath}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "otpauth://totp/") || strings.Contains(text, "client_secret=") {
		t.Fatalf("output: %s", text)
	}
	password := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(text, "\n", 2)[0], "Password (shown once, store it in a password manager):"))
	if len(password) < 20 {
		t.Fatalf("generated password too short: %q", password)
	}
	for _, p := range []string{authPath, clientPath} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, info, err)
		}
	}
	if err := initAll([]string{"-auth-file", authPath, "-client-file", clientPath}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("second init must refuse without -force")
	}
	if err := initAll([]string{"-auth-file", authPath, "-client-file", clientPath, "-force"}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatalf("-force: %v", err)
	}
}

func TestInitPasswordStdinDoesNotPrintPassword(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	err := initAll([]string{"-auth-file", filepath.Join(dir, "a.json"), "-client-file", filepath.Join(dir, "c.txt"), "-password-stdin"},
		strings.NewReader("correct horse battery\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "correct horse battery") {
		t.Fatal("piped password echoed back")
	}
	if err := initAll([]string{"-auth-file", filepath.Join(dir, "b.json"), "-client-file", filepath.Join(dir, "d.txt"), "-password-stdin"},
		strings.NewReader("short\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "d.txt")); err == nil {
		t.Fatal("client file written after failed init")
	}
}
