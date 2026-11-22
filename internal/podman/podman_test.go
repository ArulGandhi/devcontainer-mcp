package podman

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArulGandhi/devcontainer-mcp/internal/podman/podmantest"
)

func newFakeRunner(t *testing.T, maxOutput int) (*Runner, podmantest.Fake) {
	t.Helper()
	fake := podmantest.Install(t)
	r, err := New(Config{Binary: fake.Binary, Container: "devbox", MaxOutput: maxOutput})
	if err != nil {
		t.Fatal(err)
	}
	return r, fake
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewRejectsFlagLikeContainerName(t *testing.T) {
	if _, err := New(Config{Binary: "podman", Container: "-rm", MaxOutput: 1}); err == nil {
		t.Fatal("expected error for container name starting with a dash")
	}
}

func TestNewRejectsEmptyFields(t *testing.T) {
	cases := map[string]Config{
		"binary":    {Container: "c", MaxOutput: 1},
		"container": {Binary: "podman", MaxOutput: 1},
		"output":    {Binary: "podman", Container: "c"},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExecRunsInsideContainer(t *testing.T) {
	r, fake := newFakeRunner(t, 1<<20)
	res, err := r.Exec(context.Background(), nil, "sh", "-c", "echo hi")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hi\n" || res.ExitCode != 0 {
		t.Fatalf("got stdout %q exit %d", res.Stdout, res.ExitCode)
	}
	if !strings.Contains(readLog(t, fake.Log), "MCP_RUN_ID=") || !strings.Contains(readLog(t, fake.Log), "devbox sh -c echo hi") {
		t.Fatalf("unexpected podman call: %s", readLog(t, fake.Log))
	}
}

func TestExecReturnsCommandExitCode(t *testing.T) {
	r, _ := newFakeRunner(t, 1<<20)
	res, err := r.Exec(context.Background(), nil, "sh", "-c", "exit 3")
	if err != nil {
		t.Fatalf("non-zero exit must not be a transport error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestExecTruncatesOutput(t *testing.T) {
	r, _ := newFakeRunner(t, 5)
	res, err := r.Exec(context.Background(), nil, "printf", "0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "01234" || !res.Truncated {
		t.Fatalf("stdout %q truncated %t", res.Stdout, res.Truncated)
	}
}

func TestExecPassesStdin(t *testing.T) {
	r, fake := newFakeRunner(t, 1<<20)
	res, err := r.Exec(context.Background(), strings.NewReader("hello"), "cat")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hello" {
		t.Fatalf("stdout %q", res.Stdout)
	}
	if !strings.Contains(readLog(t, fake.Log), "--interactive devbox cat") {
		t.Fatalf("stdin run must pass --interactive: %s", readLog(t, fake.Log))
	}
}

func TestExecRefusesStoppedContainer(t *testing.T) {
	r, _ := newFakeRunner(t, 1<<20)
	t.Setenv("FAKE_PODMAN_STATE", "exited")
	_, err := r.Exec(context.Background(), nil, "true")
	if err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("expected not-running error, got %v", err)
	}
}

func TestExecStopsAtDeadline(t *testing.T) {
	r, _ := newFakeRunner(t, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Exec(ctx, nil, "sleep", "10")
	if err == nil {
		t.Fatal("expected deadline error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s, deadline was 200ms", elapsed)
	}
}

func TestStateFailsLoudWhenPodmanMissing(t *testing.T) {
	r, err := New(Config{Binary: "/nonexistent/podman", Container: "devbox", MaxOutput: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.State(context.Background()); err == nil {
		t.Fatal("expected error when podman binary is missing")
	}
}

func TestRealPodmanExec(t *testing.T) {
	name := os.Getenv("DEVCONTAINER_MCP_TEST_CONTAINER")
	if name == "" {
		t.Skip("set DEVCONTAINER_MCP_TEST_CONTAINER to a running container to run against real podman")
	}
	r, err := New(Config{Binary: "podman", Container: name, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Exec(context.Background(), nil, "sh", "-c", "echo integration-ok")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "integration-ok") {
		t.Fatalf("stdout %q exit %d stderr %q", res.Stdout, res.ExitCode, res.Stderr)
	}
}

func TestExecTimeoutKillsChildProcesses(t *testing.T) {
	r, _ := newFakeRunner(t, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Exec(ctx, nil, "sh", "-c", "sleep 53 & wait")
	if err == nil {
		t.Fatal("expected timeout")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
	time.Sleep(200 * time.Millisecond)
	if running := processesWithCmdline(t, "sleep\x0053\x00"); running != 0 {
		t.Fatalf("%d child process(es) survived the timeout", running)
	}
}

func TestTimeoutCleanupRunsAsConfiguredUser(t *testing.T) {
	fake := podmantest.Install(t)
	r, err := New(Config{Binary: fake.Binary, Container: "devbox", User: "root", MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := r.Exec(ctx, nil, "sleep", "10"); err == nil {
		t.Fatal("expected timeout")
	}
	var cleanupCalls int
	for _, call := range regexp.MustCompile(`(?m)^exec `).Split(readLog(t, fake.Log), -1) {
		if !strings.Contains(call, "kill -9") {
			continue
		}
		cleanupCalls++
		if !strings.HasPrefix(call, "--user root ") {
			t.Errorf("cleanup call does not run as the configured user: %.60s", call)
		}
	}
	if cleanupCalls != 1 {
		t.Fatalf("got %d cleanup calls, want 1", cleanupCalls)
	}
}

func processesWithCmdline(t *testing.T, want string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && strings.HasPrefix(string(raw), want) {
			count++
		}
	}
	return count
}
