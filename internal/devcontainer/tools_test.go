package devcontainer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArulGandhi/devcontainer-mcp/internal/mcp"
	"github.com/ArulGandhi/devcontainer-mcp/internal/podman"
	"github.com/ArulGandhi/devcontainer-mcp/internal/podman/podmantest"
)

func newRepl(t *testing.T) (mcp.Tool, podmantest.Fake) {
	t.Helper()
	fake := podmantest.Install(t)
	runner, err := podman.New(podman.Config{Binary: fake.Binary, Container: "devbox", MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	tools, err := New(runner, Options{Timeout: 5 * time.Second, BackgroundAfter: 2 * time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "repl" {
		t.Fatalf("expected exactly one tool named repl, got %d", len(tools))
	}
	return tools[0], fake
}

func runRepl(t *testing.T, tool mcp.Tool, args string) (string, error) {
	t.Helper()
	return tool.Run(context.Background(), json.RawMessage(args))
}

func argsJSON(t *testing.T, v map[string]any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewRejectsSubSecondTimeout(t *testing.T) {
	fake := podmantest.Install(t)
	runner, err := podman.New(podman.Config{Binary: fake.Binary, Container: "devbox", MaxOutput: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(runner, Options{Timeout: time.Millisecond, Logger: slog.Default()}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunsCodeAndReturnsStreams(t *testing.T) {
	tool, _ := newRepl(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	requireRuntime(t)
	out, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": "console.log('out'); console.error('err');"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exit_code: 0", "out", "err"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}
}

func TestWorkingDirectoryIsHome(t *testing.T) {
	tool, _ := newRepl(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	requireRuntime(t)
	out, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": "console.log(process.cwd());"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, home) {
		t.Fatalf("cwd not home: %q", out)
	}
}

func TestScratchFileIsRemoved(t *testing.T) {
	tool, _ := newRepl(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	requireRuntime(t)
	if _, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": "console.log(1);"})); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".repl-*.ts"))
	if len(matches) != 0 {
		t.Fatalf("leftover scripts: %v", matches)
	}
	jobs, _ := filepath.Glob(filepath.Join(home, ".repl-jobs", "*"))
	if len(jobs) != 0 {
		t.Fatalf("finished job directories not cleaned up: %v", jobs)
	}
}

func TestNonZeroExitIsNormalResult(t *testing.T) {
	tool, _ := newRepl(t)
	t.Setenv("HOME", t.TempDir())
	requireRuntime(t)
	out, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": "process.exit(3);"}))
	if err != nil {
		t.Fatalf("non-zero exit must not be a tool error: %v", err)
	}
	if !strings.Contains(out, "exit_code: 3") {
		t.Fatalf("output %q", out)
	}
}

func TestRejectsBadArguments(t *testing.T) {
	tool, _ := newRepl(t)
	cases := map[string]string{
		"unknown field":     `{"code":"1","bogus":1}`,
		"empty code":        `{"code":"   "}`,
		"missing code":      `{}`,
		"wrong type":        `{"code":5}`,
		"timeout too large": `{"code":"1","timeout_seconds":600}`,
		"negative timeout":  `{"code":"1","timeout_seconds":-1}`,
	}
	for name, args := range cases {
		_, err := runRepl(t, tool, args)
		if !errors.Is(err, mcp.ErrInvalidParams) {
			t.Errorf("%s: err = %v, want invalid params", name, err)
		}
	}
}

func TestRejectsOversizedCode(t *testing.T) {
	tool, _ := newRepl(t)
	_, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": strings.Repeat("a", maxCodeBytes+1)}))
	if !errors.Is(err, mcp.ErrInvalidParams) {
		t.Fatalf("err = %v", err)
	}
}

func TestStopsAtTimeoutSeconds(t *testing.T) {
	tool, _ := newRepl(t)
	t.Setenv("HOME", t.TempDir())
	start := time.Now()
	_, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": "setTimeout(() => {}, 30000);", "timeout_seconds": 1}))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("took %s with a 1s timeout", elapsed)
	}
}

func requireRuntime(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bun"); err != nil {
		t.Skip("bun is not on this host")
	}
}

func TestBackgroundsRunAfterWindowAndFinishes(t *testing.T) {
	tool, _ := newRepl(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	requireRuntime(t)
	start := time.Now()
	out, err := runRepl(t, tool, argsJSON(t, map[string]any{"code": "await Bun.sleep(4000); console.log('late');"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "backgrounded") {
		t.Fatalf("expected backgrounded message, got %q", out)
	}
	if elapsed := time.Since(start); elapsed > 3500*time.Millisecond {
		t.Fatalf("call returned after %s; should return once the window (2s) has passed", elapsed)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		exits, _ := filepath.Glob(filepath.Join(home, ".repl-jobs", "*", "exit"))
		if len(exits) == 1 {
			stdout, _ := os.ReadFile(filepath.Join(filepath.Dir(exits[0]), "stdout"))
			if !strings.Contains(string(stdout), "late") {
				t.Fatalf("background stdout = %q", stdout)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("backgrounded run never wrote its exit file")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
