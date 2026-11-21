package podman

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	runIDEnv        = "MCP_RUN_ID"
	killTimeout     = 10 * time.Second
	killProcsScript = `for p in /proc/[0-9]*; do
  if tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -qx "MCP_RUN_ID=$1"; then kill -9 "${p#/proc/}" 2>/dev/null; fi
done
rm -f "$HOME/.repl-$1.ts"`
)

type Config struct {
	Binary    string
	Container string
	User      string
	MaxOutput int
}

type Result struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	Truncated bool
}

type Runner struct {
	cfg Config
}

func New(cfg Config) (*Runner, error) {
	switch {
	case cfg.Binary == "":
		return nil, errors.New("podman binary path is empty")
	case cfg.Container == "":
		return nil, errors.New("container name is empty")
	case strings.HasPrefix(cfg.Container, "-") || strings.ContainsAny(cfg.Container, " \t\r\n"):
		return nil, fmt.Errorf("container name %q is not valid", cfg.Container)
	case cfg.MaxOutput <= 0:
		return nil, errors.New("max output must be positive")
	}
	return &Runner{cfg: cfg}, nil
}

func (r *Runner) State(ctx context.Context) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.cfg.Binary, "container", "inspect", "--format", "{{.State.Status}}", r.cfg.Container)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("inspect container %q: %w: %s", r.cfg.Container, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// Exec runs argv inside the container. When ctx ends first, every process started by this call
// is killed inside the container, not only the local podman client, so nothing keeps running after a timeout.
func (r *Runner) Exec(ctx context.Context, stdin io.Reader, argv ...string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("exec needs a command")
	}
	state, err := r.State(ctx)
	if err != nil {
		return Result{}, err
	}
	if state != "running" {
		return Result{}, fmt.Errorf("container %q is %s, not running; start it on the host with podman start", r.cfg.Container, state)
	}
	runID, err := newRunID()
	if err != nil {
		return Result{}, err
	}

	args := []string{"exec", "--env", runIDEnv + "=" + runID}
	if stdin != nil {
		args = append(args, "--interactive")
	}
	if r.cfg.User != "" {
		args = append(args, "--user", r.cfg.User)
	}
	args = append(args, r.cfg.Container)
	args = append(args, argv...)

	stdout := &limitedBuffer{max: r.cfg.MaxOutput}
	stderr := &limitedBuffer{max: r.cfg.MaxOutput}
	cmd := exec.CommandContext(ctx, r.cfg.Binary, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second

	var cleanupMu sync.Mutex
	var cleanupErr error
	cmd.Cancel = func() error {
		err := r.killRun(runID)
		cleanupMu.Lock()
		cleanupErr = err
		cleanupMu.Unlock()
		return cmd.Process.Kill()
	}
	runErr := cmd.Run()

	res := Result{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		if cleanupErr != nil {
			return res, fmt.Errorf("command stopped: %w; cleanup inside container failed: %v", ctxErr, cleanupErr)
		}
		return res, fmt.Errorf("command stopped: %w", ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if runErr != nil {
		return res, fmt.Errorf("run podman exec: %w", runErr)
	}
	return res, nil
}

func (r *Runner) killRun(runID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), killTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.cfg.Binary, "exec", r.cfg.Container, "sh", "-c", killProcsScript, "sh", runID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kill run %s: %w: %s", runID, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func newRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("run id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.max - b.buf.Len()
	if room >= len(p) {
		b.buf.Write(p)
		return len(p), nil
	}
	if room > 0 {
		b.buf.Write(p[:room])
	}
	b.truncated = true
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
