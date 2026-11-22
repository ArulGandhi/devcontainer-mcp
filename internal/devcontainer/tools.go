package devcontainer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ArulGandhi/devcontainer-mcp/internal/mcp"
	"github.com/ArulGandhi/devcontainer-mcp/internal/podman"
)

const (
	maxCodeBytes           = 64 << 10
	defaultBackgroundAfter = 30 * time.Second
)

// foregroundScript runs the code in the foreground. The host kills it when timeout_seconds is exceeded.
const foregroundScript = `cd "$HOME" || exit 1
f="$HOME/.repl-$MCP_RUN_ID.ts"
cat > "$f" || { rm -f "$f"; exit 1; }
command -v bun >/dev/null 2>&1 || { rm -f "$f"; echo "bun is not installed in the container" >&2; exit 127; }
bun run "$f"
s=$?
rm -f "$f"
exit $s`

// backgroundScript starts the code detached, waits up to $2 seconds for it, and returns its output if it
// finished. Otherwise it reports that the run was backgrounded; the run keeps going and writes its result
// to ~/.repl-jobs/<id>/. $1 is the hard cap in seconds applied to the detached run.
const backgroundScript = `cd "$HOME" || exit 1
id="$MCP_RUN_ID"
f="$HOME/.repl-$id.ts"
dir="$HOME/.repl-jobs/$id"
mkdir -p "$dir" || exit 1
cat > "$f" || { rm -rf "$dir" "$f"; exit 1; }
command -v bun >/dev/null 2>&1 || { rm -rf "$dir" "$f"; echo "bun is not installed in the container" >&2; exit 127; }
cap=""
command -v timeout >/dev/null 2>&1 && cap="timeout -s KILL $1"
setsid sh -c '
  $3 bun run "$1" >"$2/stdout" 2>"$2/stderr" </dev/null
  s=$?
  echo "$s" > "$2/exit.tmp" && mv "$2/exit.tmp" "$2/exit"
  rm -f "$1"
' job "$f" "$dir" "$cap" >/dev/null 2>&1 &
i=0
while [ ! -f "$dir/exit" ] && [ "$i" -lt "$2" ]; do sleep 1; i=$((i+1)); done
if [ -f "$dir/exit" ]; then
  echo "exit_code: $(cat "$dir/exit")"
  echo "--- stdout"
  cat "$dir/stdout"
  echo "--- stderr"
  cat "$dir/stderr"
  rm -rf "$dir"
else
  echo "backgrounded: run $id is still going after $2s. It keeps running in the container. Stdout goes to $dir/stdout, stderr to $dir/stderr, and the exit code is written to $dir/exit when it finishes."
fi`

type Options struct {
	// Timeout is the largest timeout_seconds a caller may set and the hard cap on backgrounded runs.
	Timeout time.Duration
	// BackgroundAfter is how long a run without timeout_seconds stays in the foreground. Zero means 30s.
	BackgroundAfter time.Duration
	Logger          *slog.Logger
}

type service struct {
	runner *podman.Runner
	opt    Options
}

// New returns the connector's only tool, repl.
func New(runner *podman.Runner, opt Options) ([]mcp.Tool, error) {
	switch {
	case runner == nil:
		return nil, errors.New("runner is nil")
	case opt.Logger == nil:
		return nil, errors.New("logger is nil")
	case opt.Timeout < time.Second:
		return nil, errors.New("timeout must be at least one second")
	case opt.BackgroundAfter < 0:
		return nil, errors.New("background-after must not be negative")
	}
	if opt.BackgroundAfter == 0 {
		opt.BackgroundAfter = defaultBackgroundAfter
	}
	s := &service{runner: runner, opt: opt}
	return []mcp.Tool{
		{
			Name: "repl",
			Description: "Run TypeScript with bun in the devcontainer. Each call is a fresh program with the home directory as " +
				"working directory. A run that is still going after 30 seconds is moved to the background and the call returns early " +
				"unless timeout_seconds is set. Returns exit_code, stdout and stderr.",
			InputSchema: objectSchema(map[string]any{
				"code": map[string]any{
					"type":        "string",
					"description": "TypeScript source to run.",
				},
				"timeout_seconds": map[string]any{
					"type": "integer",
					"description": fmt.Sprintf("If set, the run is killed when it exceeds this many seconds (1 to %d). "+
						"If unset, the run is backgrounded after 30 seconds.", int(opt.Timeout/time.Second)),
				},
			}, "code"),
			Run: s.repl,
		},
	}, nil
}

func objectSchema(props map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}

type replArgs struct {
	Code           string `json:"code"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func (s *service) repl(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := decode[replArgs](raw)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(args.Code) == "" {
		return "", invalid("code is required")
	}
	if len(args.Code) > maxCodeBytes {
		return "", invalid("code is longer than %d bytes", maxCodeBytes)
	}

	start := time.Now()
	var res podman.Result
	if args.TimeoutSeconds != 0 {
		timeout, err := s.timeout(args.TimeoutSeconds)
		if err != nil {
			return "", err
		}
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		res, err = s.runner.Exec(runCtx, strings.NewReader(args.Code), "sh", "-c", foregroundScript)
		s.log(args.Code, res, start, err, "foreground")
		if err != nil {
			return "", err
		}
		return formatResult(res), nil
	}

	capSeconds := int(s.opt.Timeout / time.Second)
	waitSeconds := int(s.opt.BackgroundAfter / time.Second)
	res, err = s.runner.Exec(context.WithoutCancel(ctx), strings.NewReader(args.Code), "sh", "-c", backgroundScript, "sh", fmt.Sprint(capSeconds), fmt.Sprint(waitSeconds))
	s.log(args.Code, res, start, err, "background")
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return formatResult(res), nil
	}
	return res.Stdout, nil
}

func (s *service) log(code string, res podman.Result, start time.Time, err error, mode string) {
	s.opt.Logger.Info("repl",
		"mode", mode,
		"code_bytes", len(code),
		"exit_code", res.ExitCode,
		"truncated", res.Truncated,
		"duration_ms", time.Since(start).Milliseconds(),
		"error", err,
	)
}

func (s *service) timeout(seconds int) (time.Duration, error) {
	maxSeconds := int(s.opt.Timeout / time.Second)
	if seconds < 0 || seconds > maxSeconds {
		return 0, invalid("timeout_seconds must be between 1 and %d", maxSeconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

func formatResult(res podman.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit_code: %d\n", res.ExitCode)
	if res.Truncated {
		b.WriteString("truncated: true\n")
	}
	b.WriteString("--- stdout\n")
	b.WriteString(res.Stdout)
	b.WriteString("\n--- stderr\n")
	b.WriteString(res.Stderr)
	return b.String()
}

func decode[T any](raw json.RawMessage) (T, error) {
	var v T
	if len(raw) == 0 {
		return v, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, invalid("%v", err)
	}
	return v, nil
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", mcp.ErrInvalidParams, fmt.Sprintf(format, a...))
}
