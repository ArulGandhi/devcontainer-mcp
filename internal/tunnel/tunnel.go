// Package tunnel gives the connector a public HTTPS address without a public IP by driving a tunnel
// program the operator already has installed: Tailscale Funnel or ngrok.
package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	Tailscale = "tailscale"
	Ngrok     = "ngrok"

	commandTimeout     = 30 * time.Second
	ngrokSurviveWindow = 3 * time.Second
)

type Config struct {
	Provider string
	// Addr is the loopback address the connector listens on, host:port.
	Addr string
	// Domain is the static ngrok domain (required for ngrok, ignored otherwise).
	Domain string
	// Binary overrides the tunnel program path; empty uses the provider's name from PATH.
	Binary string
}

// Tunnel is a running tunnel. URL is the public origin clients use.
type Tunnel struct {
	URL string

	done chan error
	stop func() error
	once sync.Once
}

// Done reports an unexpected exit of the tunnel program. It is nil for providers that run no child process.
func (t *Tunnel) Done() <-chan error { return t.done }

// Stop takes the tunnel down. It is safe to call more than once.
func (t *Tunnel) Stop() error {
	var err error
	t.once.Do(func() { err = t.stop() })
	return err
}

// Validate checks the provider settings without touching the system.
func Validate(cfg Config) error {
	switch cfg.Provider {
	case Tailscale:
	case Ngrok:
		if _, err := ngrokURL(cfg.Domain); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown tunnel %q; use %q or %q", cfg.Provider, Tailscale, Ngrok)
	}
	_, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil || port == "" {
		return fmt.Errorf("tunnel address %q must be host:port", cfg.Addr)
	}
	return nil
}

// Start brings the tunnel up and returns once its public URL is known.
func Start(ctx context.Context, cfg Config) (*Tunnel, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if cfg.Binary == "" {
		cfg.Binary = cfg.Provider
	}
	if _, err := exec.LookPath(cfg.Binary); err != nil {
		return nil, fmt.Errorf("%s is not installed or not on PATH (%v); install it from %s", cfg.Provider, err, installURL(cfg.Provider))
	}
	if cfg.Provider == Tailscale {
		return startTailscale(ctx, cfg)
	}
	return startNgrok(ctx, cfg)
}

func installURL(provider string) string {
	if provider == Tailscale {
		return "https://tailscale.com/download"
	}
	return "https://ngrok.com/download"
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

func run(ctx context.Context, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

type tailscaleStatus struct {
	BackendState string
	AuthURL      string
	Self         struct{ DNSName string }
}

func startTailscale(ctx context.Context, cfg Config) (*Tunnel, error) {
	raw, err := run(ctx, cfg.Binary, "status", "--json")
	if err != nil && raw == "" {
		return nil, err
	}
	var st tailscaleStatus
	if jsonErr := json.Unmarshal([]byte(raw), &st); jsonErr != nil {
		return nil, fmt.Errorf("tailscale status --json: unreadable output: %v: %s", jsonErr, strings.TrimSpace(raw))
	}
	if st.BackendState != "Running" {
		return nil, fmt.Errorf("tailscale is not connected (state %q); run `tailscale up` and log in", st.BackendState)
	}
	host := strings.TrimSuffix(st.Self.DNSName, ".")
	if host == "" {
		return nil, errors.New("tailscale reports no DNS name for this machine; enable MagicDNS and HTTPS in the Tailscale admin console")
	}

	existing, err := run(ctx, cfg.Binary, "serve", "status", "--json")
	if err != nil {
		return nil, err
	}
	if trimmed := strings.TrimSpace(existing); trimmed != "" && trimmed != "{}" {
		return nil, errors.New("tailscale already serves something on this machine; refusing to overwrite it. " +
			"Run `tailscale funnel reset` if it is not needed, or expose the connector yourself and pass -public-url")
	}

	if _, err := run(ctx, cfg.Binary, "funnel", "--bg", "--yes", "--https=443", port(cfg.Addr)); err != nil {
		return nil, fmt.Errorf("start funnel: %w (Funnel must be enabled for this machine in the Tailscale admin console)", err)
	}
	t := &Tunnel{URL: "https://" + host}
	t.stop = func() error {
		_, err := run(context.Background(), cfg.Binary, "funnel", "--https=443", "off")
		return err
	}
	return t, nil
}

func ngrokURL(domain string) (string, error) {
	d := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(domain), "https://"), "http://")
	d = strings.TrimSuffix(d, "/")
	if d == "" || strings.ContainsAny(d, "/ \t") {
		return "", errors.New("-tunnel-domain is required for ngrok: your static domain, e.g. name.ngrok-free.dev")
	}
	return "https://" + d, nil
}

func startNgrok(ctx context.Context, cfg Config) (*Tunnel, error) {
	url, err := ngrokURL(cfg.Domain)
	if err != nil {
		return nil, err
	}
	var out lockedBuffer
	cmd := exec.Command(cfg.Binary, "http", port(cfg.Addr), "--url", url)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ngrok: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	select {
	case err := <-exited:
		return nil, fmt.Errorf("ngrok exited immediately: %v: %s", err, strings.TrimSpace(out.String()))
	case <-time.After(ngrokSurviveWindow):
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-exited
		return nil, ctx.Err()
	}

	t := &Tunnel{URL: url, done: make(chan error, 1)}
	var stopping sync.Once
	var stopped = make(chan struct{})
	go func() {
		err := <-exited
		select {
		case <-stopped:
		default:
			t.done <- fmt.Errorf("ngrok exited: %v: %s", err, strings.TrimSpace(out.String()))
		}
	}()
	t.stop = func() error {
		stopping.Do(func() { close(stopped) })
		return cmd.Process.Kill()
	}
	return t, nil
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	const keep = 4 << 10
	s := b.buf.String()
	if len(s) > keep {
		s = s[len(s)-keep:]
	}
	return s
}
