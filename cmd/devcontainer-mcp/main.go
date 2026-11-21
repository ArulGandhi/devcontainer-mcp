package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ArulGandhi/gemini-connector/internal/devcontainer"
	"github.com/ArulGandhi/gemini-connector/internal/httpguard"
	"github.com/ArulGandhi/gemini-connector/internal/mcp"
	"github.com/ArulGandhi/gemini-connector/internal/oauth"
	"github.com/ArulGandhi/gemini-connector/internal/podman"
)

type config struct {
	listen         string
	publicURL      string
	container      string
	user           string
	authFile       string
	stateFile      string
	tlsCert        string
	tlsKey         string
	podmanBin      string
	execTimeout    time.Duration
	maxOutput      int
	maxConcurrency int
	rate           float64
	burst          int
	maxBody        int64
	auditLog       string
}

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "init-auth":
		err = initAuth(os.Args[2:], os.Stdin, os.Stdout)
	case len(os.Args) > 1 && os.Args[1] == "issue-client":
		err = issueClient(os.Args[2:], os.Stdout)
	default:
		err = run(os.Args[1:], os.Stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "devcontainer-mcp: %v\n", err)
		os.Exit(1)
	}
}

func defaultConfigPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	return filepath.Join(home, ".config", "devcontainer-mcp", name)
}

// initAuth sets the operator password (read from stdin, one line) and creates the TOTP secret.
func initAuth(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("init-auth", flag.ContinueOnError)
	authFile := fs.String("auth-file", defaultConfigPath("auth.json"), "where to write the login file")
	account := fs.String("account", "owner", "label shown in the authenticator app")
	force := fs.Bool("force", false, "overwrite an existing login file (drops the client credentials too)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*authFile); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass -force to replace it", *authFile)
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read password: %w", err)
	}
	a, err := oauth.NewAuthFile(strings.TrimRight(line, "\r\n"))
	if err != nil {
		return err
	}
	if err := oauth.SaveAuthFile(*authFile, a); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "login file written to %s (mode 600)\n", *authFile)
	fmt.Fprintln(stdout, "Add this entry to your authenticator app now. It is shown only once:")
	fmt.Fprintln(stdout, a.OTPAuthURI("devcontainer-mcp", *account))
	return nil
}

// issueClient creates the pre-registered client ID and secret that Gemini (and other clients that need one) use.
// The secret is written to a mode-600 file and never printed.
func issueClient(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("issue-client", flag.ContinueOnError)
	authFile := fs.String("auth-file", defaultConfigPath("auth.json"), "login file to add the client to")
	clientFile := fs.String("client-file", defaultConfigPath("client.txt"), "where to write the client ID and secret")
	redirects := fs.String("redirect-uri", oauth.GeminiRedirectURI, "comma-separated redirect URIs the client may use")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := oauth.LoadAuthFile(*authFile)
	if err != nil {
		return fmt.Errorf("%w (run init-auth first)", err)
	}
	var uris []string
	for _, u := range strings.Split(*redirects, ",") {
		if u = strings.TrimSpace(u); u != "" {
			uris = append(uris, u)
		}
	}
	a, clientID, secret, err := a.WithClient(uris)
	if err != nil {
		return err
	}
	if err := oauth.SaveAuthFile(*authFile, a); err != nil {
		return err
	}
	content := fmt.Sprintf("client_id=%s\nclient_secret=%s\nredirect_uris=%s\n", clientID, secret, strings.Join(uris, ","))
	if err := os.WriteFile(*clientFile, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write client file: %w", err)
	}
	fmt.Fprintf(stdout, "client credentials written to %s (mode 600)\n", *clientFile)
	fmt.Fprintf(stdout, "redirect URIs allowed: %s\n", strings.Join(uris, ", "))
	fmt.Fprintln(stdout, "Any previous client secret is now invalid.")
	return nil
}

func run(args []string, stderr io.Writer) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	logger, closeLog, err := openLogger(cfg.auditLog, stderr)
	if err != nil {
		return err
	}
	defer closeLog()

	auth, err := oauth.LoadAuthFile(cfg.authFile)
	if err != nil {
		return fmt.Errorf("%w (run init-auth, then issue-client)", err)
	}
	store, err := oauth.OpenStore(cfg.stateFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner, err := podman.New(podman.Config{
		Binary:    cfg.podmanBin,
		Container: cfg.container,
		User:      cfg.user,
		MaxOutput: cfg.maxOutput,
	})
	if err != nil {
		return err
	}
	state, err := runner.State(ctx)
	if err != nil {
		return fmt.Errorf("startup container check: %w", err)
	}
	if state != "running" {
		logger.Warn("container is not running; tool calls will fail until it is started", "container", cfg.container, "state", state)
	}

	tools, err := devcontainer.New(runner, devcontainer.Options{Timeout: cfg.execTimeout, Logger: logger})
	if err != nil {
		return err
	}
	server, err := mcp.NewServer(tools, logger, cfg.maxConcurrency)
	if err != nil {
		return err
	}
	authServer, err := oauth.New(oauth.Config{
		PublicURL: cfg.publicURL,
		Auth:      auth,
		Store:     store,
		Logger:    logger,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	authServer.Register(mux)
	mux.Handle(mcp.Path, authServer.RequireToken(server.HTTPHandler()))

	origin, err := publicOrigin(cfg.publicURL)
	if err != nil {
		return err
	}
	guarded, err := httpguard.Wrap(mux, httpguard.Options{
		AllowedOrigins: []string{origin},
		RatePerSecond:  cfg.rate,
		Burst:          cfg.burst,
		MaxBodyBytes:   cfg.maxBody,
	})
	if err != nil {
		return err
	}
	handler := logRequests(logger, guarded)

	httpServer := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      cfg.execTimeout + time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown", "error", err)
		}
	}()

	logger.Info("listening", "addr", cfg.listen, "public_url", cfg.publicURL, "container", cfg.container, "tls", cfg.tlsCert != "")
	var serveErr error
	if cfg.tlsCert != "" {
		serveErr = httpServer.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
	} else {
		serveErr = httpServer.ListenAndServe()
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}

func parseConfig(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("devcontainer-mcp", flag.ContinueOnError)
	fs.StringVar(&cfg.listen, "listen", "127.0.0.1:8787", "address to listen on; a non-loopback address requires -tls-cert and -tls-key")
	fs.StringVar(&cfg.publicURL, "public-url", "", "public origin clients use, e.g. https://host.example (required); the MCP endpoint is /mcp under it")
	fs.StringVar(&cfg.container, "container", "", "name or ID of the podman container to control (required)")
	fs.StringVar(&cfg.user, "user", "", "user to run commands as inside the container; empty uses the container's default")
	fs.StringVar(&cfg.authFile, "auth-file", defaultConfigPath("auth.json"), "login and client file made by init-auth and issue-client")
	fs.StringVar(&cfg.stateFile, "state-file", defaultConfigPath("oauth-state.json"), "file holding token hashes and the last TOTP step")
	fs.StringVar(&cfg.tlsCert, "tls-cert", "", "PEM certificate for HTTPS")
	fs.StringVar(&cfg.tlsKey, "tls-key", "", "PEM private key for HTTPS")
	fs.StringVar(&cfg.podmanBin, "podman", "podman", "podman binary")
	fs.DurationVar(&cfg.execTimeout, "exec-timeout", 2*time.Minute, "default and maximum time one repl run may take; also the cap on backgrounded runs")
	fs.IntVar(&cfg.maxOutput, "max-output", 1<<20, "bytes of stdout and of stderr returned per call")
	fs.IntVar(&cfg.maxConcurrency, "max-concurrency", 4, "tool calls allowed to run at once")
	fs.Float64Var(&cfg.rate, "rate-limit", 10, "sustained HTTP requests per second")
	fs.IntVar(&cfg.burst, "rate-burst", 20, "HTTP requests allowed in a burst")
	fs.Int64Var(&cfg.maxBody, "max-body", 2<<20, "maximum request body in bytes")
	fs.StringVar(&cfg.auditLog, "audit-log", "", "file for JSON audit lines; empty writes them to stderr")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	switch {
	case cfg.container == "":
		return config{}, errors.New("-container is required")
	case cfg.publicURL == "":
		return config{}, errors.New("-public-url is required")
	case (cfg.tlsCert == "") != (cfg.tlsKey == ""):
		return config{}, errors.New("-tls-cert and -tls-key must be given together")
	case cfg.execTimeout < time.Second:
		return config{}, errors.New("-exec-timeout must be at least 1s")
	case cfg.maxOutput <= 0, cfg.maxConcurrency <= 0, cfg.burst <= 0, cfg.maxBody <= 0, cfg.rate <= 0:
		return config{}, errors.New("-max-output, -max-concurrency, -rate-limit, -rate-burst and -max-body must be positive")
	}

	host, _, err := net.SplitHostPort(cfg.listen)
	if err != nil {
		return config{}, fmt.Errorf("-listen: %w", err)
	}
	if !isLoopback(host) && cfg.tlsCert == "" {
		return config{}, fmt.Errorf("-listen %s is reachable from the network; set -tls-cert and -tls-key", cfg.listen)
	}
	return cfg, nil
}

func publicOrigin(raw string) (string, error) {
	scheme, host, ok := strings.Cut(raw, "://")
	if !ok || host == "" {
		return "", fmt.Errorf("-public-url %q must be an origin like https://host", raw)
	}
	return scheme + "://" + strings.TrimSuffix(host, "/"), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func openLogger(path string, stderr io.Writer) (*slog.Logger, func(), error) {
	out := stderr
	closeFn := func() {}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("audit log: %w", err)
		}
		out = f
		closeFn = func() { _ = f.Close() }
	}
	return slog.New(slog.NewJSONHandler(out, nil)), closeFn, nil
}
