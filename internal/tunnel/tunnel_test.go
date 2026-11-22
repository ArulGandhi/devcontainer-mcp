package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fakeTailscale = `#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1 $2" in
  "status --json") printf '%s' "$FAKE_STATUS" ;;
  "serve status") printf '%s' "$FAKE_SERVE" ;;
  "funnel status") [ -n "$FAKE_FUNNEL_OFF" ] && echo "No serve config" || echo "https://box.tail1234.ts.net (Funnel on)" ;;
  funnel*) [ -n "$FAKE_FUNNEL_FAIL" ] && { echo "$FAKE_FUNNEL_FAIL" >&2; exit 1; } ;;
esac
exit 0
`

func installFake(t *testing.T, script string) (bin, logPath string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "fake")
	logPath = filepath.Join(dir, "calls.log")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_LOG", logPath)
	return bin, logPath
}

func calls(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

func tsConfig(bin string) Config {
	return Config{Provider: Tailscale, Addr: "127.0.0.1:8787", Binary: bin}
}

func TestValidate(t *testing.T) {
	cases := map[string]Config{
		"unknown provider": {Provider: "frp", Addr: "127.0.0.1:1"},
		"ngrok no domain":  {Provider: Ngrok, Addr: "127.0.0.1:1"},
		"ngrok bad domain": {Provider: Ngrok, Domain: "a b/c", Addr: "127.0.0.1:1"},
		"bad addr":         {Provider: Tailscale, Addr: "nonsense"},
	}
	for name, cfg := range cases {
		if err := Validate(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if err := Validate(Config{Provider: Ngrok, Domain: "https://x.ngrok-free.dev/", Addr: "127.0.0.1:1"}); err != nil {
		t.Fatalf("valid ngrok config rejected: %v", err)
	}
}

func TestStartFailsLoudWhenBinaryMissing(t *testing.T) {
	_, err := Start(context.Background(), Config{Provider: Tailscale, Addr: "127.0.0.1:1", Binary: "/nonexistent/tailscale"})
	if err == nil || !strings.Contains(err.Error(), "install it from") {
		t.Fatalf("err = %v", err)
	}
}

func TestTailscaleStartsFunnelAndStopsIt(t *testing.T) {
	bin, log := installFake(t, fakeTailscale)
	t.Setenv("FAKE_STATUS", `{"BackendState":"Running","Self":{"DNSName":"box.tail1234.ts.net."}}`)
	t.Setenv("FAKE_SERVE", "{}\n")
	tun, err := Start(context.Background(), tsConfig(bin))
	if err != nil {
		t.Fatal(err)
	}
	if tun.URL != "https://box.tail1234.ts.net" {
		t.Fatalf("URL = %q", tun.URL)
	}
	if tun.Done() != nil {
		t.Fatal("tailscale runs no child process; Done must be nil")
	}
	if !strings.Contains(calls(t, log), "funnel --bg --yes --https=443 8787") {
		t.Fatalf("calls:\n%s", calls(t, log))
	}
	if err := tun.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if got := strings.Count(calls(t, log), "funnel --https=443 off"); got != 1 {
		t.Fatalf("off called %d times:\n%s", got, calls(t, log))
	}
}

func TestTailscaleRefusesWhenLoggedOut(t *testing.T) {
	bin, log := installFake(t, fakeTailscale)
	t.Setenv("FAKE_STATUS", `{"BackendState":"NeedsLogin","Self":{"DNSName":""}}`)
	_, err := Start(context.Background(), tsConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "tailscale up") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(calls(t, log), "funnel") {
		t.Fatal("funnel was started while logged out")
	}
}

func TestTailscaleRefusesToOverwriteExistingServeConfig(t *testing.T) {
	bin, log := installFake(t, fakeTailscale)
	t.Setenv("FAKE_STATUS", `{"BackendState":"Running","Self":{"DNSName":"box.tail1234.ts.net."}}`)
	t.Setenv("FAKE_SERVE", `{"TCP":{"443":{"HTTPS":true}}}`)
	_, err := Start(context.Background(), tsConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(calls(t, log), "funnel") {
		t.Fatal("funnel was started over an existing config")
	}
}

func runningTailscale(t *testing.T) (bin, log string) {
	t.Helper()
	bin, log = installFake(t, fakeTailscale)
	t.Setenv("FAKE_STATUS", `{"BackendState":"Running","Self":{"DNSName":"box.tail1234.ts.net."}}`)
	t.Setenv("FAKE_SERVE", "{}")
	return bin, log
}

func TestTailscaleFunnelNotEnabledGivesTheLink(t *testing.T) {
	bin, _ := runningTailscale(t)
	t.Setenv("FAKE_FUNNEL_FAIL", "Funnel is not enabled on your tailnet.\nTo enable, visit:\n\n         https://login.tailscale.com/f/funnel?node=abc123\n")
	_, err := Start(context.Background(), tsConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "https://login.tailscale.com/f/funnel?node=abc123") || strings.Contains(err.Error(), "killed") {
		t.Fatalf("err = %v", err)
	}
}

func TestTailscaleAccessDeniedExplainsOperator(t *testing.T) {
	bin, _ := runningTailscale(t)
	t.Setenv("FAKE_FUNNEL_FAIL", "sending serve config: Access denied: serve config denied")
	_, err := Start(context.Background(), tsConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "set --operator") {
		t.Fatalf("err = %v", err)
	}
}

func TestTailscaleOtherFunnelFailureKeepsOutput(t *testing.T) {
	bin, _ := runningTailscale(t)
	t.Setenv("FAKE_FUNNEL_FAIL", "something unexpected")
	_, err := Start(context.Background(), tsConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "something unexpected") {
		t.Fatalf("err = %v", err)
	}
}

func TestTailscaleVerifiesFunnelIsOnAndRollsBack(t *testing.T) {
	bin, log := runningTailscale(t)
	t.Setenv("FAKE_FUNNEL_OFF", "1")
	_, err := Start(context.Background(), tsConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "Funnel on") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(calls(t, log), "funnel --https=443 off") {
		t.Fatalf("funnel not rolled back:\n%s", calls(t, log))
	}
}

func TestTailscaleRejectsGarbageStatus(t *testing.T) {
	bin, _ := installFake(t, fakeTailscale)
	t.Setenv("FAKE_STATUS", "not json")
	if _, err := Start(context.Background(), tsConfig(bin)); err == nil {
		t.Fatal("expected error")
	}
}

func ngrokConfig(bin string) Config {
	return Config{Provider: Ngrok, Addr: "127.0.0.1:8787", Domain: "me.ngrok-free.dev", Binary: bin}
}

func TestNgrokRunsWithStaticDomainAndStops(t *testing.T) {
	bin, log := installFake(t, "#!/bin/sh\necho \"$*\" >> \"$FAKE_LOG\"\nexec sleep 30\n")
	start := time.Now()
	tun, err := Start(context.Background(), ngrokConfig(bin))
	if err != nil {
		t.Fatal(err)
	}
	if tun.URL != "https://me.ngrok-free.dev" {
		t.Fatalf("URL = %q", tun.URL)
	}
	if !strings.Contains(calls(t, log), "http 8787 --url https://me.ngrok-free.dev") {
		t.Fatalf("calls:\n%s", calls(t, log))
	}
	if err := tun.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-tun.Done():
		t.Fatalf("Done fired after a requested Stop: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("start took too long")
	}
}

func TestNgrokEarlyExitReportsItsOutput(t *testing.T) {
	bin, _ := installFake(t, "#!/bin/sh\necho 'authentication failed: no authtoken' >&2\nexit 1\n")
	_, err := Start(context.Background(), ngrokConfig(bin))
	if err == nil || !strings.Contains(err.Error(), "no authtoken") {
		t.Fatalf("err = %v", err)
	}
}

func TestNgrokDeathAfterStartIsReported(t *testing.T) {
	bin, _ := installFake(t, "#!/bin/sh\nsleep 4\necho gone >&2\nexit 2\n")
	tun, err := Start(context.Background(), ngrokConfig(bin))
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Stop()
	select {
	case err := <-tun.Done():
		if err == nil || !strings.Contains(err.Error(), "gone") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel death was not reported")
	}
}
