package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArulGandhi/devcontainer-mcp/internal/oauth"
)

func baseArgs(extra ...string) []string {
	return append([]string{"-container", "devbox", "-public-url", "https://host.example"}, extra...)
}

func TestParseConfigRequiresContainer(t *testing.T) {
	_, err := parseConfig([]string{"-public-url", "https://host.example"})
	if err == nil || !strings.Contains(err.Error(), "-container") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseConfigRequiresPublicURL(t *testing.T) {
	_, err := parseConfig([]string{"-container", "devbox"})
	if err == nil || !strings.Contains(err.Error(), "-public-url") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseConfigRefusesNetworkBindWithoutTLS(t *testing.T) {
	_, err := parseConfig(baseArgs("-listen", "0.0.0.0:443"))
	if err == nil || !strings.Contains(err.Error(), "tls-cert") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseConfigAllowsNetworkBindWithTLS(t *testing.T) {
	if _, err := parseConfig(baseArgs("-listen", "0.0.0.0:443", "-tls-cert", "c.pem", "-tls-key", "k.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestPublicOriginStripsPath(t *testing.T) {
	got, err := publicOrigin("https://host.example/")
	if err != nil || got != "https://host.example" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestInitAuthWritesLoginFileAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	var out bytes.Buffer
	if err := initAuth([]string{"-auth-file", path}, strings.NewReader("correct horse battery\n"), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "otpauth://totp/") {
		t.Fatalf("no authenticator URI printed: %s", out.String())
	}
	if err := issueClient([]string{"-auth-file", path, "-client-file", filepath.Join(t.TempDir(), "c.txt")}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	a, err := oauth.LoadAuthFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !a.CheckPassword("correct horse battery") {
		t.Fatal("saved password does not verify")
	}
	if err := initAuth([]string{"-auth-file", path}, strings.NewReader("another long password\n"), &out); err == nil {
		t.Fatal("expected refusal to overwrite without -force")
	}
}

func TestInitAuthRejectsShortPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := initAuth([]string{"-auth-file", path}, strings.NewReader("short\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("expected short password error")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("auth file written despite error")
	}
}

func TestIssueClientWritesPairAndSecretFile(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.json")
	clientPath := filepath.Join(dir, "client.txt")
	if err := initAuth([]string{"-auth-file", authPath}, strings.NewReader("correct horse battery\n"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := issueClient([]string{"-auth-file", authPath, "-client-file", clientPath}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "client_secret=") {
		t.Fatal("secret printed to stdout")
	}
	info, err := os.Stat(clientPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("client file mode: %v %v", info, err)
	}
	a, err := oauth.LoadAuthFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(clientPath)
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		fields[k] = v
	}
	if !a.CheckClient(fields["client_id"], fields["client_secret"]) {
		t.Fatal("written client pair does not verify against the auth file")
	}
	if fields["redirect_uris"] != oauth.GeminiRedirectURI {
		t.Fatalf("redirect_uris = %q", fields["redirect_uris"])
	}
}

func TestIssueClientNeedsLoginFirst(t *testing.T) {
	err := issueClient([]string{"-auth-file", filepath.Join(t.TempDir(), "missing.json"), "-client-file", filepath.Join(t.TempDir(), "c")}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error without a login file")
	}
}
