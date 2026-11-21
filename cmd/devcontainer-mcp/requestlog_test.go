package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactBodyFormHidesSecrets(t *testing.T) {
	got := redactBody("application/x-www-form-urlencoded", []byte("grant_type=authorization_code&code=abc&code_verifier=xyz&password=hunter2&totp=123456&client_id=c1"), "/token")
	for _, secret := range []string{"abc", "xyz", "hunter2", "123456"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q leaked: %s", secret, got)
		}
	}
	if !strings.Contains(got, "client_id=c1") || !strings.Contains(got, "grant_type=authorization_code") {
		t.Fatalf("non-secret fields dropped: %s", got)
	}
}

func TestRedactBodyJSONHidesTokens(t *testing.T) {
	got := redactBody("application/json", []byte(`{"access_token":"A1","refresh_token":"R1","nested":{"client_secret":"S1"},"expires_in":3600}`), "/token")
	for _, secret := range []string{"A1", "R1", "S1"} {
		if strings.Contains(got, secret) {
			t.Fatalf("secret %q leaked: %s", secret, got)
		}
	}
	if !strings.Contains(got, "3600") {
		t.Fatalf("expires_in dropped: %s", got)
	}
}

func TestRedactLocationHidesCode(t *testing.T) {
	got := redactLocation("https://client.test/cb?code=SECRETCODE&state=xyz")
	if strings.Contains(got, "SECRETCODE") || !strings.Contains(got, "state=xyz") {
		t.Fatalf("location = %s", got)
	}
}

func TestLogRequestsRecordsFullExchangeWithoutSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	h := logRequests(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"TOPSECRET","token_type":"Bearer"}`))
	}))
	req := httptest.NewRequest(http.MethodPost, "/token?x=1", strings.NewReader("grant_type=refresh_token&refresh_token=RSECRET"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic c2VjcmV0")
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	for _, secret := range []string{"RSECRET", "TOPSECRET", "c2VjcmV0"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret %q in log: %s", secret, out)
		}
	}
	for _, want := range []string{`"method":"POST"`, `"status":200`, `Bearer`, `http://example.com/token?x=1`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %s: %s", want, out)
		}
	}
}

func TestMCPBodyKeepsReplCode(t *testing.T) {
	got := redactBody("application/json", []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"repl","arguments":{"code":"console.log(1)"}}}`), "/mcp")
	if !strings.Contains(got, "console.log(1)") {
		t.Fatalf("repl code was redacted: %s", got)
	}
}
