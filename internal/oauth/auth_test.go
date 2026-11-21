package oauth

import (
	"strings"
	"testing"
)

func TestWithClientIssuesVerifiableSecret(t *testing.T) {
	auth, clientID, secret, err := mustAuth(t).WithClient([]string{GeminiRedirectURI})
	if err != nil {
		t.Fatal(err)
	}
	if clientID == "" || secret == "" {
		t.Fatal("empty credentials issued")
	}
	if !auth.CheckClient(clientID, secret) {
		t.Fatal("issued pair does not verify")
	}
	if auth.CheckClient(clientID, secret+"x") || auth.CheckClient("other", secret) {
		t.Fatal("wrong client credentials verified")
	}
}

func TestWithClientRejectsBadRedirects(t *testing.T) {
	for _, uri := range []string{"", "http://evil.example/cb", "https://x.test/cb#frag"} {
		if _, _, _, err := mustAuth(t).WithClient([]string{uri}); err == nil {
			t.Errorf("redirect %q accepted", uri)
		}
	}
	if _, _, _, err := mustAuth(t).WithClient(nil); err == nil {
		t.Error("no redirects accepted")
	}
}

func TestValidateRequiresClient(t *testing.T) {
	err := mustAuth(t).Validate()
	if err == nil || !strings.Contains(err.Error(), "issue-client") {
		t.Fatalf("err = %v", err)
	}
}

func mustAuth(t *testing.T) AuthFile {
	t.Helper()
	a, err := NewAuthFile(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
