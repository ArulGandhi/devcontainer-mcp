package httpguard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func newGuard(t *testing.T, opt Options) http.Handler {
	t.Helper()
	if opt.RatePerSecond == 0 {
		opt.RatePerSecond = 1000
	}
	if opt.Burst == 0 {
		opt.Burst = 1000
	}
	if opt.MaxBodyBytes == 0 {
		opt.MaxBodyBytes = 1 << 20
	}
	h, err := Wrap(okHandler(), opt)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func do(h http.Handler, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDisallowedOriginIsForbidden(t *testing.T) {
	h := newGuard(t, Options{AllowedOrigins: []string{"https://ok.example"}})
	rec := do(h, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestAllowedOriginPasses(t *testing.T) {
	h := newGuard(t, Options{AllowedOrigins: []string{"https://ok.example"}})
	rec := do(h, func(r *http.Request) { r.Header.Set("Origin", "https://ok.example") })
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestNoOriginHeaderPasses(t *testing.T) {
	if rec := do(newGuard(t, Options{}), nil); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRateLimitReturns429(t *testing.T) {
	h := newGuard(t, Options{Burst: 2, RatePerSecond: 0.001})
	codes := []int{}
	for range 3 {
		codes = append(codes, do(h, nil).Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v", codes)
	}
}

func TestBodyIsCapped(t *testing.T) {
	var readErr error
	reader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	h, err := Wrap(reader, Options{RatePerSecond: 1000, Burst: 1000, MaxBodyBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("x", 100)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr == nil {
		t.Fatal("body over the cap was read in full")
	}
}

func TestWrapRejectsZeroLimits(t *testing.T) {
	if _, err := Wrap(okHandler(), Options{Burst: 1, MaxBodyBytes: 1}); err == nil {
		t.Fatal("expected rate limit error")
	}
}
