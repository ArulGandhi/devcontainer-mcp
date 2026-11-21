package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func echoTool() Tool {
	return Tool{
		Name:        "echo",
		Description: "echo the text argument",
		InputSchema: map[string]any{"type": "object"},
		Run: func(_ context.Context, args json.RawMessage) (string, error) {
			var a struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return "", fmt.Errorf("%w: %v", ErrInvalidParams, err)
			}
			return a.Text, nil
		},
	}
}

func newServer(t *testing.T, slots int, tools ...Tool) *Server {
	t.Helper()
	s, err := NewServer(tools, discard(), slots)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func send(t *testing.T, s *Server, body string) map[string]any {
	t.Helper()
	resp := s.Handle(context.Background(), []byte(body))
	if resp == nil {
		return nil
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func errorCode(t *testing.T, msg map[string]any) float64 {
	t.Helper()
	e, ok := msg["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error reply, got %v", msg)
	}
	return e["code"].(float64)
}

func TestInitializeEchoesSupportedVersion(t *testing.T) {
	s := newServer(t, 1)
	out := send(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	got := out["result"].(map[string]any)["protocolVersion"]
	if got != "2025-03-26" {
		t.Fatalf("protocolVersion = %v", got)
	}
}

func TestInitializeFallsBackToLatestVersion(t *testing.T) {
	s := newServer(t, 1)
	out := send(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if got := out["result"].(map[string]any)["protocolVersion"]; got != ProtocolVersion {
		t.Fatalf("protocolVersion = %v, want %s", got, ProtocolVersion)
	}
}

func TestNotificationGetsNoReply(t *testing.T) {
	s := newServer(t, 1)
	if out := send(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); out != nil {
		t.Fatalf("notification must not be answered, got %v", out)
	}
}

func TestClientResponseGetsNoReply(t *testing.T) {
	s := newServer(t, 1)
	if out := send(t, s, `{"jsonrpc":"2.0","id":5,"result":{}}`); out != nil {
		t.Fatalf("client response must not be answered, got %v", out)
	}
}

func TestBatchIsRejected(t *testing.T) {
	s := newServer(t, 1, echoTool())
	out := send(t, s, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	if code := errorCode(t, out); code != codeInvalidRequest {
		t.Fatalf("code = %v", code)
	}
}

func TestParseErrorIsReported(t *testing.T) {
	s := newServer(t, 1)
	if code := errorCode(t, send(t, s, `{"jsonrpc":`)); code != codeParseError {
		t.Fatalf("code = %v", code)
	}
}

func TestUnknownMethodIsReported(t *testing.T) {
	s := newServer(t, 1)
	if code := errorCode(t, send(t, s, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)); code != codeMethodNotFound {
		t.Fatalf("code = %v", code)
	}
}

func TestToolsListExposesSchemas(t *testing.T) {
	s := newServer(t, 1, echoTool())
	out := send(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	tools := out["result"].(map[string]any)["tools"].([]any)
	first := tools[0].(map[string]any)
	if first["name"] != "echo" || first["inputSchema"] == nil {
		t.Fatalf("tools/list = %v", tools)
	}
}

func TestToolsCallReturnsText(t *testing.T) {
	s := newServer(t, 1, echoTool())
	out := send(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`)
	result := out["result"].(map[string]any)
	content := result["content"].([]any)[0].(map[string]any)
	if content["text"] != "hi" || result["isError"] != false {
		t.Fatalf("result = %v", result)
	}
}

func TestUnknownToolIsInvalidParams(t *testing.T) {
	s := newServer(t, 1, echoTool())
	out := send(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope"}}`)
	if code := errorCode(t, out); code != codeInvalidParams {
		t.Fatalf("code = %v", code)
	}
}

func TestBadArgumentsAreInvalidParams(t *testing.T) {
	s := newServer(t, 1, echoTool())
	out := send(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":[1]}}`)
	if code := errorCode(t, out); code != codeInvalidParams {
		t.Fatalf("code = %v", code)
	}
}

func TestToolFailureIsReportedInResult(t *testing.T) {
	failing := Tool{
		Name: "fail",
		Run: func(context.Context, json.RawMessage) (string, error) {
			return "", errors.New("boom")
		},
	}
	s := newServer(t, 1, failing)
	out := send(t, s, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fail"}}`)
	result := out["result"].(map[string]any)
	if result["isError"] != true || !strings.Contains(fmt.Sprint(result), "boom") {
		t.Fatalf("result = %v", result)
	}
}

func TestBusyWhenConcurrencySlotsAreFull(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	blocking := Tool{
		Name: "block",
		Run: func(context.Context, json.RawMessage) (string, error) {
			close(started)
			<-release
			return "done", nil
		},
	}
	s := newServer(t, 1, blocking)
	done := make(chan map[string]any)
	go func() {
		done <- send(t, s, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"block"}}`)
	}()
	<-started
	out := send(t, s, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"block"}}`)
	result := out["result"].(map[string]any)
	if result["isError"] != true || !strings.Contains(fmt.Sprint(result), "busy") {
		t.Fatalf("second call should be refused as busy, got %v", result)
	}
	close(release)
	<-done
}

func TestHTTPRejectsGET(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Path, nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("status %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestHTTPRejectsOtherPaths(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/other", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHTTPRejectsWrongContentType(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHTTPRejectsUnsupportedProtocolHeader(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "1999-01-01")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHTTPNotificationReturnsAccepted(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
}

func TestHTTPPingReturnsJSON(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestHTTPAcceptsNewerSpecVersionHeader(t *testing.T) {
	h := newServer(t, 1).HTTPHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}
