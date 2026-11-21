package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxLoggedBody = 64 << 10
	redacted      = "REDACTED"
)

// authSecretFields are only secret on the login and token endpoints; on /mcp a "code" field is the TypeScript to run.
var authSecretFields = map[string]bool{"code": true}

// secretFields are never written to the log, in forms, query strings, JSON bodies or redirect URLs.
var secretFields = map[string]bool{
	"password": true, "totp": true, "client_secret": true, "code_verifier": true,
	"refresh_token": true, "access_token": true, "ticket": true, "id_token": true,
}

var secretHeaders = map[string]bool{"authorization": true, "cookie": true, "set-cookie": true, "proxy-authorization": true}

type recorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if room := maxLoggedBody - r.body.Len(); room > 0 {
		if len(p) <= room {
			r.body.Write(p)
		} else {
			r.body.Write(p[:room])
		}
	}
	return r.ResponseWriter.Write(p)
}

// Hijack keeps WebSocket-style upgrades working through the recorder, though this server doesn't use them.
func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

// logRequests writes one entry per request: method, full path and query (secrets redacted), request headers,
// request body, response status, response headers and response body. Secret values are replaced by "[redacted]".
func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqBody, _ := io.ReadAll(io.LimitReader(r.Body, maxLoggedBody))
		rest, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBody), bytes.NewReader(rest)))

		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		logger.Info("http",
			"method", r.Method,
			"url", scheme(r)+"://"+r.Host+redactQuery(r.URL, r.URL.Path),
			"remote", r.RemoteAddr,
			"req_headers", headers(r.Header),
			"req_body", redactBody(r.Header.Get("Content-Type"), reqBody, r.URL.Path),
			"status", rec.status,
			"resp_headers", headers(rec.Header()),
			"resp_body", redactBody(rec.Header().Get("Content-Type"), rec.body.Bytes(), r.URL.Path),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func headers(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if secretHeaders[strings.ToLower(k)] {
			out[k] = redacted
			continue
		}
		if strings.EqualFold(k, "Location") {
			out[k] = redactLocation(strings.Join(v, ", "))
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func redactLocation(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host + redactQuery(u, "/authorize")
}

func redactQuery(u *url.URL, path string) string {
	if u.RawQuery == "" {
		return u.Path
	}
	q := u.Query()
	for k := range q {
		if isSecretField(path, k) {
			q.Set(k, redacted)
		}
	}
	return u.Path + "?" + q.Encode()
}

func isSecretField(path, key string) bool {
	k := strings.ToLower(key)
	if secretFields[k] {
		return true
	}
	return authSecretFields[k] && path != "/mcp"
}

func redactBody(contentType string, body []byte, path string) string {
	if len(body) == 0 {
		return ""
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		q, err := url.ParseQuery(string(body))
		if err != nil {
			return "[unparseable form body]"
		}
		for k := range q {
			if isSecretField(path, k) {
				q.Set(k, redacted)
			}
		}
		return q.Encode()
	case strings.HasPrefix(ct, "application/json"):
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return string(body)
		}
		raw, _ := json.Marshal(redactValue(v, path))
		return string(raw)
	case strings.HasPrefix(ct, "text/html"):
		return "[html page]"
	}
	return string(body)
}

func redactValue(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isSecretField(path, k) {
				t[k] = redacted
			} else {
				t[k] = redactValue(val, path)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactValue(t[i], path)
		}
		return t
	}
	return v
}
