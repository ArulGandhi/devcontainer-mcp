package httpguard

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

type Options struct {
	AllowedOrigins []string
	RatePerSecond  float64
	Burst          int
	MaxBodyBytes   int64
}

// Wrap puts the checks every request passes before it reaches next: Origin allow-list, rate limit, body size cap.
// Authentication is the handler's job (the OAuth middleware guards the MCP endpoint).
func Wrap(next http.Handler, opt Options) (http.Handler, error) {
	switch {
	case opt.RatePerSecond <= 0:
		return nil, errors.New("rate limit must be positive")
	case opt.Burst <= 0:
		return nil, errors.New("burst must be positive")
	case opt.MaxBodyBytes <= 0:
		return nil, errors.New("max body bytes must be positive")
	}
	allowed := make(map[string]struct{}, len(opt.AllowedOrigins))
	for _, o := range opt.AllowedOrigins {
		allowed[o] = struct{}{}
	}
	limiter := newBucket(opt.RatePerSecond, opt.Burst, time.Now())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			if _, ok := allowed[origin]; !ok {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
		}
		if !limiter.take(time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, opt.MaxBodyBytes)
		next.ServeHTTP(w, r)
	}), nil
}

type bucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func newBucket(rate float64, capacity int, now time.Time) *bucket {
	return &bucket{tokens: float64(capacity), capacity: float64(capacity), rate: rate, last: now}
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(b.capacity, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
