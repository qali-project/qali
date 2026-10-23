package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
)

type requestIDKey struct{}

// RequestID returns the server-generated ID of the request in ctx.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRequestID assigns every request a fresh random ID. Client-supplied
// X-Request-ID values are ignored so they cannot forge log correlation.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		_, _ = rand.Read(b) // crypto/rand.Read never returns an error
		id := hex.EncodeToString(b)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// StatusClientClosedRequest records requests the client abandoned (nginx
// convention); the response is never seen by the client.
const StatusClientClosedRequest = 499

// WriteProblem writes RFC 9457 problem details (ADR-0003). code is a stable
// snake_case identifier; no internal detail is ever included.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openapi.Problem{
		Type:      "about:blank",
		Title:     http.StatusText(status),
		Status:    status,
		Code:      code,
		RequestId: RequestID(r.Context()),
	})
}

// recoverPanics turns a panic into a generic 500 problem. Details go to the
// log with the request ID, never to the client.
func recoverPanics(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared as documented by net/http
				panic(v)
			}
			logger.Error("handler panic", "request_id", RequestID(r.Context()), "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
			WriteProblem(w, r, http.StatusInternalServerError, "internal_error")
		}()
		next.ServeHTTP(w, r)
	})
}

const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
	"form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"

func securityHeaders(next http.Handler, https bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if https {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/health/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// LimitBody rejects declared bodies above limit and caps undeclared ones while
// they are read. Handlers report read errors with WriteBodyError.
func LimitBody(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// DecodeJSON strictly decodes one JSON object from the request body into dst:
// unknown fields, trailing data, and malformed input answer 400, oversized
// bodies 413. It reports whether decoding succeeded; on failure the response
// has been written.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		WriteBodyError(w, r, err)
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		WriteBodyError(w, r, errors.New("trailing data after the JSON object"))
		return false
	}
	return true
}

// WriteBodyError maps a request-body read error to a problem response.
func WriteBodyError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteProblem(w, r, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	WriteProblem(w, r, http.StatusBadRequest, "invalid_body")
}

// checkOrigin rejects unsafe browser requests that do not prove they come from
// the application's own origin (Fetch Metadata, Origin, then Referer).
// Requests with an Authorization header carry explicit, non-ambient
// credentials and are exempt; session-bound CSRF tokens are added in MVP-04.
func checkOrigin(next http.Handler, public *url.URL) http.Handler {
	origin := strings.ToLower(public.Scheme + "://" + public.Host)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" || sameOrigin(r, origin) {
			next.ServeHTTP(w, r)
			return
		}
		WriteProblem(w, r, http.StatusForbidden, "cross_site_request")
	})
}

func sameOrigin(r *http.Request, origin string) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		return strings.ToLower(o) == origin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && strings.ToLower(u.Scheme+"://"+u.Host) == origin
	}
	return false
}

// RateLimit is a per-client token bucket.
type RateLimit struct {
	PerSecond float64
	Burst     int
}

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	clock   clock.Clock
	rate    float64
	burst   float64
	buckets map[netip.Addr]*bucket
	calls   int
}

func newLimiter(cfg RateLimit, c clock.Clock) *limiter {
	return &limiter{clock: c, rate: cfg.PerSecond, burst: float64(cfg.Burst), buckets: map[netip.Addr]*bucket{}}
}

type clientAddrKey struct{}

// ClientAddr returns the client address resolved from the peer and trusted
// proxies (see clientAddr).
func ClientAddr(ctx context.Context) netip.Addr {
	addr, _ := ctx.Value(clientAddrKey{}).(netip.Addr)
	return addr
}

func withClientAddr(next http.Handler, trusted []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), clientAddrKey{}, clientAddr(r, trusted))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// allow takes one token for addr, or returns how long until one is available.
func (l *limiter) allow(addr netip.Addr) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	l.calls++
	if l.calls%1024 == 0 {
		l.evictFull(now)
	}
	b, ok := l.buckets[addr]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[addr] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// evictFull drops buckets that have refilled completely; they carry no state.
func (l *limiter) evictFull(now time.Time) {
	for addr, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, addr)
		}
	}
}

func (l *limiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/health/") {
			next.ServeHTTP(w, r)
			return
		}
		ok, wait := l.allow(ClientAddr(r.Context()))
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			WriteProblem(w, r, http.StatusTooManyRequests, "rate_limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientAddr returns the peer address, or, when the peer is a trusted proxy,
// the right-most X-Forwarded-For address that is not itself a trusted proxy.
func clientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if !isTrusted(peer, trusted) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if addr = addr.Unmap(); !isTrusted(addr, trusted) {
			return addr
		}
	}
	return peer
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
