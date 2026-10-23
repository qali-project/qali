// Package httpserver assembles the single public HTTP handler: generated API
// routes, private probes, and the embedded single-page application
// (ADR-0003 route families).
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	"github.com/qali-project/qali/internal/platform/metrics"
)

//go:generate go tool -modfile=../../../tools/mod/oapi-codegen.mod oapi-codegen -config ../../../api/oapi-codegen.yaml -o openapi/openapi.gen.go ../../../api/openapi.yaml

// Route prefixes that never fall back to the application shell.
var reservedPrefixes = []string{"/api/", "/auth/", "/health/", "/internal/", "/mcp", "/assets/"}

// Options configures the root handler. Zero values select safe defaults.
type Options struct {
	// UI holds the built web bundle with index.html at its root.
	UI fs.FS
	// PublicURL is the external origin; unsafe browser requests must match it.
	PublicURL *url.URL
	// TrustedProxies may set X-Forwarded-For.
	TrustedProxies []netip.Prefix
	Clock          clock.Clock
	MaxBodyBytes   int64
	RateLimit      RateLimit
	Logger         *slog.Logger
	Metrics        metrics.Recorder
	// Ready reports whether dependencies are available; nil means always ready.
	Ready func(context.Context) error
	// API serves the feature operations of the OpenAPI contract; operations
	// it does not implement answer 501. Health operations stay here.
	API openapi.ServerInterface
	// APIMiddlewares wrap every contract operation after routing (for
	// example authentication), so Route(r) is available to them.
	APIMiddlewares []openapi.MiddlewareFunc
}

// Defaults applied by NewHandler.
const (
	DefaultMaxBodyBytes = 1 << 20
	defaultPerSecond    = 20
	defaultBurst        = 40
	readinessTimeout    = 2 * time.Second
)

// NewHandler returns the root handler with the middleware chain (outermost
// first): request ID, request log, security headers, panic recovery, rate
// limit, body limit, origin check, router.
func NewHandler(opts Options) http.Handler {
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.RateLimit.PerSecond <= 0 || opts.RateLimit.Burst <= 0 {
		opts.RateLimit = RateLimit{PerSecond: defaultPerSecond, Burst: defaultBurst}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.Nop{}
	}
	if opts.API == nil {
		opts.API = openapi.Unimplemented{}
	}

	r := chi.NewRouter()
	r.Use(captureRoute)
	openapi.HandlerWithOptions(api{ServerInterface: opts.API, ready: opts.Ready, logger: opts.Logger}, openapi.ChiServerOptions{
		BaseRouter:  r,
		Middlewares: opts.APIMiddlewares,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, _ error) {
			WriteProblem(w, r, http.StatusBadRequest, "invalid_parameter")
		},
	})
	r.NotFound(spa(opts.UI))

	var h http.Handler = r
	h = checkOrigin(h, opts.PublicURL)
	h = LimitBody(h, opts.MaxBodyBytes)
	h = newLimiter(opts.RateLimit, opts.Clock).middleware(h)
	h = withClientAddr(h, opts.TrustedProxies)
	h = recoverPanics(h, opts.Logger)
	h = securityHeaders(h, opts.PublicURL.Scheme == "https")
	h = logRequests(h, opts.Logger, opts.Metrics, opts.Clock)
	return withRequestID(h)
}

// api serves the platform's health operations and delegates everything else
// to the feature implementation.
type api struct {
	openapi.ServerInterface
	ready  func(context.Context) error
	logger *slog.Logger
}

var _ openapi.ServerInterface = api{}

// Route returns "METHOD /pattern" for the matched contract operation, or ""
// before routing.
func Route(r *http.Request) string {
	rc := chi.RouteContext(r.Context())
	if rc == nil || rc.RoutePattern() == "" {
		return ""
	}
	return r.Method + " " + rc.RoutePattern()
}

// GetReadiness exposes only ready/not_ready; the reason goes to the log.
func (a api) GetReadiness(w http.ResponseWriter, r *http.Request) {
	if a.ready != nil {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()
		if err := a.ready(ctx); err != nil {
			a.logger.Warn("not ready", "request_id", RequestID(r.Context()), "reason", err.Error())
			WriteJSON(w, http.StatusServiceUnavailable, openapi.Readiness{Status: openapi.NotReady})
			return
		}
	}
	WriteJSON(w, http.StatusOK, openapi.Readiness{Status: openapi.Ready})
}

func (api) GetLiveness(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, openapi.Liveness{Status: openapi.Ok})
}

// WriteJSON writes v as a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// spa serves static files from ui and falls back to index.html for client-side
// routes. Reserved prefixes and missing assets return 404.
func spa(ui fs.FS) http.HandlerFunc {
	files := http.FileServerFS(ui)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if isReserved(r.URL.Path) {
				WriteProblem(w, r, http.StatusNotFound, "not_found")
			} else {
				WriteProblem(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
			}
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if info, err := fs.Stat(ui, name); err == nil && !info.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		if isReserved(r.URL.Path) {
			WriteProblem(w, r, http.StatusNotFound, "not_found")
			return
		}
		index, err := fs.ReadFile(ui, "index.html")
		if errors.Is(err, fs.ErrNotExist) {
			WriteProblem(w, r, http.StatusServiceUnavailable, "web_bundle_missing")
			return
		}
		if err != nil {
			WriteProblem(w, r, http.StatusInternalServerError, "internal_error")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	}
}

func isReserved(p string) bool {
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
