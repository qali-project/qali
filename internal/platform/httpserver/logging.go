package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/metrics"
)

type routeKey struct{}

// route holds the matched chi pattern so outer middleware can log it.
type route struct{ pattern string }

// statusWriter records the response status.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests writes one structured line per request: request ID, method,
// route pattern, status, and duration. It never logs paths with identifiers,
// query strings, headers, or bodies. Probes log at debug level.
func logRequests(next http.Handler, logger *slog.Logger, rec metrics.Recorder, c clock.Clock) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := c.Now()
		matched := &route{}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), routeKey{}, matched)))

		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		pattern := matched.pattern
		if pattern == "" || pattern == "/*" {
			pattern = "unmatched"
		}
		elapsed := c.Now().Sub(start)
		level := slog.LevelInfo
		if strings.HasPrefix(r.URL.Path, "/health/") {
			level = slog.LevelDebug
		}
		logger.LogAttrs(r.Context(), level, "http request",
			slog.String("request_id", RequestID(r.Context())),
			slog.String("method", r.Method),
			slog.String("route", pattern),
			slog.Int("status", status),
			slog.Float64("duration_ms", float64(elapsed.Microseconds())/1000),
		)
		rec.Count("http_requests_total", metrics.Labels{"method": r.Method, "route": pattern, "status": strconv.Itoa(status)})
		rec.Observe("http_request_duration_seconds", elapsed.Seconds(), metrics.Labels{"route": pattern})
	})
}

// captureRoute runs inside the chi router and stores the matched pattern.
func captureRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if matched, ok := r.Context().Value(routeKey{}).(*route); ok {
			if rc := chi.RouteContext(r.Context()); rc != nil {
				matched.pattern = rc.RoutePattern()
			}
		}
	})
}
