package httpserver_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
)

const indexHTML = `<!doctype html><html><body><div id="root"></div></body></html>`

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	ui := fstest.MapFS{
		"index.html":    {Data: []byte(indexHTML)},
		"assets/app.js": {Data: []byte("console.log('app')")},
	}
	opts := options(t)
	opts.UI = ui
	srv := httptest.NewServer(httpserver.NewHandler(opts))
	t.Cleanup(srv.Close)
	return srv
}

type response struct {
	StatusCode int
	Header     http.Header
}

func get(t *testing.T, srv *httptest.Server, method, path string) (response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Unsafe methods need same-origin evidence since MVP-02 (SECURITY_ARCHITECTURE 6).
	req.Header.Set("Origin", publicOrigin)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	if closeErr := res.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	return response{StatusCode: res.StatusCode, Header: res.Header}, string(body)
}

func TestLivenessReturnsContractShape(t *testing.T) {
	res, body := get(t, newServer(t), http.MethodGet, "/health/live")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got openapi.Liveness
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("body %q does not match the Liveness schema: %v", body, err)
	}
	if got.Status != openapi.Ok {
		t.Fatalf("status field = %q, want %q", got.Status, openapi.Ok)
	}
}

func TestLivenessRejectsOtherMethods(t *testing.T) {
	res, _ := get(t, newServer(t), http.MethodPost, "/health/live")
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", res.StatusCode)
	}
}

func TestSinglePageApplicationRoutes(t *testing.T) {
	srv := newServer(t)
	for _, path := range []string{"/", "/projects/abc", "/index.html"} {
		res, body := get(t, srv, http.MethodGet, path)
		if res.StatusCode != http.StatusOK || body != indexHTML {
			t.Fatalf("GET %s = %d %q, want 200 index.html", path, res.StatusCode, body)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("GET %s Content-Type = %q, want text/html", path, ct)
		}
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	res, body := get(t, newServer(t), http.MethodGet, "/assets/app.js")
	if res.StatusCode != http.StatusOK || body != "console.log('app')" {
		t.Fatalf("GET /assets/app.js = %d %q", res.StatusCode, body)
	}
}

func TestUnknownAPIAndProbeRoutesAreNotServedTheApplication(t *testing.T) {
	srv := newServer(t)
	for _, path := range []string{"/api/v1/unknown", "/health/other", "/mcp", "/internal/metrics", "/assets/missing.js"} {
		res, body := get(t, srv, http.MethodGet, path)
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, res.StatusCode)
		}
		if strings.Contains(body, "<html") {
			t.Fatalf("GET %s returned the application shell", path)
		}
	}
}

func TestMissingWebBuildIsReportedNotPanicking(t *testing.T) {
	opts := options(t)
	opts.UI = fstest.MapFS{}
	srv := httptest.NewServer(httpserver.NewHandler(opts))
	t.Cleanup(srv.Close)
	res, _ := get(t, srv, http.MethodGet, "/")
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the web bundle is absent", res.StatusCode)
	}
	live, _ := get(t, srv, http.MethodGet, "/health/live")
	if live.StatusCode != http.StatusOK {
		t.Fatalf("liveness must not depend on the web bundle, got %d", live.StatusCode)
	}
}
