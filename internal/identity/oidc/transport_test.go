package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/platform/clock"
)

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDialChecksEveryAnswerAndPinsIP(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.2", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "250.0.0.1", "::1", "::", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2001:db8::1", "fe80::1%lo"} {
		t.Run(address, func(t *testing.T) {
			calls := 0
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(address)}, nil
			}
			dial := func(context.Context, string, string) (net.Conn, error) {
				calls++
				return nil, errors.New("unexpected dial")
			}
			if _, err := dialChecked(context.Background(), "tcp", "issuer.example:443", "issuer.example", false, lookup, dial); !errors.Is(err, ErrUnsafeEndpoint) || calls != 0 {
				t.Fatalf("unsafe/mixed DNS answer: %v, dials=%d", err, calls)
			}
		})
	}
	for _, address := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(address)}, nil
		}
		left, right := net.Pipe()
		dial := func(_ context.Context, _ string, got string) (net.Conn, error) {
			if got != net.JoinHostPort(address, "443") {
				t.Fatalf("DNS not pinned: %q", got)
			}
			return left, nil
		}
		conn, err := dialChecked(context.Background(), "tcp", "issuer.example:443", "issuer.example", false, lookup, dial)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		_ = right.Close()
	}
}

func TestPrivateOptInIsHostBound(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	dial := func(context.Context, string, string) (net.Conn, error) { return left, nil }
	conn, err := dialChecked(context.Background(), "tcp", "issuer.local:443", "issuer.local", true, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := dialChecked(context.Background(), "tcp", "another.local:443", "issuer.local", true, lookup, dial); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("private bypass escaped issuer host: %v", err)
	}
	if _, err := dialChecked(context.Background(), "tcp", "invalid", "issuer.local", true, lookup, dial); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("invalid address: %v", err)
	}
	failedLookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("resolver failure")
	}
	if _, err := dialChecked(context.Background(), "tcp", "issuer.local:443", "issuer.local", true, failedLookup, dial); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal(err)
	}
	failedDial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failure") }
	if _, err := dialChecked(context.Background(), "tcp", "issuer.local:443", "issuer.local", true, lookup, failedDial); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatal(err)
	}
}

func TestDialRechecksDNSOnEveryConnection(t *testing.T) {
	lookups, dials := 0, 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
		dials++
		if address != "8.8.8.8:443" {
			t.Fatalf("unchecked destination: %s", address)
		}
		return left, nil
	}
	conn, err := dialChecked(context.Background(), "tcp", "issuer.example:443", "issuer.example", false, lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := dialChecked(context.Background(), "tcp", "issuer.example:443", "issuer.example", false, lookup, dial); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("DNS rebinding was allowed: %v", err)
	}
	if lookups != 2 || dials != 1 {
		t.Fatalf("lookups=%d dials=%d", lookups, dials)
	}
}

func TestTransportLimitsAndPolicy(t *testing.T) {
	for _, tc := range []struct {
		address     string
		development bool
		valid       bool
	}{{"http://localhost", true, true}, {"http://127.0.0.1", true, true}, {"http://[::1]", true, true}, {"http://localhost", false, false}, {"http://public.example", true, false}, {"https://example.org/#fragment", false, false}, {"https://user:secret@example.org", false, false}, {"https://example.org", false, true}} {
		_, err := endpoint(tc.address, tc.development)
		if (err == nil) != tc.valid {
			t.Errorf("endpoint %s: %v", tc.address, err)
		}
	}
	transport := newTransport(Config{}, "issuer.example")
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.MaxResponseHeaderBytes > 32<<10 {
		t.Fatal("unbounded or unsafe HTTP transport")
	}
	for _, tc := range []struct {
		name      string
		body      string
		wantError bool
	}{{"at limit", strings.Repeat("x", responseLimit), false}, {"over limit", strings.Repeat("x", responseLimit+1), true}} {
		t.Run(tc.name, func(t *testing.T) {
			base := roundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://issuer.example", nil)
			response, err := (boundedTransport{base: base}).RoundTrip(r)
			if (err != nil) != tc.wantError {
				t.Fatalf("size bound: %v", err)
			}
			if response != nil {
				_ = response.Body.Close()
			}
		})
	}
	manual := clock.NewManual(time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC))
	calls := 0
	base := roundTripper(func(*http.Request) (*http.Response, error) { calls++; return nil, ErrProviderUnavailable })
	limited := &keyTransport{base: base, clock: manual, last: make(map[string]time.Time)}
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://issuer.example/keys", nil)
	for range 4 {
		response, err := limited.RoundTrip(r)
		if response != nil {
			_ = response.Body.Close()
		}
		if !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("expected failed/throttled request: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("failed fetches not rate limited: %d", calls)
	}
	manual.Advance(time.Minute)
	response, err := limited.RoundTrip(r)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("expected boundary failure: %v", err)
	}
	if calls != 2 {
		t.Fatal("refresh did not resume after one minute")
	}
}
