package oidc

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/qali-project/qali/internal/platform/clock"
)

func localHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2001:2::/48", "2001:db8::/32", "2002::/16"} {
		if netip.MustParsePrefix(prefix).Contains(address) {
			return false
		}
	}
	return true
}

func newTransport(cfg Config, issuerHost string) *http.Transport {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.Roots != nil {
		tlsConfig.RootCAs = cfg.Roots.Clone()
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		// No environment proxy: every connection must use the checked IP below.
		TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: time.Minute, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialChecked(ctx, network, address, issuerHost, cfg.AllowPrivateIssuer, net.DefaultResolver.LookupNetIP, dialer.DialContext)
		},
	}
}

func dialChecked(ctx context.Context, network, address, issuerHost string, allowPrivate bool, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrUnsafeEndpoint
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, ErrProviderUnavailable
	}
	privateAllowed := allowPrivate && strings.EqualFold(host, issuerHost)
	// Validate the whole DNS answer, then pin the connection to its numeric IP.
	if err := checkAddresses(ips, privateAllowed); err != nil {
		return nil, err
	}
	for _, ip := range ips {
		conn, dialErr := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
	}
	return nil, ErrProviderUnavailable
}

func checkAddresses(ips []netip.Addr, privateAllowed bool) error {
	for _, ip := range ips {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || (!privateAllowed && !publicAddress(ip)) {
			return ErrUnsafeEndpoint
		}
	}
	return nil
}

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	validScheme := req.URL.Scheme == "https" || req.URL.Scheme == "http" && localHost(req.URL.Hostname())
	if req.URL.User != nil || req.URL.Fragment != "" || !validScheme {
		return nil, ErrUnsafeEndpoint
	}
	response, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || len(body) > responseLimit {
		return nil, ErrProviderUnavailable
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

// keyTransport bounds unknown-kid refreshes, including failed requests. The
// issuer's remote key set still performs signature verification and caching.
type keyTransport struct {
	base  http.RoundTripper
	clock clock.Clock
	mu    sync.Mutex
	last  map[string]time.Time
}

func (t *keyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	now := t.clock.Now()
	last, exists := t.last[req.URL.String()]
	if exists && now.Before(last.Add(time.Minute)) {
		t.mu.Unlock()
		return nil, ErrProviderUnavailable
	}
	t.last[req.URL.String()] = now
	t.mu.Unlock()
	return t.base.RoundTrip(req)
}
