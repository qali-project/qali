package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/qali-project/qali/internal/identity/oidc"
	"github.com/qali-project/qali/internal/platform/secret"
)

func TestConfigurationAndAuthorizationInputs(t *testing.T) {
	f := newIssuer(t)
	for _, tc := range []struct {
		name   string
		change func(*oidc.Config)
	}{
		{"issuer scheme", func(c *oidc.Config) { c.Issuer = "http://issuer.example" }},
		{"issuer query", func(c *oidc.Config) { c.Issuer += "?token=never" }},
		{"empty client", func(c *oidc.Config) { c.ClientID = "" }},
		{"long client", func(c *oidc.Config) { c.ClientID = strings.Repeat("x", 513) }},
		{"public path", func(c *oidc.Config) { c.PublicURL += "/untrusted/callback" }},
		{"public query", func(c *oidc.Config) { c.PublicURL += "?redirect_uri=https://other.example" }},
		{"public credentials", func(c *oidc.Config) { c.PublicURL = "https://user:password@qali.example" }},
		{"public malformed", func(c *oidc.Config) { c.PublicURL = "https://[invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := f.config()
			tc.change(&cfg)
			if c, err := oidc.New(cfg); !errors.Is(err, oidc.ErrInvalidConfig) {
				if c != nil {
					c.Close()
				}
				t.Fatalf("invalid configuration accepted: %v", err)
			}
		})
	}
	c := f.client(t)
	for _, tc := range []struct{ state, nonce, verifier string }{{"", "nonce", strings.Repeat("v", 43)}, {"state", "", strings.Repeat("v", 43)}, {"state", "nonce", "short"}, {"state", "nonce", strings.Repeat("v", 129)}, {"state", "nonce", strings.Repeat("v", 42) + "!"}, {strings.Repeat("s", 513), "nonce", strings.Repeat("v", 43)}} {
		if _, err := c.AuthorizationURL(context.Background(), tc.state, tc.nonce, tc.verifier); !errors.Is(err, oidc.ErrInvalidConfig) {
			t.Fatalf("invalid authorization input accepted: %v", err)
		}
	}
	if _, err := c.Exchange(context.Background(), "", strings.Repeat("v", 43), secret.New([]byte("fixture-only")), nonceMatches); !errors.Is(err, oidc.ErrInvalidConfig) {
		t.Fatalf("empty code: %v", err)
	}
	if _, err := c.Exchange(context.Background(), "code", strings.Repeat("v", 43), secret.Value{}, nonceMatches); !errors.Is(err, oidc.ErrInvalidConfig) {
		t.Fatalf("empty credential: %v", err)
	}
	cfg := f.config()
	cfg.Clock = nil
	defaultClock, err := oidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defaultClock.Close()
}

func TestPrivateIssuerDeniedByDefault(t *testing.T) {
	f := newIssuer(t)
	cfg := f.config()
	cfg.AllowPrivateIssuer = false
	c, err := oidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Discover(context.Background()); !errors.Is(err, oidc.ErrProviderUnavailable) {
		t.Fatalf("private issuer connected without operator opt-in: %v", err)
	}
}

func TestDiscoveryAndKeyCacheRefresh(t *testing.T) {
	f := newIssuer(t)
	c := f.client(t)
	if _, err := c.Validate(context.Background(), f.token, nonceMatches); err != nil {
		t.Fatal(err)
	}
	unknown := f.sign(t, jose.RS256, f.key, "unknown", f.claims())
	for range 8 {
		if _, err := c.Validate(context.Background(), unknown, nonceMatches); !errors.Is(err, oidc.ErrInvalidToken) {
			t.Fatalf("unknown kid accepted: %v", err)
		}
	}
	f.mu.Lock()
	requests := f.keyRequests
	f.mu.Unlock()
	if requests != 1 {
		t.Fatalf("key refresh was not throttled: %d", requests)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.keys = append(f.keys, jose.JSONWebKey{Key: &other.PublicKey, KeyID: "rotated", Algorithm: "RS256", Use: "sig"})
	f.document["issuer"] = "https://invalid.example"
	f.mu.Unlock()
	f.clock.Advance(time.Minute)
	rotated := f.sign(t, jose.RS256, other, "rotated", f.claims())
	if _, err := c.Validate(context.Background(), rotated, nonceMatches); err != nil {
		t.Fatalf("rotated key not refreshed: %v", err)
	}
	f.mu.Lock()
	requests = f.keyRequests
	f.mu.Unlock()
	if requests != 2 {
		t.Fatalf("expected exactly one rotation refresh: %d", requests)
	}
	if err := c.Discover(context.Background()); err != nil {
		t.Fatalf("cached discovery not reused: %v", err)
	}
	f.clock.Advance(time.Hour)
	if err := c.Discover(context.Background()); !errors.Is(err, oidc.ErrInvalidConfig) {
		t.Fatalf("discovery not revalidated at expiry: %v", err)
	}
}

func TestValidationIsConcurrent(t *testing.T) {
	f := newIssuer(t)
	c := f.client(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			identity, err := c.Validate(context.Background(), f.token, nonceMatches)
			if err != nil || identity.Subject != "subject-1" {
				t.Errorf("concurrent validation: %+v %v", identity, err)
			}
		})
	}
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keyRequests != 1 {
		t.Fatalf("expected one JWKS fetch: %d", f.keyRequests)
	}
}

func TestProviderOutageCancellationAndBoundedResponses(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		f := newIssuer(t)
		c := f.client(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := c.Discover(ctx); !errors.Is(err, oidc.ErrProviderUnavailable) {
			t.Fatalf("cancelled request: %v", err)
		}
	})
	t.Run("outage", func(t *testing.T) {
		f := newIssuer(t)
		c := f.client(t)
		f.server.Close()
		if err := c.Discover(context.Background()); !errors.Is(err, oidc.ErrProviderUnavailable) {
			t.Fatalf("outage: %v", err)
		}
	})
	t.Run("large discovery", func(t *testing.T) {
		f := newIssuer(t)
		f.document["padding"] = strings.Repeat("x", 1<<20)
		if err := f.client(t).Discover(context.Background()); !errors.Is(err, oidc.ErrProviderUnavailable) {
			t.Fatalf("large discovery accepted: %v", err)
		}
	})
	t.Run("large JWKS", func(t *testing.T) {
		f := newIssuer(t)
		f.keys[0].KeyID = strings.Repeat("x", 1<<20)
		if _, err := f.client(t).Validate(context.Background(), f.token, nonceMatches); !errors.Is(err, oidc.ErrInvalidToken) {
			t.Fatalf("large JWKS accepted: %v", err)
		}
	})
}
