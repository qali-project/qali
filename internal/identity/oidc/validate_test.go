package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/qali-project/qali/internal/identity/oidc"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/secret"
)

// fixtureIssuer exercises the real HTTP, OAuth, and signature boundaries.
// It is local, uses ephemeral keys, and never depends on an external IdP.
type fixtureIssuer struct {
	server        *httptest.Server
	key           *rsa.PrivateKey
	clock         *clock.Manual
	mu            sync.Mutex
	document      map[string]any
	token         string
	keys          []jose.JSONWebKey
	keyRequests   int
	codeUsed      bool
	postAuth      bool
	redirectToken bool
}

func newIssuer(t *testing.T) *fixtureIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixtureIssuer{key: key, clock: clock.NewManual(time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC))}
	f.keys = []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "first", Algorithm: "RS256", Use: "sig"}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(f.document)
		case "/keys":
			f.keyRequests++
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: f.keys})
		case "/token":
			if f.redirectToken {
				w.Header().Set("Location", f.server.URL+"/keys")
				w.WriteHeader(http.StatusFound)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			id, credential, basic := r.BasicAuth()
			validAuth := basic && id == "test-client" && credential == "fixture-only"
			if f.postAuth {
				validAuth = !basic && r.Form.Get("client_id") == "test-client" && r.Form.Get("client_secret") == "fixture-only"
			}
			if !validAuth || f.codeUsed || r.Form.Get("code") != "one-use-code" || r.Form.Get("code_verifier") != strings.Repeat("v", 43) || r.Form.Get("redirect_uri") != "https://qali.example/api/v1/auth/oidc/callback" || r.Form.Get("grant_type") != "authorization_code" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"fixture-sensitive-detail"}`))
				return
			}
			f.codeUsed = true
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "discard-access", "refresh_token": "discard-refresh", "token_type": "Bearer", "id_token": f.token})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)
	f.document = map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}}
	f.token = f.sign(t, jose.RS256, key, "first", f.claims())
	return f
}

func (f *fixtureIssuer) config() oidc.Config {
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	return oidc.Config{Issuer: f.server.URL, ClientID: "test-client", PublicURL: "https://qali.example", AllowPrivateIssuer: true, Roots: roots, Clock: f.clock}
}

func (f *fixtureIssuer) client(t *testing.T) *oidc.Client {
	t.Helper()
	c, err := oidc.New(f.config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func (f *fixtureIssuer) claims() map[string]any {
	return map[string]any{"iss": f.server.URL, "sub": "subject-1", "aud": "test-client", "iat": f.clock.Now().Unix(), "exp": f.clock.Now().Add(5 * time.Minute).Unix(), "nonce": "browser-nonce", "email": "member@example.org", "email_verified": true, "name": "Member"}
}

func (f *fixtureIssuer) sign(t *testing.T, algorithm jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nonceMatches(s string) bool { return s == "browser-nonce" }

func TestIDTokenValidation(t *testing.T) {
	f := newIssuer(t)
	c := f.client(t)
	claims, err := c.Validate(context.Background(), f.token, nonceMatches)
	if err != nil || claims.Subject != "subject-1" || claims.Issuer != f.server.URL || !claims.EmailVerified || claims.Email != "member@example.org" {
		t.Fatalf("valid identity: %+v, %v", claims, err)
	}
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"issuer", func(m map[string]any) { m["iss"] = "https://another.example" }},
		{"audience", func(m map[string]any) { m["aud"] = "another-client" }},
		{"multiple audiences without azp", func(m map[string]any) { m["aud"] = []string{"test-client", "another"} }},
		{"wrong azp", func(m map[string]any) { m["azp"] = "another-client" }},
		{"nonce", func(m map[string]any) { m["nonce"] = "wrong" }},
		{"missing nonce", func(m map[string]any) { delete(m, "nonce") }},
		{"missing subject", func(m map[string]any) { delete(m, "sub") }},
		{"expired", func(m map[string]any) { m["exp"] = f.clock.Now().Add(-61 * time.Second).Unix() }},
		{"future issued", func(m map[string]any) { m["iat"] = f.clock.Now().Add(61 * time.Second).Unix() }},
		{"not yet valid", func(m map[string]any) { m["nbf"] = f.clock.Now().Add(61 * time.Second).Unix() }},
		{"missing expiry", func(m map[string]any) { delete(m, "exp") }},
		{"missing issued", func(m map[string]any) { delete(m, "iat") }},
		{"invalid lifetime", func(m map[string]any) { m["exp"] = f.clock.Now().Add(-30 * time.Second).Unix() }},
		{"untyped email verification", func(m map[string]any) { m["email_verified"] = "true" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := f.claims()
			tc.change(m)
			raw := f.sign(t, jose.RS256, f.key, "first", m)
			if _, err := c.Validate(context.Background(), raw, nonceMatches); !errors.Is(err, oidc.ErrInvalidToken) {
				t.Fatalf("accepted invalid token: %v", err)
			}
		})
	}
	for name, raw := range map[string]string{"malformed": "not-a-jwt", "none": "eyJhbGciOiJub25lIn0.e30.", "HS256": f.sign(t, jose.HS256, []byte(strings.Repeat("x", 32)), "first", f.claims())} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Validate(context.Background(), raw, nonceMatches); !errors.Is(err, oidc.ErrInvalidToken) {
				t.Fatalf("accepted invalid signature: %v", err)
			}
		})
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Validate(context.Background(), f.sign(t, jose.RS256, other, "first", f.claims()), nonceMatches); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("forged token: %v", err)
	}
	if _, err := c.Validate(context.Background(), f.token, nil); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("missing nonce validator: %v", err)
	}
	if _, err := c.Validate(context.Background(), strings.Repeat("x", (1<<20)+1), nonceMatches); !errors.Is(err, oidc.ErrInvalidToken) {
		t.Fatalf("oversized token: %v", err)
	}
}

func TestSupportedAlgorithmsAndClockSkew(t *testing.T) {
	f := newIssuer(t)
	c := f.client(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.keys = append(f.keys, jose.JSONWebKey{Key: &ec.PublicKey, KeyID: "ec", Use: "sig", Algorithm: "ES256"})
	f.mu.Unlock()
	for _, tc := range []struct {
		alg jose.SignatureAlgorithm
		key any
		kid string
	}{{jose.RS256, f.key, "first"}, {jose.PS256, f.key, "first"}, {jose.ES256, ec, "ec"}} {
		m := f.claims()
		m["aud"] = []string{"another", "test-client"}
		m["azp"] = "test-client"
		m["exp"] = f.clock.Now().Add(-59 * time.Second).Unix()
		m["iat"] = f.clock.Now().Add(-time.Hour).Unix()
		m["nbf"] = f.clock.Now().Add(59 * time.Second).Unix()
		if _, err := c.Validate(context.Background(), f.sign(t, tc.alg, tc.key, tc.kid, m), nonceMatches); err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
	}
}

func TestAuthorizationAndExchange(t *testing.T) {
	for _, post := range []bool{false, true} {
		t.Run(map[bool]string{false: "basic", true: "post"}[post], func(t *testing.T) {
			f := newIssuer(t)
			f.postAuth = post
			if post {
				f.document["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
			}
			c := f.client(t)
			verifier := strings.Repeat("v", 43)
			location, err := c.AuthorizationURL(context.Background(), "random-state", "browser-nonce", verifier)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(location)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			digest := sha256.Sum256([]byte(verifier))
			for k, want := range map[string]string{"state": "random-state", "nonce": "browser-nonce", "response_type": "code", "scope": "openid email profile", "client_id": "test-client", "redirect_uri": "https://qali.example/api/v1/auth/oidc/callback", "code_challenge_method": "S256", "code_challenge": base64.RawURLEncoding.EncodeToString(digest[:])} {
				if q.Get(k) != want {
					t.Errorf("%s: %q != %q", k, q.Get(k), want)
				}
			}
			if q.Has("client_secret") || q.Has("code_verifier") {
				t.Fatal("authorization URL leaked secret")
			}
			claims, err := c.Exchange(context.Background(), "one-use-code", verifier, secret.New([]byte("fixture-only")), nonceMatches)
			if err != nil || claims.Subject != "subject-1" {
				t.Fatalf("exchange: %+v %v", claims, err)
			}
			if _, err := c.Exchange(context.Background(), "one-use-code", verifier, secret.New([]byte("fixture-only")), nonceMatches); !errors.Is(err, oidc.ErrProviderUnavailable) || strings.Contains(err.Error(), "fixture-sensitive-detail") {
				t.Fatalf("replay failure must be generic: %v", err)
			}
		})
	}
}

func TestExchangeRejectsWrongPKCEAndDoesNotFollowRedirects(t *testing.T) {
	f := newIssuer(t)
	c := f.client(t)
	if _, err := c.Exchange(context.Background(), "one-use-code", strings.Repeat("w", 43), secret.New([]byte("fixture-only")), nonceMatches); !errors.Is(err, oidc.ErrProviderUnavailable) {
		t.Fatalf("wrong verifier: %v", err)
	}
	f.mu.Lock()
	f.redirectToken = true
	f.mu.Unlock()
	if _, err := c.Exchange(context.Background(), "one-use-code", strings.Repeat("v", 43), secret.New([]byte("fixture-only")), nonceMatches); !errors.Is(err, oidc.ErrProviderUnavailable) {
		t.Fatalf("redirect followed: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keyRequests != 0 {
		t.Fatalf("token redirect reached keys endpoint: %d", f.keyRequests)
	}
}

func TestDiscoveryValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{"issuer mismatch", "issuer", "https://other.example"},
		{"missing keys", "jwks_uri", ""},
		{"endpoint credentials", "token_endpoint", "https://user:password@issuer.example/token"},
		{"endpoint fragment", "authorization_endpoint", "https://issuer.example/auth#fragment"},
		{"endpoint protocol", "token_endpoint", "file:///tmp/token"},
		{"private authorization endpoint outside issuer", "authorization_endpoint", "https://169.254.169.254/auth"},
		{"private token endpoint outside issuer", "token_endpoint", "https://169.254.169.254/token"},
		{"private keys endpoint outside issuer", "jwks_uri", "https://169.254.169.254/keys"},
		{"implicit only", "response_types_supported", []string{"id_token"}},
		{"plain PKCE only", "code_challenge_methods_supported", []string{"plain"}},
		{"unsupported authentication", "token_endpoint_auth_methods_supported", []string{"private_key_jwt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newIssuer(t)
			f.document[tc.field] = tc.value
			c := f.client(t)
			if err := c.Discover(context.Background()); err == nil {
				t.Fatal("accepted invalid discovery document")
			}
		})
	}
}
