// Package oidctest provides an ephemeral identity provider for automated tests.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const ClientID = "test-client"
const Credential = "fixture-only"

type authorization struct {
	Nonce, Challenge, Redirect, Subject, Email string
	Verified                                   bool
}
type Issuer struct {
	Server      *httptest.Server
	mu          sync.Mutex
	key         *rsa.PrivateKey
	codes       map[string]authorization
	now         func() time.Time
	exchanges   int
	unavailable bool
	redirectURI string
}

func New(now func() time.Time, redirectURI string) (*Issuer, error) {
	callback, err := url.Parse(redirectURI)
	if err != nil || callback.Hostname() == "" || (callback.Scheme != "http" && callback.Scheme != "https") || callback.User != nil || callback.Opaque != "" || callback.Fragment != "" || callback.RawQuery != "" || callback.Path != "/api/v1/auth/oidc/callback" {
		return nil, fmt.Errorf("invalid registered redirect URI")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	f := &Issuer{key: key, codes: map[string]authorization{}, now: now, redirectURI: redirectURI}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f, nil
}
func (f *Issuer) Close()             { f.Server.Close() }
func (f *Issuer) URL() string        { return f.Server.URL }
func (f *Issuer) ExchangeCount() int { f.mu.Lock(); defer f.mu.Unlock(); return f.exchanges }

// Authorize retains the real nonce, PKCE challenge and redirect URI.
func (f *Issuer) Authorize(raw, subject, email string, verified bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if u.Scheme+"://"+u.Host != f.URL() || q.Get("client_id") != ClientID || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("redirect_uri") != f.redirectURI {
		return "", fmt.Errorf("invalid authorization request")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(random[:])
	f.mu.Lock()
	f.codes[code] = authorization{Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), Redirect: f.redirectURI, Subject: subject, Email: email, Verified: verified}
	f.mu.Unlock()
	callback, err := url.Parse(f.redirectURI)
	if err != nil {
		return "", err
	}
	v := callback.Query()
	v.Set("state", q.Get("state"))
	v.Set("code", code)
	v.Set("iss", f.URL())
	callback.RawQuery = v.Encode()
	return callback.String(), nil
}
func (f *Issuer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	unavailable := f.unavailable
	f.mu.Unlock()
	if unavailable && r.URL.Path != "/outage" {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/outage":
		f.mu.Lock()
		f.unavailable = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "/.well-known/openid-configuration":
		write(w, map[string]any{"issuer": f.URL(), "authorization_endpoint": f.URL() + "/authorize", "token_endpoint": f.URL() + "/token", "jwks_uri": f.URL() + "/keys", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"}})
	case "/keys":
		write(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "ephemeral", Algorithm: "RS256", Use: "sig"}}})
	case "/authorize":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<html><body><h1>Test identity provider</h1><form method="post"><label>Email <input name="email" type="email" required></label><button>Continue</button></form></body></html>`)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		callback, err := f.Authorize(f.URL()+r.URL.String(), r.Form.Get("email"), r.Form.Get("email"), true)
		if err != nil {
			http.Error(w, "invalid authorization", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, callback, http.StatusFound) //nolint:gosec // G710: origin/path are constructor-registered; request data appears only in escaped OAuth query parameters.
	case "/token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		id, password, ok := r.BasicAuth()
		if !ok || id != ClientID || password != Credential {
			http.Error(w, "invalid client", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		a, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		f.exchanges++
		f.mu.Unlock()
		digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != a.Redirect || base64.RawURLEncoding.EncodeToString(digest[:]) != a.Challenge {
			http.Error(w, "invalid grant", http.StatusBadRequest)
			return
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "ephemeral"))
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		now := f.now()
		payload, err := json.Marshal(map[string]any{"iss": f.URL(), "sub": a.Subject, "email": a.Email, "email_verified": a.Verified, "name": "OIDC member", "aud": ClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": a.Nonce})
		if err != nil {
			http.Error(w, "claims failed", http.StatusInternalServerError)
			return
		}
		object, err := signer.Sign(payload)
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		token, err := object.CompactSerialize()
		if err != nil {
			http.Error(w, "signing failed", http.StatusInternalServerError)
			return
		}
		write(w, map[string]any{"access_token": "discard-access", "refresh_token": "discard-refresh", "id_token": token, "token_type": "Bearer"})
	default:
		http.NotFound(w, r)
	}
}
func write(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
