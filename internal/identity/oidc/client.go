// Package oidc implements the protocol boundary to an OpenID Connect issuer.
// Persisted flow consumption, browser binding, linking, MFA and sessions belong
// to the application layer and must precede/follow this client's exchange.
package oidc

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/secret"
)

const responseLimit = 1 << 20

var (
	ErrInvalidConfig       = errors.New("oidc: invalid configuration")
	ErrInvalidToken        = errors.New("oidc: invalid identity token")
	ErrProviderUnavailable = errors.New("oidc: provider unavailable")
	ErrUnsafeEndpoint      = errors.New("oidc: unsafe endpoint")
)

// Config contains no recoverable credentials. AllowPrivateIssuer is an operator
// decision, restricted to the configured issuer hostname, never caller input.
type Config struct {
	Issuer             string
	ClientID           string
	PublicURL          string
	Development        bool
	AllowPrivateIssuer bool
	Roots              *x509.CertPool
	Clock              clock.Clock
}

// Identity contains only verified identity claims, never provider tokens.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Client caches discovery and verification keys for at most an hour.
type Client struct {
	cfg       Config
	http      *http.Client
	keysHTTP  *http.Client
	transport *http.Transport
	mu        sync.Mutex
	cached    *provider
	expires   time.Time
}

type provider struct {
	oauth    oauth2.Config
	verifier *gooidc.IDTokenVerifier
}

type discovery struct {
	Issuer           string   `json:"issuer"`
	AuthURL          string   `json:"authorization_endpoint"`
	TokenURL         string   `json:"token_endpoint"`
	KeysURL          string   `json:"jwks_uri"`
	ResponseTypes    []string `json:"response_types_supported"`
	ChallengeMethods []string `json:"code_challenge_methods_supported"`
	AuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// New validates local configuration without performing network requests.
func New(cfg Config) (*Client, error) {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	issuer, err := endpoint(cfg.Issuer, cfg.Development)
	if err != nil || issuer.RawQuery != "" || len(cfg.ClientID) == 0 || len(cfg.ClientID) > 512 {
		return nil, ErrInvalidConfig
	}
	public, err := endpoint(cfg.PublicURL, cfg.Development)
	if err != nil || public.RawQuery != "" || (public.Path != "" && public.Path != "/") {
		return nil, ErrInvalidConfig
	}
	transport := newTransport(cfg, issuer.Hostname())
	bounded := boundedTransport{base: transport}
	httpClient := &http.Client{Transport: bounded, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	keyClient := *httpClient
	keyClient.Transport = &keyTransport{base: bounded, clock: cfg.Clock, last: make(map[string]time.Time)}
	return &Client{cfg: cfg, http: httpClient, keysHTTP: &keyClient, transport: transport}, nil
}

// Close releases idle outbound connections; it does not alter stored identities.
func (c *Client) Close() { c.transport.CloseIdleConnections() }

// Discover validates the provider's discovery document and endpoints.
func (c *Client) Discover(ctx context.Context) error { _, err := c.provider(ctx); return err }

func (c *Client) provider(ctx context.Context) (*provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil && c.cfg.Clock.Now().Before(c.expires) {
		return c.cached, nil
	}
	var d discovery
	if err := c.getJSON(ctx, strings.TrimSuffix(c.cfg.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	if d.Issuer != c.cfg.Issuer || !contains(d.ResponseTypes, "code") || (len(d.ChallengeMethods) > 0 && !contains(d.ChallengeMethods, "S256")) {
		return nil, ErrInvalidConfig
	}
	for _, address := range []string{d.AuthURL, d.TokenURL, d.KeysURL} {
		if err := c.checkEndpoint(ctx, address); err != nil {
			return nil, err
		}
	}
	style := oauth2.AuthStyleInHeader
	if len(d.AuthMethods) > 0 && !contains(d.AuthMethods, "client_secret_basic") {
		if !contains(d.AuthMethods, "client_secret_post") {
			return nil, ErrInvalidConfig
		}
		style = oauth2.AuthStyleInParams
	}
	keySet := gooidc.NewRemoteKeySet(gooidc.ClientContext(context.Background(), c.keysHTTP), d.KeysURL)
	p := &provider{oauth: oauth2.Config{ClientID: c.cfg.ClientID, RedirectURL: strings.TrimSuffix(c.cfg.PublicURL, "/") + "/api/v1/auth/oidc/callback", Scopes: []string{"openid", "email", "profile"}, Endpoint: oauth2.Endpoint{AuthURL: d.AuthURL, TokenURL: d.TokenURL, AuthStyle: style}}, verifier: gooidc.NewVerifier(c.cfg.Issuer, keySet, &gooidc.Config{ClientID: c.cfg.ClientID, SupportedSigningAlgs: []string{"RS256", "PS256", "ES256"}, Now: c.cfg.Clock.Now, SkipExpiryCheck: true})}
	// Expiry is checked explicitly below together with iat/nbf, with one skew policy.
	c.cached = p
	c.expires = c.cfg.Clock.Now().Add(time.Hour)
	return p, nil
}

func (c *Client) checkEndpoint(ctx context.Context, address string) error {
	u, err := endpoint(address, c.cfg.Development)
	if err != nil {
		return ErrUnsafeEndpoint
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return ErrProviderUnavailable
	}
	issuer, _ := url.Parse(c.cfg.Issuer) // New already validated this URL.
	return checkAddresses(ips, c.cfg.AllowPrivateIssuer && strings.EqualFold(u.Hostname(), issuer.Hostname()))
}

// AuthorizationURL requires caller-generated state/nonce and a stored PKCE
// verifier. The application must bind them to a browser and single-use flow.
func (c *Client) AuthorizationURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	if state == "" || len(state) > 512 || nonce == "" || len(nonce) > 512 || !validVerifier(verifier) {
		return "", ErrInvalidConfig
	}
	p, err := c.provider(ctx)
	if err != nil {
		return "", err
	}
	return p.oauth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange sends a code only after the caller atomically consumes and validates
// the persisted flow and browser binding. Credentials and tokens are not cached.
// verifyNonce compares a keyed verifier in the flow, without storing raw nonce.
func (c *Client) Exchange(ctx context.Context, code, verifier string, credential secret.Value, verifyNonce func(string) bool) (Identity, error) {
	if code == "" || len(code) > 8192 || !validVerifier(verifier) || credential.IsZero() || credential.Len() > 8192 || verifyNonce == nil {
		return Identity{}, ErrInvalidConfig
	}
	p, err := c.provider(ctx)
	if err != nil {
		return Identity{}, err
	}
	conf := p.oauth
	conf.ClientSecret = string(credential.Expose())
	token, err := conf.Exchange(gooidc.ClientContext(ctx, c.http), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, ErrProviderUnavailable
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Identity{}, ErrInvalidToken
	}
	return c.validate(ctx, p, raw, verifyNonce)
}

// Validate verifies the signature and protocol claims. It does not create a
// session, auto-provision an account, or interpret provider MFA claims.
func (c *Client) Validate(ctx context.Context, raw string, verifyNonce func(string) bool) (Identity, error) {
	if raw == "" || len(raw) > responseLimit || verifyNonce == nil {
		return Identity{}, ErrInvalidToken
	}
	p, err := c.provider(ctx)
	if err != nil {
		return Identity{}, err
	}
	return c.validate(ctx, p, raw, verifyNonce)
}

func (c *Client) validate(ctx context.Context, p *provider, raw string, verifyNonce func(string) bool) (Identity, error) {
	if len(raw) > responseLimit {
		return Identity{}, ErrInvalidToken
	}
	token, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, ErrInvalidToken
	}
	var claims struct {
		Subject       string `json:"sub"`
		Issuer        string `json:"iss"`
		AZP           string `json:"azp"`
		Nonce         string `json:"nonce"`
		Expires       *int64 `json:"exp"`
		Issued        *int64 `json:"iat"`
		NotBefore     *int64 `json:"nbf"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := token.Claims(&claims); err != nil {
		return Identity{}, ErrInvalidToken
	}
	if claims.Issuer != c.cfg.Issuer || claims.Subject == "" || len(claims.Subject) > 255 || claims.Nonce == "" || claims.Expires == nil || claims.Issued == nil {
		return Identity{}, ErrInvalidToken
	}
	if (len(token.Audience) > 1 || claims.AZP != "") && subtle.ConstantTimeCompare([]byte(claims.AZP), []byte(c.cfg.ClientID)) != 1 {
		return Identity{}, ErrInvalidToken
	}
	now := c.cfg.Clock.Now().Unix()
	if *claims.Expires <= now-60 || *claims.Issued > now+60 || *claims.Expires <= *claims.Issued || (claims.NotBefore != nil && *claims.NotBefore > now+60) {
		return Identity{}, ErrInvalidToken
	}
	if !verifyNonce(claims.Nonce) {
		return Identity{}, ErrInvalidToken
	}
	return Identity{Issuer: claims.Issuer, Subject: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified, Name: claims.Name}, nil
}

func (c *Client) getJSON(ctx context.Context, address string, value any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return ErrInvalidConfig
	}
	response, err := c.http.Do(req)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return ErrProviderUnavailable
	}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(value); err != nil {
		return ErrProviderUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrProviderUnavailable
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)
		if !valid {
			return false
		}
	}
	return true
}

func endpoint(value string, development bool) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrUnsafeEndpoint
	}
	validScheme := u.Scheme == "https" || development && u.Scheme == "http" && localHost(u.Hostname())
	if !validScheme {
		return nil, ErrUnsafeEndpoint
	}
	return u, nil
}
