//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/secret"
	"github.com/qali-project/qali/test/oidctest"
)

func TestOIDCSecretsAndCleanup(t *testing.T) {
	f := newOIDCFixture(t)
	f.verify()
	c := f.s.client()
	start := f.start(c)
	u, _ := url.Parse(start.body["authorizationUrl"].(string))
	nonce, state := u.Query().Get("nonce"), u.Query().Get("state")
	callback := f.authorize(start, "owner-sub", "owner@example.org", true)
	r := f.callback(c, callback)
	expect(t, r, http.StatusFound)
	admin := connect(t, f.s.db.admin)
	var provider, flows, audit string
	for _, row := range []struct {
		query string
		out   *string
	}{
		{"SELECT row_to_json(p)::text FROM qali.oidc_provider p", &provider},
		{"SELECT coalesce(json_agg(f)::text,'') FROM qali.oidc_flows f", &flows},
		{"SELECT coalesce(json_agg(e)::text,'') FROM qali.audit_events e", &audit},
	} {
		if err := admin.QueryRow(t.Context(), row.query).Scan(row.out); err != nil {
			t.Fatal(err)
		}
	}
	f.s.logsMu.Lock()
	logs := f.s.logs.String()
	f.s.logsMu.Unlock()
	p := f.owner.do(http.MethodGet, f.path, nil)
	expect(t, p, http.StatusOK)
	for _, raw := range []string{provider, flows, audit, logs, p.raw} {
		for _, sensitive := range []string{oidctest.Credential, "discard-access", "discard-refresh", nonce, state} {
			if strings.Contains(raw, sensitive) {
				t.Fatalf("persisted or returned provider secret: %q", sensitive)
			}
		}
	}
	var scheduled int
	if err := admin.QueryRow(t.Context(), "SELECT count(*) FROM qali.jobs WHERE kind='identity.oidc_cleanup'").Scan(&scheduled); err != nil {
		t.Fatal(err)
	}
	if scheduled != 2 {
		t.Fatalf("cleanup jobs: %d", scheduled)
	}
	f.s.clock.Advance(11 * time.Minute)
	if err := f.s.svc.CleanupOIDCFlows(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := admin.QueryRow(t.Context(), "SELECT count(*) FROM qali.oidc_flows").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired flows left: %d", count)
	}
}

func TestOIDCAtomicConsumption(t *testing.T) {
	f := newOIDCFixture(t)
	f.verify()
	c := f.s.client()
	callback := f.authorize(f.start(c), "owner-sub", "owner@example.org", true)
	u, _ := url.Parse(callback)
	q := u.Query()
	origin, _ := url.Parse(f.s.srv.URL)
	var binding secret.Value
	for _, cookie := range c.http.Jar.Cookies(&url.URL{Scheme: "https", Host: origin.Host}) {
		if cookie.Name == "__Host-qali_oidc" {
			binding = secret.New([]byte(cookie.Value))
		}
	}
	results := make(chan error, 2)
	before := f.issuer.ExchangeCount()
	for range 2 {
		go func() {
			_, _, err := f.s.svc.CompleteOIDC(t.Context(), q.Get("state"), q.Get("code"), "", q.Get("iss"), binding, secret.Value{}, app.RequestMeta{})
			results <- err
		}()
	}
	success := 0
	for range 2 {
		if <-results == nil {
			success++
		}
	}
	if success != 1 || f.issuer.ExchangeCount() != before+1 {
		t.Fatalf("single-use success=%d exchanges=%d", success, f.issuer.ExchangeCount()-before)
	}
}
