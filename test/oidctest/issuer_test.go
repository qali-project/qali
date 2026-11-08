package oidctest_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/test/oidctest"
)

func TestIssuerRejectsUnregisteredRedirect(t *testing.T) {
	c := clock.NewManual(time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC))
	f, err := oidctest.New(c.Now, "https://qali.example.org/api/v1/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	client := f.Server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, callback := range []string{"https://attacker.example/callback", "//attacker.example/callback", "https://qali.example.org/another-path"} {
		t.Run(callback, func(t *testing.T) {
			q := url.Values{"client_id": {oidctest.ClientID}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {strings.Repeat("v", 43)}, "nonce": {"nonce"}, "state": {"state"}, "redirect_uri": {callback}}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.URL()+"/authorize?"+q.Encode(), strings.NewReader(url.Values{"email": {"member@example.org"}}.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Body.Close() }()
			if r.StatusCode != http.StatusBadRequest || r.Header.Get("Location") != "" {
				t.Fatalf("unregistered callback accepted: status=%d location=%q", r.StatusCode, r.Header.Get("Location"))
			}
		})
	}
}
