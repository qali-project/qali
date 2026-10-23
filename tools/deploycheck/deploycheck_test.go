package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// validConfig mirrors `docker compose config --format json` for a compliant
// deployment.
func validConfig() map[string]any {
	hardened := func(extra map[string]any) map[string]any {
		s := map[string]any{
			"cap_drop":     []any{"ALL"},
			"security_opt": []any{"no-new-privileges:true"},
			"read_only":    true,
		}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	return map[string]any{
		"services": map[string]any{
			"proxy": hardened(map[string]any{
				"ports":    []any{map[string]any{"target": 443, "published": "443", "protocol": "tcp", "mode": "ingress"}},
				"networks": map[string]any{"edge": nil, "app": nil},
				"cap_add":  []any{"NET_BIND_SERVICE"},
			}),
			"qali": hardened(map[string]any{
				"user":     "65532:65532",
				"networks": map[string]any{"app": nil, "data": nil},
				"environment": map[string]any{
					"QALI_KEK_FILE": "/run/secrets/kek",
				},
				"secrets": []any{map[string]any{"source": "database_url"}, map[string]any{"source": "kek"}},
			}),
			"migrate": hardened(map[string]any{
				"user":        "65532:65532",
				"networks":    map[string]any{"data": nil},
				"environment": map[string]any{"QALI_MIGRATION_DATABASE_URL_FILE": "/run/secrets/migration_database_url"},
				"secrets":     []any{map[string]any{"source": "migration_database_url"}},
			}),
			"postgres": hardened(map[string]any{
				"networks":    map[string]any{"data": nil},
				"environment": map[string]any{"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password"},
			}),
		},
		"networks": map[string]any{
			"edge": map[string]any{},
			"app":  map[string]any{"internal": true},
			"data": map[string]any{"internal": true},
		},
	}
}

func check(t *testing.T, cfg map[string]any) []string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := CheckCompose(b)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func svc(cfg map[string]any, name string) map[string]any {
	return cfg["services"].(map[string]any)[name].(map[string]any)
}

func TestCompliantConfigurationPasses(t *testing.T) {
	if f := check(t, validConfig()); len(f) != 0 {
		t.Fatalf("unexpected findings: %v", f)
	}
}

func TestViolationsAreReported(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"postgres port": {func(c map[string]any) {
			svc(c, "postgres")["ports"] = []any{map[string]any{"target": 5432, "published": "5432", "protocol": "tcp"}}
		}, "postgres publishes"},
		"qali port": {func(c map[string]any) {
			svc(c, "qali")["ports"] = []any{map[string]any{"target": 8080, "published": "8080", "protocol": "tcp"}}
		}, "qali publishes"},
		"proxy port 80": {func(c map[string]any) {
			svc(c, "proxy")["ports"] = append(svc(c, "proxy")["ports"].([]any), map[string]any{"target": 80, "published": "80", "protocol": "tcp"})
		}, "proxy publishes 80/tcp"},
		"proxy udp 443": {func(c map[string]any) {
			svc(c, "proxy")["ports"] = append(svc(c, "proxy")["ports"].([]any), map[string]any{"target": 443, "published": "443", "protocol": "udp"})
		}, "443/udp"},
		"proxy wrong published port": {func(c map[string]any) {
			svc(c, "proxy")["ports"] = []any{map[string]any{"target": 443, "published": "8443", "protocol": "tcp"}}
		}, "host port 8443"},
		"expose metrics": {func(c map[string]any) { svc(c, "qali")["expose"] = []any{"9090"} }, "expose"},
		"host network":   {func(c map[string]any) { svc(c, "qali")["network_mode"] = "host" }, "host network"},
		"privileged":     {func(c map[string]any) { svc(c, "proxy")["privileged"] = true }, "privileged"},
		"data network not internal": {func(c map[string]any) {
			c["networks"].(map[string]any)["data"] = map[string]any{}
		}, "data network must be internal"},
		"postgres on edge": {func(c map[string]any) {
			svc(c, "postgres")["networks"] = map[string]any{"data": nil, "edge": nil}
		}, "postgres must join only"},
		"qali on edge": {func(c map[string]any) {
			svc(c, "qali")["networks"] = map[string]any{"app": nil, "data": nil, "edge": nil}
		}, "qali must not join"},
		"qali as root":      {func(c map[string]any) { svc(c, "qali")["user"] = "0:0" }, "non-root"},
		"qali without user": {func(c map[string]any) { delete(svc(c, "qali"), "user") }, "non-root"},
		"capabilities kept": {func(c map[string]any) { delete(svc(c, "qali"), "cap_drop") }, "cap_drop"},
		"new privileges":    {func(c map[string]any) { delete(svc(c, "postgres"), "security_opt") }, "no-new-privileges"},
		"writable root":     {func(c map[string]any) { svc(c, "qali")["read_only"] = false }, "read_only"},
		"extra capability":  {func(c map[string]any) { svc(c, "qali")["cap_add"] = []any{"NET_ADMIN"} }, "cap_add"},
		"plain secret env": {func(c map[string]any) {
			svc(c, "qali")["environment"].(map[string]any)["QALI_KEK"] = "abc"
		}, "QALI_KEK"},
		"postgres plain password": {func(c map[string]any) {
			svc(c, "postgres")["environment"].(map[string]any)["POSTGRES_PASSWORD"] = "pw"
		}, "POSTGRES_PASSWORD"},
		"qali holds migration credential": {func(c map[string]any) {
			svc(c, "qali")["secrets"] = append(svc(c, "qali")["secrets"].([]any), map[string]any{"source": "migration_database_url"})
		}, "qali must not receive secret migration_database_url"},
		"migrate holds runtime key": {func(c map[string]any) {
			svc(c, "migrate")["secrets"] = append(svc(c, "migrate")["secrets"].([]any), map[string]any{"source": "kek"})
		}, "migrate may only receive migration_database_url"},
		"migrate on app network": {func(c map[string]any) {
			svc(c, "migrate")["networks"] = map[string]any{"app": nil, "data": nil}
		}, "migrate must join only"},
		"migrate as root": {func(c map[string]any) { svc(c, "migrate")["user"] = "root" }, "migrate must run as a non-root user"},
		"migrate port": {func(c map[string]any) {
			svc(c, "migrate")["ports"] = []any{map[string]any{"target": 8080, "published": "8080", "protocol": "tcp"}}
		}, "migrate publishes"},
		"unexpected service": {func(c map[string]any) {
			c["services"].(map[string]any)["adminer"] = map[string]any{"cap_drop": []any{"ALL"}}
		}, "unexpected service adminer"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)
			findings := check(t, cfg)
			if !containsFinding(findings, tc.want) {
				t.Fatalf("want a finding containing %q, got %v", tc.want, findings)
			}
		})
	}
}

func TestMalformedInputIsAnError(t *testing.T) {
	if _, err := CheckCompose([]byte("{not json")); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if _, err := CheckCompose([]byte(`{"services":{}}`)); err == nil {
		t.Fatal("configuration without the required services accepted")
	}
}

// The repository's Compose file is checked by `make build`; this test keeps
// the expected service names in sync with it.
func TestRepositoryComposeFileDeclaresExpectedServices(t *testing.T) {
	b, err := os.ReadFile("../../deploy/compose/compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy:", "qali:", "migrate:", "postgres:"} {
		if !strings.Contains(string(b), "\n  "+name) {
			t.Fatalf("compose.yaml lacks service %s", name)
		}
	}
}

func containsFinding(findings []string, want string) bool {
	for _, f := range findings {
		if strings.Contains(f, want) {
			return true
		}
	}
	return false
}
