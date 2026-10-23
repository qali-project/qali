// Package config loads typed process configuration. Secrets are read only
// from files named by <NAME>_FILE variables (Docker/Kubernetes secrets) and
// are held as secret.Value; invalid or weak settings fail closed with every
// problem reported at once (docs/SECURITY_ARCHITECTURE.md section 4, ADR-0006).
package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/qali-project/qali/internal/platform/secret"
)

// Environment selects validation strictness.
type Environment string

const (
	Production  Environment = "production"
	Development Environment = "development"
)

// Config is the validated process configuration.
type Config struct {
	Environment    Environment
	PublicURL      *url.URL
	HTTPAddr       string
	TrustedProxies []netip.Prefix
	DatabaseURL    secret.Value
	KEK            secret.Value
	TokenPepper    secret.Value
	PasswordPepper secret.Value
}

// Source abstracts the process environment for deterministic tests.
type Source struct {
	Getenv   func(string) (string, bool)
	ReadFile func(string) ([]byte, error)
}

// OS reads the real process environment and filesystem.
func OS() Source {
	return Source{Getenv: os.LookupEnv, ReadFile: os.ReadFile}
}

// Error lists every configuration problem. Messages name settings, never
// secret values.
type Error struct {
	Problems []string
}

func (e *Error) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

const keyBytes = 32

// Load reads and validates the configuration.
func Load(src Source) (Config, error) {
	l := loader{src: src}
	var cfg Config

	switch env := l.optional("QALI_ENV", string(Production)); Environment(env) {
	case Production, Development:
		cfg.Environment = Environment(env)
	default:
		l.problem("QALI_ENV must be %q or %q", Production, Development)
	}

	for _, name := range []string{"QALI_DATABASE_URL", "QALI_KEK", "QALI_TOKEN_PEPPER", "QALI_PASSWORD_PEPPER"} {
		if _, ok := src.Getenv(name); ok {
			l.problem("%s must not be set; provide the secret as a file with %s_FILE", name, name)
		}
	}

	cfg.PublicURL = l.publicURL(cfg.Environment)
	cfg.HTTPAddr = l.optional("QALI_HTTP_ADDR", ":8080")
	cfg.TrustedProxies = l.trustedProxies()
	cfg.DatabaseURL = l.databaseURL("QALI_DATABASE_URL_FILE")

	keys := []struct {
		name string
		dst  *secret.Value
	}{
		{"QALI_KEK_FILE", &cfg.KEK},
		{"QALI_TOKEN_PEPPER_FILE", &cfg.TokenPepper},
		{"QALI_PASSWORD_PEPPER_FILE", &cfg.PasswordPepper},
	}
	for _, k := range keys {
		*k.dst = l.key(k.name)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			a, b := *keys[i].dst, *keys[j].dst
			if !a.IsZero() && a.Equal(b) {
				l.problem("%s and %s must contain distinct keys", keys[i].name, keys[j].name)
			}
		}
	}

	if len(l.problems) > 0 {
		return Config{}, &Error{Problems: l.problems}
	}
	return cfg, nil
}

type loader struct {
	src      Source
	problems []string
}

func (l *loader) problem(format string, args ...any) {
	l.problems = append(l.problems, fmt.Sprintf(format, args...))
}

func (l *loader) optional(name, fallback string) string {
	if v, ok := l.src.Getenv(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func (l *loader) required(name string) (string, bool) {
	v, ok := l.src.Getenv(name)
	if !ok || strings.TrimSpace(v) == "" {
		l.problem("%s is required", name)
		return "", false
	}
	return strings.TrimSpace(v), true
}

// secretFile reads the file named by the setting; the content is trimmed.
func (l *loader) secretFile(name string) ([]byte, bool) {
	path, ok := l.required(name)
	if !ok {
		return nil, false
	}
	b, err := l.src.ReadFile(path)
	if err != nil {
		l.problem("%s: cannot read %s", name, path)
		return nil, false
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		l.problem("%s: %s is empty", name, path)
		return nil, false
	}
	return b, true
}

// key decodes a base64 file holding exactly 32 random bytes. Generate one with
// `openssl rand -base64 32`.
func (l *loader) key(name string) secret.Value {
	content, ok := l.secretFile(name)
	if !ok {
		return secret.Value{}
	}
	defer clear(content)
	raw, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil || len(raw) != keyBytes {
		clear(raw)
		l.problem("%s must contain base64 for exactly %d random bytes (generate with `openssl rand -base64 32`)", name, keyBytes)
		return secret.Value{}
	}
	defer clear(raw)
	if weak(raw) {
		l.problem("%s contains low-entropy key material; generate a new random key", name)
		return secret.Value{}
	}
	return secret.New(raw)
}

// weak rejects obviously non-random keys. Random 32-byte keys have about 30
// distinct byte values; fewer than 16 is effectively impossible by chance.
func weak(b []byte) bool {
	distinct := map[byte]bool{}
	for _, x := range b {
		distinct[x] = true
	}
	return len(distinct) < 16
}

func (l *loader) publicURL(env Environment) *url.URL {
	raw, ok := l.required("QALI_PUBLIC_URL")
	if !ok {
		return nil
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
		l.problem("QALI_PUBLIC_URL must be an absolute URL such as https://qali.example.org")
		return nil
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		l.problem("QALI_PUBLIC_URL must be an origin without credentials, path, query, or fragment")
		return nil
	case u.Scheme == "http" && (env != Development || !isLoopback(u.Hostname())):
		l.problem("QALI_PUBLIC_URL must use https (http is allowed only for localhost in development)")
		return nil
	}
	u.Path = ""
	return u
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (l *loader) trustedProxies() []netip.Prefix {
	raw := l.optional("QALI_TRUSTED_PROXIES", "")
	if raw == "" {
		return nil
	}
	var out []netip.Prefix
	for part := range strings.SplitSeq(raw, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			l.problem("QALI_TRUSTED_PROXIES must be a comma-separated list of CIDR prefixes")
			return nil
		}
		out = append(out, p.Masked())
	}
	return out
}

// MigrationConfig is the configuration of `qali migrate`. It holds only the
// migration role's connection, never the runtime keys.
type MigrationConfig struct {
	DatabaseURL secret.Value
}

// LoadMigration reads QALI_MIGRATION_DATABASE_URL_FILE.
func LoadMigration(src Source) (MigrationConfig, error) {
	l := loader{src: src}
	if _, ok := src.Getenv("QALI_MIGRATION_DATABASE_URL"); ok {
		l.problem("QALI_MIGRATION_DATABASE_URL must not be set; provide the secret as a file with QALI_MIGRATION_DATABASE_URL_FILE")
	}
	cfg := MigrationConfig{DatabaseURL: l.databaseURL("QALI_MIGRATION_DATABASE_URL_FILE")}
	if len(l.problems) > 0 {
		return MigrationConfig{}, &Error{Problems: l.problems}
	}
	return cfg, nil
}

// databaseURL requires TLS with certificate verification for any host that is
// not on a private container network or loopback (SECURITY_ARCHITECTURE 8).
func (l *loader) databaseURL(name string) secret.Value {
	content, ok := l.secretFile(name)
	if !ok {
		return secret.Value{}
	}
	defer clear(content)
	u, err := url.Parse(string(content))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		l.problem("%s must contain a postgres:// URL", name)
		return secret.Value{}
	}
	host := u.Hostname()
	private := isLoopback(host) || !strings.Contains(host, ".")
	if mode := u.Query().Get("sslmode"); !private && mode != "verify-full" && mode != "verify-ca" {
		l.problem("%s: remote database hosts require sslmode=verify-full or verify-ca", name)
		return secret.Value{}
	}
	return secret.New(content)
}
