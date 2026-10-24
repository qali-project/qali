// Command deploycheck verifies the production Compose deployment against
// docs/SECURITY_ARCHITECTURE.md: only the proxy publishes a host port
// (443/tcp), internal networks isolate Qali and PostgreSQL, and every service
// runs hardened.
//
// Usage:
//
//	go run ./tools/deploycheck static          # rendered configuration only
//	go run ./tools/deploycheck live <secrets>  # start the stack and probe it
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

var (
	requiredServices = []string{"proxy", "qali", "migrate", "postgres"}
	// runningServices stay up; migrate is a one-shot job.
	runningServices = []string{"proxy", "qali", "postgres"}
	plainSecretEnv  = []string{"QALI_KEK", "QALI_TOKEN_PEPPER", "QALI_PASSWORD_PEPPER", "QALI_DATABASE_URL", "POSTGRES_PASSWORD"}
)

type port struct {
	Target    int    `json:"target"`
	Published string `json:"published"`
	Protocol  string `json:"protocol"`
}

type service struct {
	Ports       []port             `json:"ports"`
	Expose      []any              `json:"expose"`
	Networks    map[string]any     `json:"networks"`
	NetworkMode string             `json:"network_mode"`
	Privileged  bool               `json:"privileged"`
	CapDrop     []string           `json:"cap_drop"`
	CapAdd      []string           `json:"cap_add"`
	SecurityOpt []string           `json:"security_opt"`
	ReadOnly    bool               `json:"read_only"`
	User        string             `json:"user"`
	Environment map[string]*string `json:"environment"`
	Secrets     []struct {
		Source string `json:"source"`
	} `json:"secrets"`
}

func (s service) secretSources() []string {
	out := make([]string, 0, len(s.Secrets))
	for _, sec := range s.Secrets {
		out = append(out, sec.Source)
	}
	return out
}

type network struct {
	Internal bool `json:"internal"`
}

type compose struct {
	Services map[string]service `json:"services"`
	Networks map[string]network `json:"networks"`
}

// CheckCompose validates `docker compose config --format json` output for the
// default published port 443.
func CheckCompose(data []byte) ([]string, error) {
	return checkCompose(data, "443")
}

func checkCompose(data []byte, httpsPort string) ([]string, error) {
	var c compose
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("decode compose configuration: %w", err)
	}
	for _, name := range requiredServices {
		if _, ok := c.Services[name]; !ok {
			return nil, fmt.Errorf("compose configuration lacks service %q", name)
		}
	}
	var f []string
	add := func(format string, args ...any) { f = append(f, fmt.Sprintf(format, args...)) }

	for name, s := range c.Services {
		if !slices.Contains(requiredServices, name) {
			add("unexpected service %s: the default deployment has only proxy, qali, migrate, and postgres", name)
		}
		if s.NetworkMode == "host" {
			add("%s uses the host network", name)
		}
		if s.Privileged {
			add("%s is privileged", name)
		}
		if !slices.Contains(s.CapDrop, "ALL") {
			add("%s must set cap_drop: [ALL]", name)
		}
		if name == "proxy" {
			for _, cap := range s.CapAdd {
				if cap != "NET_BIND_SERVICE" {
					add("proxy cap_add may contain only NET_BIND_SERVICE, found %s", cap)
				}
			}
		} else if len(s.CapAdd) > 0 {
			add("%s must not use cap_add", name)
		}
		if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") && !slices.Contains(s.SecurityOpt, "no-new-privileges") {
			add("%s must set security_opt no-new-privileges", name)
		}
		if !s.ReadOnly {
			add("%s must set read_only: true", name)
		}
		if len(s.Expose) > 0 {
			add("%s must not expose extra ports", name)
		}
		for _, env := range plainSecretEnv {
			if _, ok := s.Environment[env]; ok {
				add("%s sets %s in the environment; use a secret file", name, env)
			}
		}
		if name != "proxy" && len(s.Ports) > 0 {
			add("%s publishes host ports; only the proxy may", name)
		}
	}

	proxy := c.Services["proxy"]
	published443 := false
	for _, p := range proxy.Ports {
		switch {
		case p.Target != 443 || p.Protocol != "tcp":
			add("proxy publishes %d/%s; only 443/tcp is allowed", p.Target, p.Protocol)
		case p.Published != httpsPort:
			add("proxy publishes 443/tcp on host port %s, want %s", p.Published, httpsPort)
		default:
			published443 = true
		}
	}
	if !published443 {
		add("proxy does not publish 443/tcp")
	}

	if n, ok := c.Networks["data"]; !ok || !n.Internal {
		add("data network must be internal")
	}
	if n, ok := c.Networks["app"]; !ok || !n.Internal {
		add("app network must be internal")
	}
	if nets := keys(c.Services["postgres"].Networks); !slices.Equal(nets, []string{"data"}) {
		add("postgres must join only the data network, joins %v", nets)
	}
	if _, ok := c.Services["qali"].Networks["edge"]; ok {
		add("qali must not join the edge network")
	}
	if _, ok := proxy.Networks["data"]; ok {
		add("proxy must not join the data network")
	}
	for _, name := range []string{"qali", "migrate"} {
		if u := c.Services[name].User; u == "" || strings.HasPrefix(u, "0") || strings.HasPrefix(u, "root") {
			add("%s must run as a non-root user, has %q", name, u)
		}
	}
	// The migration credential never reaches the runtime container, and the
	// one-shot migrate job receives nothing else.
	if slices.Contains(c.Services["qali"].secretSources(), "migration_database_url") {
		add("qali must not receive secret migration_database_url")
	}
	for _, src := range c.Services["migrate"].secretSources() {
		if src != "migration_database_url" {
			add("migrate may only receive migration_database_url, also gets %s", src)
		}
	}
	if nets := keys(c.Services["migrate"].Networks); !slices.Equal(nets, []string{"data"}) {
		add("migrate must join only the data network, joins %v", nets)
	}
	slices.Sort(f)
	return f, nil
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

const (
	composeFile = "deploy/compose/compose.yaml"
	liveProject = "qali-deploycheck"
	livePort    = "18443"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: deploycheck static | live <secrets-dir>")
		os.Exit(2)
	}
	var err error
	switch {
	case os.Args[1] == "static" && len(os.Args) == 2:
		err = static()
	case os.Args[1] == "live" && len(os.Args) == 3:
		err = live(os.Args[2])
	default:
		err = errors.New("usage: deploycheck static | live <secrets-dir>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "deploycheck:", err)
		os.Exit(1)
	}
}

func dockerCompose(ctx context.Context, env []string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", composeFile}, args...)...) //nolint:gosec // G204: fixed program, arguments built from constants
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	return cmd
}

func render(ctx context.Context, env []string, port string) error {
	out, err := dockerCompose(ctx, env, "config", "--format", "json").Output()
	if err != nil {
		return fmt.Errorf("docker compose config: %w", err)
	}
	findings, err := checkCompose(out, port)
	if err != nil {
		return err
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, f)
	}
	if len(findings) > 0 {
		return fmt.Errorf("%d deployment finding(s) in %s", len(findings), composeFile)
	}
	return nil
}

func static() error {
	env := []string{"QALI_DOMAIN=qali.example.org", "QALI_SECRETS_DIR=./secrets"}
	if err := render(context.Background(), env, "443"); err != nil {
		return err
	}
	fmt.Println("deploycheck: static configuration OK")
	return nil
}

// live starts the stack on a test port, proves the application is reachable
// only through the proxy, and removes everything afterwards.
func live(secretsDir string) error {
	abs, err := filepath.Abs(secretsDir)
	if err != nil {
		return err
	}
	if err := prepareComposeSecrets(abs); err != nil {
		return err
	}
	ctx := context.Background()
	env := []string{
		"QALI_DOMAIN=localhost", "QALI_TLS=internal", "QALI_HTTPS_PORT=" + livePort,
		"QALI_SECRETS_DIR=" + filepath.ToSlash(abs), "COMPOSE_PROJECT_NAME=" + liveProject,
	}
	if err := render(ctx, env, livePort); err != nil {
		return err
	}
	defer func() { _ = dockerCompose(ctx, env, "down", "--volumes", "--remove-orphans").Run() }()
	if err := dockerCompose(ctx, env, "up", "--detach", "--quiet-pull").Run(); err != nil {
		_ = dockerCompose(ctx, env, "logs", "--no-color", "--tail", "50").Run()
		return fmt.Errorf("docker compose up: %w", err)
	}

	if err := probeHTTPS(ctx); err != nil {
		_ = dockerCompose(ctx, env, "logs", "--no-color", "--tail", "50").Run()
		return err
	}
	for _, name := range []string{"postgres", "qali"} {
		if err := waitHealthy(ctx, env, name); err != nil {
			return err
		}
	}
	if err := checkPublishers(ctx, env); err != nil {
		return err
	}
	fmt.Println("deploycheck: live deployment OK (migrated, ready, only 443/tcp published)")
	return nil
}

// prepareComposeSecrets adjusts only the disposable secrets generated for the
// live deployment check. On Linux, Compose implements file-backed secrets as
// bind mounts and preserves the host ownership and mode. The fixed non-root
// container users therefore cannot read the generator's secure 0600 files.
// These values are random test fixtures under bin/, so make them read-only and
// container-readable immediately before starting the short-lived stack.
func prepareComposeSecrets(dir string) error {
	return prepareComposeSecretsForOS(dir, runtime.GOOS, os.Chmod)
}

func prepareComposeSecretsForOS(dir, goos string, chmod func(string, os.FileMode) error) error {
	if goos == "windows" {
		return nil
	}
	for _, name := range []string{
		"database_url", "migration_database_url", "kek", "token_pepper", "password_pepper",
		"postgres_password", "migrator_password", "app_password",
	} {
		path := filepath.Join(dir, name)
		if err := chmod(path, 0o444); err != nil {
			return fmt.Errorf("make disposable Compose secret %s container-readable: %w", name, err)
		}
	}
	return nil
}

func probeHTTPS(ctx context.Context) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		// The test stack uses Caddy's internal CA, so the certificate chain is
		// not publicly trusted. This client only talks to the local test stack.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}, //nolint:gosec // G402: local test stack with an internal CA
	}
	url := "https://localhost:" + livePort + "/health/ready"
	var lastErr error
	for range 60 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK && bytes.Contains(body, []byte(`"status":"ready"`)) {
				if res.Header.Get("Strict-Transport-Security") == "" || res.Header.Get("Content-Security-Policy") == "" {
					return errors.New("security headers missing behind the proxy")
				}
				return nil
			}
			lastErr = fmt.Errorf("GET %s: HTTP %d", url, res.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("application not reachable through the proxy: %w", lastErr)
}

// waitHealthy polls until the service's healthcheck reports healthy, which for
// PostgreSQL proves it initialized under the hardened settings.
func waitHealthy(ctx context.Context, env []string, name string) error {
	for range 45 {
		out, err := dockerCompose(ctx, env, "ps", "--all", "--format", "json").Output()
		if err != nil {
			return fmt.Errorf("docker compose ps: %w", err)
		}
		entries, err := parsePS(out)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Service == name && e.Health == "healthy" {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("%s did not become healthy", name)
}

type publisher struct {
	TargetPort    int    `json:"TargetPort"`
	PublishedPort int    `json:"PublishedPort"`
	Protocol      string `json:"Protocol"`
}

type psEntry struct {
	Service    string      `json:"Service"`
	State      string      `json:"State"`
	Health     string      `json:"Health"`
	ExitCode   int         `json:"ExitCode"`
	Publishers []publisher `json:"Publishers"`
}

// checkPublishers inspects the running containers' host port bindings.
func checkPublishers(ctx context.Context, env []string) error {
	out, err := dockerCompose(ctx, env, "ps", "--all", "--format", "json").Output()
	if err != nil {
		return fmt.Errorf("docker compose ps: %w", err)
	}
	entries, err := parsePS(out)
	if err != nil {
		return err
	}
	running := map[string]bool{}
	var problems []string
	for _, e := range entries {
		running[e.Service] = e.State == "running"
		if e.Service == "migrate" && (e.State != "exited" || e.ExitCode != 0) {
			problems = append(problems, fmt.Sprintf("migrate did not complete successfully (state %s, exit %d)", e.State, e.ExitCode))
		}
		for _, p := range e.Publishers {
			if p.PublishedPort == 0 {
				continue // exposed inside the network only
			}
			if e.Service != "proxy" || p.TargetPort != 443 || p.Protocol != "tcp" {
				problems = append(problems, fmt.Sprintf("%s publishes %d/%s on host port %d", e.Service, p.TargetPort, p.Protocol, p.PublishedPort))
			}
		}
	}
	for _, name := range runningServices {
		if !running[name] {
			problems = append(problems, name+" is not running")
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// parsePS accepts both a JSON array and one JSON object per line.
func parsePS(out []byte) ([]psEntry, error) {
	trimmed := bytes.TrimSpace(out)
	if bytes.HasPrefix(trimmed, []byte("[")) {
		var entries []psEntry
		return entries, json.Unmarshal(trimmed, &entries)
	}
	var entries []psEntry
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e psEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("decode docker compose ps: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}
