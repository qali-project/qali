//go:build integration

package integration_test

import (
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/qali-project/qali/internal/identity/adapter/httpapi"
)

type contractOp struct {
	method, path string
	public       bool
	states       []string
}

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// contractOperations reads every operation from the OpenAPI contract.
func contractOperations(t *testing.T) []contractOp {
	t.Helper()
	data, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	var ops []contractOp
	for path, methods := range spec.Paths {
		for method, node := range methods {
			if !slices.Contains(httpMethods, method) {
				continue // path-level keys such as parameters
			}
			var op struct {
				Security *[]map[string][]string `yaml:"security"`
				States   []string               `yaml:"x-qali-session-states"`
			}
			if err := node.Decode(&op); err != nil {
				t.Fatal(err)
			}
			ops = append(ops, contractOp{
				method: strings.ToUpper(method), path: path,
				public: op.Security != nil && len(*op.Security) == 0,
				states: op.States,
			})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].method+ops[i].path < ops[j].method+ops[j].path })
	if len(ops) < 15 {
		t.Fatalf("parsed only %d operations", len(ops))
	}
	return ops
}

// TestRoutePolicyMatchesTheContract keeps the adapter's route table in sync
// with security and x-qali-session-states in api/openapi.yaml.
func TestRoutePolicyMatchesTheContract(t *testing.T) {
	policy := httpapi.RoutePolicy()
	for _, op := range contractOperations(t) {
		key := op.method + " " + op.path
		got, ok := policy[key]
		switch {
		case op.public && (!ok || !got.Public):
			t.Fatalf("%s is public in the contract but not in the route policy", key)
		case !op.public && ok && got.Public:
			t.Fatalf("%s is public in the route policy but requires a session in the contract", key)
		case !op.public && len(op.states) > 0 && (!ok || !slices.Equal(got.States, op.states)):
			t.Fatalf("%s states: policy %v, contract %v", key, got.States, op.states)
		case !op.public && len(op.states) == 0 && ok:
			t.Fatalf("%s should rely on the default (active session only)", key)
		}
	}
}

// TestNoOperationIsReachableWithoutTheRequiredSession proves MVP-04.AC-12
// and the exit gate: every operation that is not explicitly public rejects
// anonymous requests, and pre-MFA sessions reach only operations that list
// their state.
func TestNoOperationIsReachableWithoutTheRequiredSession(t *testing.T) {
	s := newAuthServer(t)
	_, _, _ = s.enrolledOwner()
	challenged := s.client()
	expect(t, challenged.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}), http.StatusOK)

	// Path parameters get well-formed IDs so the request reaches the
	// authentication layer; malformed IDs are rejected even earlier.
	params := regexp.MustCompile(`\{[A-Za-z]+\}`)
	for _, op := range contractOperations(t) {
		if op.public {
			continue
		}
		op.path = params.ReplaceAllStringFunc(op.path, func(string) string { return uuid.NewString() })
		anon := s.client().do(op.method, op.path, map[string]any{})
		if anon.status != http.StatusUnauthorized || anon.code() != "unauthenticated" {
			t.Fatalf("%s %s without a session: %d %s", op.method, op.path, anon.status, anon.raw)
		}
		pre := challenged.do(op.method, op.path, map[string]any{})
		allowed := slices.Contains(op.states, "mfa_challenge")
		switch {
		case !allowed && (pre.status != http.StatusForbidden || pre.code() != "mfa_required"):
			t.Fatalf("%s %s with an mfa_challenge session: %d %s", op.method, op.path, pre.status, pre.raw)
		case allowed && slices.Contains([]string{"unauthenticated", "mfa_required", "csrf_token_invalid"}, pre.code()):
			// Business errors (for example invalid_code for an empty body) are
			// fine; the authentication layer must not reject the request.
			t.Fatalf("%s %s lists mfa_challenge but the session was rejected: %d %s", op.method, op.path, pre.status, pre.raw)
		}
		if op.path == "/api/v1/auth/logout" {
			// Logging out ends the challenged session; start a new one.
			challenged = s.client()
			expect(t, challenged.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}), http.StatusOK)
		}
	}
}
