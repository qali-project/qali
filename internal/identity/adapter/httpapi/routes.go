package httpapi

import "maps"

// Policy is the session requirement of one contract operation.
type Policy struct {
	// Public operations need no session (OpenAPI `security: []`).
	Public bool
	// States lists the session states allowed (x-qali-session-states). Empty
	// means the default: an active session only.
	States []string
}

var anyState = []string{"mfa_enrollment", "mfa_challenge", "active"}

// routePolicy mirrors api/openapi.yaml; a test keeps them identical.
// Operations not listed require an active session (fail closed).
var routePolicy = map[string]Policy{
	"GET /health/live":                              {Public: true},
	"GET /health/ready":                             {Public: true},
	"GET /api/v1/setup":                             {Public: true},
	"POST /api/v1/setup/owner":                      {Public: true},
	"POST /api/v1/auth/login":                       {Public: true},
	"POST /api/v1/auth/recovery":                    {Public: true},
	"POST /api/v1/auth/password-reset":              {Public: true},
	"POST /api/v1/invitations/preview":              {Public: true},
	"POST /api/v1/invitations/accept":               {Public: true},
	"GET /api/v1/auth/session":                      {States: anyState},
	"POST /api/v1/auth/logout":                      {States: anyState},
	"POST /api/v1/auth/mfa/challenge":               {States: []string{"mfa_challenge"}},
	"POST /api/v1/auth/mfa/totp/enrollment":         {States: []string{"mfa_enrollment", "active"}},
	"POST /api/v1/auth/mfa/totp/enrollment/confirm": {States: []string{"mfa_enrollment", "active"}},
}

// RoutePolicy returns a copy of the route table for contract tests.
func RoutePolicy() map[string]Policy { return maps.Clone(routePolicy) }
