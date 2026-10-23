// Package httpapi exposes the identity use cases over the OpenAPI contract
// and provides the authentication middleware for every contract operation.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	"github.com/qali-project/qali/internal/platform/secret"
)

// CookieName is the session cookie (ADR-0006). The __Host- prefix requires
// Secure, Path=/, and no Domain.
const CookieName = "__Host-qali_session"

// Handler implements the identity operations; others answer 501.
type Handler struct {
	openapi.Unimplemented
	svc    *app.Service
	logger *slog.Logger
}

// New returns the handler.
func New(svc *app.Service, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, logger: logger}
}

func current(r *http.Request) app.Current {
	c, _ := app.CurrentFrom(r.Context())
	return c
}

func meta(r *http.Request) app.RequestMeta {
	return app.RequestMeta{IP: httpserver.ClientAddr(r.Context()), RequestID: httpserver.RequestID(r.Context())}
}

func isSafe(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// Authenticate enforces the route policy for every contract operation:
// a valid session in an allowed state, and a session-bound CSRF token on
// unsafe methods. Unknown routes require an active session.
func (h *Handler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := routePolicy[httpserver.Route(r)]
		if policy.Public {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(CookieName)
		if err != nil {
			httpserver.WriteProblem(w, r, http.StatusUnauthorized, "unauthenticated")
			return
		}
		cur, err := h.svc.Authenticate(r.Context(), secret.New([]byte(cookie.Value)), meta(r))
		if err != nil {
			if !errors.Is(err, app.ErrUnauthenticated) {
				h.fail(w, r, err)
				return
			}
			clearCookie(w)
			httpserver.WriteProblem(w, r, http.StatusUnauthorized, "unauthenticated")
			return
		}
		states := policy.States
		if len(states) == 0 {
			states = []string{string(domain.StateActive)}
		}
		if !slices.Contains(states, string(cur.View.State)) {
			httpserver.WriteProblem(w, r, http.StatusForbidden, "mfa_required")
			return
		}
		if !isSafe(r.Method) && !h.svc.CheckCSRF(cur, r.Header.Get("X-CSRF-Token")) {
			httpserver.WriteProblem(w, r, http.StatusForbidden, "csrf_token_invalid")
			return
		}
		next.ServeHTTP(w, r.WithContext(app.WithCurrent(r.Context(), cur)))
	})
}

func setCookie(w http.ResponseWriter, g app.Grant) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: string(g.Token.Expose()), Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// WriteSession sets the cookie for a new session and writes its body. Other
// modules that sign users in (invitation acceptance) receive it at assembly.
func WriteSession(w http.ResponseWriter, status int, g app.Grant) {
	setCookie(w, g)
	httpserver.WriteJSON(w, status, sessionBody(g))
}

func sessionBody(g app.Grant) openapi.Session {
	return openapi.Session{
		CsrfToken: string(g.CSRF.Expose()),
		ExpiresAt: g.View.ExpiresAt.UTC(),
		State:     openapi.SessionState(g.View.State),
		User: openapi.SessionUser{
			Id: g.View.UserID, Email: g.View.Email, DisplayName: g.View.DisplayName, MfaEnrolled: g.View.MFAEnrolled,
		},
	}
}

// fail maps use-case errors to stable problem codes.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var throttled *app.ThrottledError
	switch {
	case errors.As(err, &throttled):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(throttled.RetryAfter.Seconds()))))
		httpserver.WriteProblem(w, r, http.StatusTooManyRequests, "too_many_attempts")
	case errors.Is(err, app.ErrInvalidCredentials):
		httpserver.WriteProblem(w, r, http.StatusUnauthorized, "invalid_credentials")
	case errors.Is(err, app.ErrInvalidCode):
		httpserver.WriteProblem(w, r, http.StatusUnauthorized, "invalid_code")
	case errors.Is(err, app.ErrInvalidToken):
		httpserver.WriteProblem(w, r, http.StatusUnauthorized, "invalid_token")
	case errors.Is(err, app.ErrUnauthenticated):
		httpserver.WriteProblem(w, r, http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, app.ErrInvalidSetupToken):
		httpserver.WriteProblem(w, r, http.StatusForbidden, "setup_token_invalid")
	case errors.Is(err, app.ErrAlreadyBootstrapped):
		httpserver.WriteProblem(w, r, http.StatusConflict, "already_bootstrapped")
	case errors.Is(err, app.ErrAlreadyEnrolled):
		httpserver.WriteProblem(w, r, http.StatusConflict, "already_enrolled")
	case errors.Is(err, app.ErrEnrollmentNotStarted):
		httpserver.WriteProblem(w, r, http.StatusConflict, "enrollment_not_started")
	case errors.Is(err, domain.ErrWeakPassword):
		httpserver.WriteProblem(w, r, http.StatusBadRequest, "weak_password")
	case errors.Is(err, domain.ErrInvalidEmail):
		httpserver.WriteProblem(w, r, http.StatusBadRequest, "invalid_email")
	case errors.Is(err, app.ErrInvalidInput):
		httpserver.WriteProblem(w, r, http.StatusBadRequest, "invalid_input")
	case errors.Is(err, context.Canceled):
		// The client went away; nothing failed on the server.
		h.logger.Info("request canceled by the client", "request_id", httpserver.RequestID(r.Context()))
		httpserver.WriteProblem(w, r, httpserver.StatusClientClosedRequest, "request_canceled")
	default:
		h.logger.Error("identity request failed", "request_id", httpserver.RequestID(r.Context()),
			"error", err.Error(), "cause", rootCause(err).Error())
		httpserver.WriteProblem(w, r, http.StatusInternalServerError, "internal_error")
	}
}

// rootCause returns the innermost wrapped error for operator logs; clients
// only ever see the stable problem code.
func rootCause(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

func (h *Handler) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	required, err := h.svc.SetupRequired(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.SetupStatus{BootstrapRequired: required})
}

func (h *Handler) BootstrapOwner(w http.ResponseWriter, r *http.Request) {
	var body openapi.BootstrapRequest
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, err := h.svc.Bootstrap(r.Context(), app.BootstrapInput{
		Email: string(body.Email), DisplayName: body.DisplayName, Password: secret.New([]byte(body.Password)), WorkspaceName: body.WorkspaceName,
		SetupToken: secret.New([]byte(body.SetupToken)),
	}, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setCookie(w, g)
	httpserver.WriteJSON(w, http.StatusCreated, sessionBody(g))
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body openapi.LoginRequest
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, err := h.svc.Login(r.Context(), body.Email, secret.New([]byte(body.Password)), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setCookie(w, g)
	httpserver.WriteJSON(w, http.StatusOK, sessionBody(g))
}

func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	c := current(r)
	httpserver.WriteJSON(w, http.StatusOK, openapi.Session{
		CsrfToken: string(c.CSRFToken().Expose()),
		State:     openapi.SessionState(c.View.State),
		ExpiresAt: c.View.ExpiresAt.UTC(),
		User: openapi.SessionUser{
			Id: c.View.UserID, Email: c.View.Email, DisplayName: c.View.DisplayName, MfaEnrolled: c.View.MFAEnrolled,
		},
	})
}

func (h *Handler) CompleteMfaChallenge(w http.ResponseWriter, r *http.Request) {
	var body openapi.TotpCode
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, err := h.svc.CompleteMFAChallenge(r.Context(), current(r), body.Code, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setCookie(w, g)
	httpserver.WriteJSON(w, http.StatusOK, sessionBody(g))
}

func (h *Handler) StepUpMfa(w http.ResponseWriter, r *http.Request) {
	var body openapi.TotpCode
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, err := h.svc.StepUp(r.Context(), current(r), body.Code, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setCookie(w, g)
	httpserver.WriteJSON(w, http.StatusOK, sessionBody(g))
}

func (h *Handler) BeginTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	e, err := h.svc.BeginTOTPEnrollment(r.Context(), current(r), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpserver.WriteJSON(w, http.StatusOK, openapi.TotpEnrollment{Secret: e.Secret, OtpauthUri: e.URI})
}

func (h *Handler) ConfirmTotpEnrollment(w http.ResponseWriter, r *http.Request) {
	var body openapi.TotpCode
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, codes, err := h.svc.ConfirmTOTPEnrollment(r.Context(), current(r), body.Code, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setCookie(w, g)
	httpserver.WriteJSON(w, http.StatusOK, openapi.EnrollmentResult{Session: sessionBody(g), RecoveryCodes: codes})
}

func (h *Handler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	var body openapi.TotpCode
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	codes, err := h.svc.RegenerateRecoveryCodes(r.Context(), current(r), body.Code, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.RecoveryCodes{RecoveryCodes: codes})
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var body openapi.PasswordChange
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, err := h.svc.ChangePassword(r.Context(), current(r), secret.New([]byte(body.CurrentPassword)), secret.New([]byte(body.NewPassword)), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setCookie(w, g)
	httpserver.WriteJSON(w, http.StatusOK, sessionBody(g))
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Logout(r.Context(), current(r), meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.LogoutAll(r.Context(), current(r), meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RecoverAccount(w http.ResponseWriter, r *http.Request) {
	var body openapi.RecoveryRequest
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	if err := h.svc.Recover(r.Context(), body.Email, body.RecoveryCode, secret.New([]byte(body.NewPassword)), meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RedeemPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body openapi.PasswordResetRequest
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	if err := h.svc.RedeemPasswordReset(r.Context(), secret.New([]byte(body.Token)), secret.New([]byte(body.NewPassword)), meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
