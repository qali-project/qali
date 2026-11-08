package httpapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	"github.com/qali-project/qali/internal/platform/secret"
)

const oidcCookie = "__Host-qali_oidc"

func oidcETag(version int32) string { return `"` + strconv.Itoa(int(version)) + `"` }
func oidcIfMatch(header *string) *int32 {
	if header == nil {
		return nil
	}
	v := int32(-1)
	if len(*header) > 2 && (*header)[0] == '"' && (*header)[len(*header)-1] == '"' {
		n, err := strconv.ParseInt((*header)[1:len(*header)-1], 10, 32)
		if err == nil && n >= 0 {
			v = int32(n)
		}
	}
	return &v
}

func (h *Handler) GetAuthMethods(w http.ResponseWriter, r *http.Request) {
	local, label, err := h.svc.AuthMethods(r.Context())
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := openapi.AuthMethods{LocalLogin: local}
	if label != "" {
		out.Oidc = &openapi.AuthMethodOidc{Label: label}
	}
	httpserver.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) startOIDC(w http.ResponseWriter, r *http.Request, purpose string, invitation, password secret.Value, ws uuid.UUID) {
	out, err := h.svc.StartOIDC(r.Context(), current(r), purpose, invitation, password, ws, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: string(out.Binding.Expose()), Path: "/", MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	httpserver.WriteJSON(w, http.StatusOK, openapi.OidcAuthorization{AuthorizationUrl: out.URL})
}

func (h *Handler) StartOidcSignIn(w http.ResponseWriter, r *http.Request) {
	var body openapi.OidcStart
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	if body.Purpose != openapi.OidcStartPurposeLogin && body.Purpose != openapi.OidcStartPurposeInvitation {
		h.fail(w, r, app.ErrInvalidInput)
		return
	}
	var invitation secret.Value
	if body.InvitationToken != nil {
		invitation = secret.New([]byte(*body.InvitationToken))
	}
	h.startOIDC(w, r, string(body.Purpose), invitation, secret.Value{}, uuid.Nil)
}

func (h *Handler) StartOidcLink(w http.ResponseWriter, r *http.Request) {
	var body openapi.OidcLinkStart
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	var password secret.Value
	if body.Password != nil {
		password = secret.New([]byte(*body.Password))
	}
	h.startOIDC(w, r, "link", secret.Value{}, password, uuid.Nil)
}

func (h *Handler) StartOidcVerification(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId) {
	h.startOIDC(w, r, "verify", secret.Value{}, secret.Value{}, ws)
}

func (h *Handler) CompleteOidcSignIn(w http.ResponseWriter, r *http.Request, p openapi.CompleteOidcSignInParams) {
	var binding, session secret.Value
	if c, err := r.Cookie(oidcCookie); err == nil {
		binding = secret.New([]byte(c.Value))
	}
	if c, err := r.Cookie(CookieName); err == nil {
		session = secret.New([]byte(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	str := func(v *string) string {
		if v == nil {
			return ""
		}
		return *v
	}
	g, to, err := h.svc.CompleteOIDC(r.Context(), str(p.State), str(p.Code), str(p.Error), str(p.Iss), binding, session, meta(r))
	if err != nil {
		http.Redirect(w, r, "/login?oidc=failed", http.StatusFound)
		return
	}
	if !g.Token.IsZero() {
		setCookie(w, g)
	}
	http.Redirect(w, r, to, http.StatusFound) //nolint:gosec // G710: application returns fixed local routes; no redirect target is accepted from the caller.
}

func providerBody(p app.OIDCProvider, redirect string) openapi.OidcProvider {
	return openapi.OidcProvider{Issuer: p.Issuer, ClientId: p.ClientID, Label: p.Label, ClientSecretSet: len(p.Secret.Ciphertext) > 0, Status: openapi.OidcProviderStatus(p.Status), VerifiedAt: p.VerifiedAt, UpdatedAt: p.UpdatedAt, RedirectUri: redirect}
}

func (h *Handler) writeProvider(w http.ResponseWriter, p app.OIDCProvider) {
	w.Header().Set("ETag", oidcETag(p.Version))
	httpserver.WriteJSON(w, http.StatusOK, providerBody(p, h.svc.OIDCRedirectURI()))
}
func (h *Handler) GetOidcProvider(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId) {
	p, err := h.svc.GetOIDCProvider(r.Context(), current(r), ws, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeProvider(w, p)
}
func (h *Handler) PutOidcProvider(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId, params openapi.PutOidcProviderParams) {
	var body openapi.OidcProviderInput
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	in := app.OIDCProviderInput{Issuer: body.Issuer, ClientID: body.ClientId, Label: body.Label}
	if body.ClientSecret != nil {
		v := secret.New([]byte(*body.ClientSecret))
		in.ClientSecret = &v
	}
	p, err := h.svc.PutOIDCProvider(r.Context(), current(r), ws, in, oidcIfMatch(params.IfMatch), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeProvider(w, p)
}
func (h *Handler) DeleteOidcProvider(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId, p openapi.DeleteOidcProviderParams) {
	if err := h.svc.DeleteOIDCProvider(r.Context(), current(r), ws, oidcIfMatch(p.IfMatch), meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *Handler) GetLoginPolicy(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId) {
	p, err := h.svc.GetLoginPolicy(r.Context(), current(r), ws, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", oidcETag(p.Version))
	httpserver.WriteJSON(w, http.StatusOK, openapi.LoginPolicy{LocalLogin: p.LocalLogin})
}
func (h *Handler) PutLoginPolicy(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId, p openapi.PutLoginPolicyParams) {
	var body openapi.LoginPolicyInput
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	out, err := h.svc.PutLoginPolicy(r.Context(), current(r), ws, body.LocalLogin, oidcIfMatch(p.IfMatch), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", oidcETag(out.Version))
	httpserver.WriteJSON(w, http.StatusOK, openapi.LoginPolicy{LocalLogin: out.LocalLogin})
}
func (h *Handler) GetOwnOidcIdentity(w http.ResponseWriter, r *http.Request) {
	i, err := h.svc.OwnOIDCIdentity(r.Context(), current(r), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.OidcIdentity{Issuer: i.Issuer, LinkedAt: i.LinkedAt, LastLoginAt: i.LastLoginAt})
}
func (h *Handler) UnlinkOwnOidcIdentity(w http.ResponseWriter, r *http.Request) {
	c := current(r)
	if err := h.svc.UnlinkOIDC(r.Context(), c, uuid.Nil, c.View.UserID, meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *Handler) UnlinkMemberOidcIdentity(w http.ResponseWriter, r *http.Request, ws openapi.WorkspaceId, user openapi.UserId) {
	if err := h.svc.UnlinkOIDC(r.Context(), current(r), ws, user, meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
