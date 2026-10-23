// Package httpapi exposes the workspace use cases over the OpenAPI
// contract. Authentication happens earlier (identity middleware); every
// authorization decision is made by the application layer.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/qali-project/qali/internal/authz"
	identity "github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	"github.com/qali-project/qali/internal/platform/pagination"
	"github.com/qali-project/qali/internal/platform/secret"
	"github.com/qali-project/qali/internal/workspace/app"
	"github.com/qali-project/qali/internal/workspace/domain"
)

// Handler implements the workspace, invitation, and project operations. It
// does not embed openapi.Unimplemented: process assembly combines it with
// the other module handlers into one openapi.ServerInterface.
type Handler struct {
	svc          *app.Service
	logger       *slog.Logger
	writeSession SessionWriter
}

// SessionWriter sets the session cookie and writes the session body for a
// new account; the identity adapter owns the cookie format.
type SessionWriter func(w http.ResponseWriter, status int, g identity.Grant)

// New returns the handler.
func New(svc *app.Service, logger *slog.Logger, writeSession SessionWriter) *Handler {
	return &Handler{svc: svc, logger: logger, writeSession: writeSession}
}

func meta(r *http.Request) identity.RequestMeta {
	return identity.RequestMeta{IP: httpserver.ClientAddr(r.Context()), RequestID: httpserver.RequestID(r.Context())}
}

func caller(r *http.Request) app.Caller {
	c, _ := identity.CurrentFrom(r.Context())
	return app.CallerFrom(c)
}

func page(limit *int, cursor *string) app.PageRequest {
	p := app.PageRequest{Limit: limit}
	if cursor != nil {
		p.Cursor = *cursor
	}
	return p
}

// ifMatch parses a strong ETag of the form "<version>"; anything else is a
// version that cannot match.
func ifMatch(h *string) *int32 {
	if h == nil || *h == "" {
		return nil
	}
	v, err := strconv.ParseInt(strings.Trim(*h, `"`), 10, 32)
	if err != nil || v < 1 {
		v = -1
	}
	n := int32(v)
	return &n
}

func etag(version int32) string { return `"` + strconv.Itoa(int(version)) + `"` }

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var code string
	switch {
	case errors.Is(err, app.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, app.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, app.ErrRecentMFARequired):
		status, code = http.StatusForbidden, "recent_mfa_required"
	case errors.Is(err, app.ErrInvitationInvalid):
		status, code = http.StatusGone, "invitation_invalid"
	case errors.Is(err, app.ErrAlreadyMember):
		status, code = http.StatusConflict, "already_member"
	case errors.Is(err, identity.ErrAccountExists):
		status, code = http.StatusConflict, "account_exists"
	case errors.Is(err, app.ErrProjectCodeTaken):
		status, code = http.StatusConflict, "project_code_taken"
	case errors.Is(err, domain.ErrLastOwner):
		status, code = http.StatusConflict, "last_owner"
	case errors.Is(err, app.ErrIfMatchRequired):
		status, code = http.StatusPreconditionRequired, "if_match_required"
	case errors.Is(err, app.ErrVersionMismatch):
		status, code = http.StatusPreconditionFailed, "version_mismatch"
	case errors.Is(err, pagination.ErrInvalidCursor):
		status, code = http.StatusBadRequest, "invalid_cursor"
	case errors.Is(err, pagination.ErrInvalidLimit):
		status, code = http.StatusBadRequest, "invalid_limit"
	case errors.Is(err, identity.ErrInvalidInput), errors.Is(err, domain.ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_input"
	case errors.Is(err, identity.ErrWeakPassword):
		status, code = http.StatusBadRequest, "weak_password"
	case errors.Is(err, identity.ErrInvalidEmail):
		status, code = http.StatusBadRequest, "invalid_email"
	case errors.Is(err, context.Canceled):
		// The client went away; nothing failed on the server.
		h.logger.Info("request canceled by the client", "request_id", httpserver.RequestID(r.Context()))
		status, code = httpserver.StatusClientClosedRequest, "request_canceled"
	default:
		h.logger.Error("workspace request failed", "request_id", httpserver.RequestID(r.Context()), "error", err.Error(), "cause", rootCause(err).Error())
		status, code = http.StatusInternalServerError, "internal_error"
	}
	httpserver.WriteProblem(w, r, status, code)
}

func (h *Handler) ListWorkspaces(w http.ResponseWriter, r *http.Request, params openapi.ListWorkspacesParams) {
	p, err := h.svc.ListWorkspaces(r.Context(), caller(r), page(params.Limit, params.Cursor), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := make([]openapi.Workspace, 0, len(p.Items))
	for _, ws := range p.Items {
		items = append(items, workspaceBody(ws))
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.WorkspaceList{Items: items, NextCursor: p.NextCursor})
}

func workspaceBody(ws app.Workspace) openapi.Workspace {
	return openapi.Workspace{Id: ws.ID, Name: ws.Name, Role: openapi.WorkspaceRole(ws.Role), Permissions: ws.Permissions}
}

func (h *Handler) GetWorkspace(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId) {
	ws, err := h.svc.GetWorkspace(r.Context(), caller(r), workspaceID, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, workspaceBody(ws))
}

func memberBody(m app.Member) openapi.Member {
	status := openapi.MemberStatusActive
	if !m.Active {
		status = openapi.MemberStatusDeactivated
	}
	return openapi.Member{
		UserId: m.UserID, Email: m.Email, DisplayName: m.DisplayName, Role: openapi.WorkspaceRole(m.Role),
		Status: status, Version: int(m.Version), CreatedAt: m.CreatedAt.UTC(),
	}
}

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, params openapi.ListMembersParams) {
	p, err := h.svc.ListMembers(r.Context(), caller(r), workspaceID, page(params.Limit, params.Cursor), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := make([]openapi.Member, 0, len(p.Items))
	for _, m := range p.Items {
		items = append(items, memberBody(m))
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.MemberList{Items: items, NextCursor: p.NextCursor})
}

func (h *Handler) UpdateMember(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, userID openapi.UserId, params openapi.UpdateMemberParams) {
	var body openapi.MemberPatch
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	var change domain.MemberChange
	if body.Role != nil {
		role := authz.Role(*body.Role)
		change.Role = &role
	}
	if body.Status != nil {
		if *body.Status != openapi.MemberStatusActive && *body.Status != openapi.MemberStatusDeactivated {
			httpserver.WriteProblem(w, r, http.StatusBadRequest, "invalid_input")
			return
		}
		active := *body.Status == openapi.MemberStatusActive
		change.Active = &active
	}
	m, err := h.svc.UpdateMember(r.Context(), caller(r), workspaceID, userID, change, ifMatch(params.IfMatch), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(m.Version))
	httpserver.WriteJSON(w, http.StatusOK, memberBody(m))
}

func invitationBody(inv app.Invitation) openapi.Invitation {
	return openapi.Invitation{
		Id: inv.ID, Email: inv.Email, Role: openapi.InvitableRole(inv.Role), InvitedBy: inv.InvitedBy,
		CreatedAt: inv.Window.CreatedAt.UTC(), ExpiresAt: inv.Window.ExpiresAt.UTC(),
	}
}

func (h *Handler) CreateInvitation(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId) {
	var body openapi.InvitationCreate
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	var role authz.Role
	if body.Role != nil {
		role = authz.Role(*body.Role)
	}
	created, err := h.svc.CreateInvitation(r.Context(), caller(r), workspaceID, string(body.Email), role, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpserver.WriteJSON(w, http.StatusCreated, openapi.InvitationCreated{
		Invitation: invitationBody(created.Invitation), Token: string(created.Token.Expose()),
	})
}

func (h *Handler) ListInvitations(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, params openapi.ListInvitationsParams) {
	p, err := h.svc.ListInvitations(r.Context(), caller(r), workspaceID, page(params.Limit, params.Cursor), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := make([]openapi.Invitation, 0, len(p.Items))
	for _, inv := range p.Items {
		items = append(items, invitationBody(inv))
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.InvitationList{Items: items, NextCursor: p.NextCursor})
}

func (h *Handler) RevokeInvitation(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, invitationID openapi_types.UUID) {
	if err := h.svc.RevokeInvitation(r.Context(), caller(r), workspaceID, invitationID, meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) PreviewInvitation(w http.ResponseWriter, r *http.Request) {
	var body openapi.InvitationToken
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	p, err := h.svc.PreviewInvitation(r.Context(), secret.New([]byte(body.Token)), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpserver.WriteJSON(w, http.StatusOK, openapi.InvitationPreview{
		WorkspaceName: p.WorkspaceName, Email: p.Email, Role: openapi.InvitableRole(p.Role), ExpiresAt: p.ExpiresAt.UTC(),
	})
}

func (h *Handler) AcceptInvitationNewAccount(w http.ResponseWriter, r *http.Request) {
	var body openapi.InvitationAcceptNew
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	g, err := h.svc.AcceptNewAccount(r.Context(), secret.New([]byte(body.Token)), body.DisplayName, secret.New([]byte(body.Password)), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeSession(w, http.StatusCreated, g)
}

func (h *Handler) AcceptInvitationExistingAccount(w http.ResponseWriter, r *http.Request) {
	var body openapi.InvitationToken
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	ws, err := h.svc.AcceptWithAccount(r.Context(), caller(r), secret.New([]byte(body.Token)), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, workspaceBody(ws))
}

func projectBody(p app.ProjectView) openapi.Project {
	return openapi.Project{
		Id: p.ID, Code: p.Code, Name: p.Name, Visibility: openapi.ProjectVisibility(p.Visibility),
		Version: int(p.Version), CreatedAt: p.CreatedAt.UTC(), Permissions: p.Permissions,
	}
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId) {
	var body openapi.ProjectCreate
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	p, err := h.svc.CreateProject(r.Context(), caller(r), workspaceID, app.NewProject{
		Code: body.Code, Name: body.Name, Visibility: authz.Visibility(body.Visibility),
	}, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(p.Version))
	httpserver.WriteJSON(w, http.StatusCreated, projectBody(p))
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, params openapi.ListProjectsParams) {
	p, err := h.svc.ListProjects(r.Context(), caller(r), workspaceID, page(params.Limit, params.Cursor), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := make([]openapi.Project, 0, len(p.Items))
	for _, proj := range p.Items {
		items = append(items, projectBody(proj))
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.ProjectList{Items: items, NextCursor: p.NextCursor})
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, projectID openapi.ProjectId) {
	p, err := h.svc.GetProject(r.Context(), caller(r), workspaceID, projectID, meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(p.Version))
	httpserver.WriteJSON(w, http.StatusOK, projectBody(p))
}

func projectMemberBody(m app.ProjectMemberView) openapi.ProjectMember {
	return openapi.ProjectMember{
		UserId: m.UserID, Email: m.Email, DisplayName: m.DisplayName,
		Level: openapi.ProjectAccessLevel(m.Level), Version: int(m.Version),
	}
}

func (h *Handler) ListProjectMembers(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, projectID openapi.ProjectId, params openapi.ListProjectMembersParams) {
	p, err := h.svc.ListProjectMembers(r.Context(), caller(r), workspaceID, projectID, page(params.Limit, params.Cursor), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	items := make([]openapi.ProjectMember, 0, len(p.Items))
	for _, m := range p.Items {
		items = append(items, projectMemberBody(m))
	}
	httpserver.WriteJSON(w, http.StatusOK, openapi.ProjectMemberList{Items: items, NextCursor: p.NextCursor})
}

func (h *Handler) AddProjectMember(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, projectID openapi.ProjectId) {
	var body openapi.ProjectMemberAdd
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	m, err := h.svc.AddProjectMember(r.Context(), caller(r), workspaceID, projectID, body.UserId, authz.AccessLevel(body.Level), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(m.Version))
	httpserver.WriteJSON(w, http.StatusCreated, projectMemberBody(m))
}

func (h *Handler) UpdateProjectMember(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, projectID openapi.ProjectId, userID openapi.UserId, params openapi.UpdateProjectMemberParams) {
	var body openapi.ProjectMemberPatch
	if !httpserver.DecodeJSON(w, r, &body) {
		return
	}
	m, err := h.svc.UpdateProjectMember(r.Context(), caller(r), workspaceID, projectID, userID, authz.AccessLevel(body.Level), ifMatch(params.IfMatch), meta(r))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", etag(m.Version))
	httpserver.WriteJSON(w, http.StatusOK, projectMemberBody(m))
}

func (h *Handler) RemoveProjectMember(w http.ResponseWriter, r *http.Request, workspaceID openapi.WorkspaceId, projectID openapi.ProjectId, userID openapi.UserId, params openapi.RemoveProjectMemberParams) {
	if err := h.svc.RemoveProjectMember(r.Context(), caller(r), workspaceID, projectID, userID, ifMatch(params.IfMatch), meta(r)); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
