# Roles and Permissions

Status: normative security design  
Default posture: deny unless explicitly granted

## 1. Authorization model

An authorization decision requires all of the following:

```text
authenticated principal
AND active workspace membership
AND role permission
AND project/resource access
AND credential scope
AND applicable security policy
AND resource-state rule
```

Possessing a URL, UUID, API token, integration installation, or MCP connection is
never sufficient by itself. Backend application services make decisions; UI
visibility is only a convenience.

## 2. Principal types

- Human user: interactive UI/API access.
- Service account: non-human identity owned by a workspace and restricted to
  named projects and scopes.
- CI credential: append-oriented automation identity; cannot log into the UI.
- Integration installation: provider-specific identity restricted to its mapped
  projects, repositories, and callback actions.
- OAuth/MCP client grant: acts for a human or service account with the narrower
  of principal permissions and approved scopes.
- Operator: deployment-level diagnostics and recovery. Operator access does not
  imply tenant content access; exceptional access is explicit and audited.

## 3. Built-in workspace roles

| Role | Purpose | Administrative access |
|---|---|---|
| Owner | Legal/security authority for one workspace | Full; ownership transfer and break-glass policy |
| Workspace Administrator | Identity, roles, security, integrations, retention, audit | Full except ownership transfer and protected owner actions |
| Project Administrator | Manage assigned projects, membership, fields, workflows | No workspace identity/security/integration administration |
| QA Lead | Curate repository, approve reviews, manage plans/runs and reports | No workspace or project security configuration |
| Tester | Author permitted cases and execute assigned testing | None; no users, roles, tokens, integrations, or settings |
| Developer | Read test assets/results, comment, and work with linked defects | None |
| Viewer/Auditor | Read/export explicitly shared data | None; immutable, no comments by default |

Custom roles compose granular permissions but cannot grant owner-only actions.
`Tester` is the default invitation role unless an administrator chooses a more
restrictive default. It must not create projects, manage project membership,
configure fields/workflows, install integrations, issue service credentials,
view security settings, or read the audit/security log.

## 4. Permission families

Permissions use stable names and are checked as actions, not inferred from menu
access. Representative families:

- `workspace`: read, update, transfer_ownership, delete.
- `security`: read, update, manage_sso, manage_scim, manage_sessions,
  manage_break_glass, rotate_keys.
- `members`: invite, read, update_role, deactivate, manage_groups.
- `roles`: read, create, update, delete, set_default.
- `projects`: create, read, update, archive, delete, manage_access,
  manage_settings.
- `repository`: read, create, update, delete, restore, purge, bulk_update, export.
- `reviews`: read, submit, approve, request_changes, merge, configure.
- `plans` and `runs`: create, read, update, delete, execute, assign, complete,
  schedule, trigger_pipeline, export.
- `results`: read, submit_manual, submit_automation, correct, attach, export.
- `requirements` and `defects`: create, read, update, delete, link_external.
- `reports`: read, create_dashboard, share_dashboard, query, export.
- `integrations`: read, install, configure, rotate_secret, retry_delivery, remove.
- `credentials`: manage_own, manage_service_accounts, manage_ci, manage_oauth.
- `mcp`: connect, read_tools, write_tools, destructive_tools.
- `ai_integrations`: use_read, use_write, manage, approve_high_risk_action.
- `audit`: read, export, configure_retention.
- `operations`: read_diagnostics, manage_jobs, backup, restore.

## 5. Default capability matrix

Legend: `A` all actions in the family, `L` limited as described, `R` read only,
`-` denied. Project access is still required for every project-owned action.

| Capability | Owner | Workspace Admin | Project Admin | QA Lead | Tester | Developer | Viewer |
|---|---:|---:|---:|---:|---:|---:|---:|
| Workspace/security | A | L | - | - | - | - | - |
| Members/groups/roles | A | A | L project membership | - | - | - | - |
| Project settings/access | A | A | A assigned | - | - | - | - |
| Repository authoring | A | A | A | A | L assigned projects | R/comment | R |
| Review approval/merge | A | A | A | A | L if granted | - | R |
| Plans and run management | A | A | A | A | L create/assigned | R/comment | R |
| Manual execution | A | A | A | A | A assigned | L if assigned | - |
| Automation submission | A | A | A | L | - | - | - |
| Requirements/defects | A | A | A | A | L | L defects | R |
| Reports/query/export | A | A | A | A | L | L | R if granted |
| Integrations/webhooks | A | A | L project-owned | - | - | - | - |
| Service/CI/OAuth credentials | A | A | L project CI | - | - | - | - |
| Audit/security events | A | A | R project events | - | - | - | - |
| AI integration management | A | A | L project policy | - | - | - | - |

Workspace Administrator limitations: cannot transfer/delete the workspace,
demote the last Owner, disable the Owner's recovery path, or access protected
private projects without an explicit, audited access grant.

## 6. Project access

- Public-to-workspace: visible to active members, but actions still require role
  permission.
- Restricted: only direct members and mapped groups can discover it.
- Access levels: project administrator, contributor, executor, commenter, viewer.
- Effective project permission is the intersection of role and project level,
  never the union. A permissive project membership cannot elevate a restrictive
  workspace role.
- Group removal and user deactivation revoke access immediately and invalidate
  relevant sessions/grants; historical attribution remains. In the MVP,
  member deactivation is workspace-local: the user's sessions stay valid for
  other workspaces, and credentials bound to the workspace stop working
  (ADR-0013).

## 7. Credential rules

- Personal tokens inherit current user permissions but may only reduce them with
  scopes; role changes take effect immediately.
- CI credentials are project-bound and default to `runs:create`,
  `results:submit`, `artifacts:upload`, and `runs:complete`. They cannot read the
  repository in bulk, create users, configure projects, or trigger pipelines.
- Service accounts have an owner, purpose, expiry, project allowlist, scopes, and
  last-used metadata. Owner deactivation does not silently orphan them.
- Integration credentials can only execute provider callback and synchronization
  actions for the installation's mapped resources.
- OAuth access uses the intersection of actor, client, consented scopes, audience,
  and project grant. Refresh never broadens access.

## 8. Sensitive operations

The following require recent MFA/strong-auth confirmation, a CSRF-protected
browser flow, and a high-severity audit event:

- ownership transfer or workspace deletion;
- SSO/SCIM enforcement and break-glass changes;
- role/default-role changes and administrator assignment;
- integration install/removal or secret reveal/rotation;
- issuing service, SCIM, CI administration, or OAuth client credentials;
- key rotation, audit retention reduction, backup restore, or permanent purge;
- enabling external AI egress or destructive MCP/AI tools.

The last Owner cannot be removed or deactivated through ordinary workflows.

## 9. Verification requirements

- Maintain a machine-readable permission catalog and generated policy matrix.
- Table-driven tests cover every built-in role/action combination.
- Integration tests cover guessed IDs, cross-workspace and cross-project access,
  list/search/count/export leaks, indirect object references, background jobs,
  notifications, API, webhooks, SCIM, OAuth, and MCP.
- Frontend tests ensure restricted controls are hidden, but backend denial tests
  remain authoritative.
- Policy changes invalidate caches and active high-risk grants immediately.

