# Permission matrix

<!-- Generated from permission-catalog.json by `make docs-generate`. Do not edit. -->

Generated from [the permission catalog](permission-catalog.json), version 1.
Cells show the grant condition; `-` means denied. Project-scoped permissions
also require project access, capped by the project access level.

Conditions:

- `all`: Every resource of this type the principal can reach through workspace membership and project access.
- `own`: Only resources the principal created.
- `assigned`: Only run cases assigned to the principal, or not assigned to anyone, in runs the principal can access.

## Role grants

| Permission | Kind | Admin | Owner | Workspace Administrator | QA Lead | Tester | Viewer |
|---|---|---|---|---|---|---|---|
| `workspace.read` | read | no | all | all | all | all | all |
| `workspace.update` | write | yes | all | all | - | - | - |
| `workspace.transfer_ownership` | write | yes | all | - | - | - | - |
| `security.read` | read | yes | all | all | - | - | - |
| `security.update` | write | yes | all | all | - | - | - |
| `security.manage_sso` | write | yes | all | all | - | - | - |
| `security.manage_sessions` | write | yes | all | all | - | - | - |
| `security.manage_break_glass` | write | yes | all | - | - | - | - |
| `members.read` | read | yes | all | all | - | - | - |
| `members.invite` | write | yes | all | all | - | - | - |
| `members.update_role` | write | yes | all | all | - | - | - |
| `members.deactivate` | write | yes | all | all | - | - | - |
| `projects.create` | write | yes | all | all | - | - | - |
| `projects.read` | read | no | all | all | all | all | all |
| `projects.update` | write | yes | all | all | - | - | - |
| `projects.archive` | write | yes | all | all | - | - | - |
| `projects.manage_access` | write | yes | all | all | - | - | - |
| `repository.read` | read | no | all | all | all | all | all |
| `repository.create` | write | no | all | all | all | all | - |
| `repository.update` | write | no | all | all | all | all | - |
| `repository.delete` | write | no | all | all | all | own | - |
| `repository.restore` | write | no | all | all | all | own | - |
| `plans.read` | read | no | all | all | all | all | all |
| `plans.create` | write | no | all | all | all | all | - |
| `plans.update` | write | no | all | all | all | own | - |
| `plans.delete` | write | no | all | all | all | - | - |
| `runs.read` | read | no | all | all | all | all | all |
| `runs.create` | write | no | all | all | all | all | - |
| `runs.update` | write | no | all | all | all | own | - |
| `runs.delete` | write | no | all | all | all | - | - |
| `runs.assign` | write | no | all | all | all | - | - |
| `runs.execute` | write | no | all | all | all | assigned | - |
| `runs.complete` | write | no | all | all | all | own | - |
| `results.read` | read | no | all | all | all | all | all |
| `results.submit_manual` | write | no | all | all | all | assigned | - |
| `results.attach` | write | no | all | all | all | assigned | - |
| `defects.read` | read | no | all | all | all | all | all |
| `defects.create` | write | no | all | all | all | all | - |
| `defects.update` | write | no | all | all | all | all | - |
| `defects.delete` | write | no | all | all | all | - | - |
| `defects.link_external` | write | no | all | all | all | all | - |
| `reports.read` | read | no | all | all | all | all | all |
| `reports.export` | read | no | all | all | all | all | - |
| `integrations.read` | read | yes | all | all | - | - | - |
| `integrations.install` | write | yes | all | all | - | - | - |
| `integrations.configure` | write | yes | all | all | - | - | - |
| `integrations.rotate_secret` | write | yes | all | all | - | - | - |
| `integrations.retry_delivery` | write | yes | all | all | - | - | - |
| `integrations.remove` | write | yes | all | all | - | - | - |
| `credentials.manage_ci` | write | yes | all | all | - | - | - |
| `mcp.connect` | write | no | all | all | all | - | - |
| `mcp.read_tools` | read | no | all | all | all | - | - |
| `audit.read` | read | yes | all | all | - | - | - |
| `audit.export` | read | yes | all | all | - | - | - |
| `operations.read_diagnostics` | read | yes | all | all | - | - | - |
| `operations.manage_jobs` | write | yes | all | all | - | - | - |

## Sensitive and owner-only permissions

- `workspace.transfer_ownership` (owner-only) (recent MFA, high-severity audit)
- `security.update` (recent MFA, high-severity audit)
- `security.manage_sso` (recent MFA, high-severity audit)
- `security.manage_break_glass` (owner-only) (recent MFA, high-severity audit)
- `members.update_role` (recent MFA, high-severity audit)
- `integrations.install` (recent MFA, high-severity audit)
- `integrations.rotate_secret` (recent MFA, high-severity audit)
- `integrations.remove` (recent MFA, high-severity audit)
- `credentials.manage_ci` (recent MFA, high-severity audit)
- `audit.export` (recent MFA, high-severity audit)
- `operations.read_diagnostics` (recent MFA, high-severity audit)

## Project access levels

| Level | Maximum kind | Description |
|---|---|---|
| `contributor` | write | Role grants apply in full within the project. |
| `viewer` | read | Only read-kind role grants apply within the project. |

## Credential types

| Type | Token prefix | Scopes |
|---|---|---|
| `session` | `qali_sess_` | - |
| `password_reset` | `qali_reset_` | - |
| `invitation` | `qali_inv_` | - |
| `setup` | `qali_setup_` | - |
| `ci` | `qali_ci_` | `runs:create`, `results:submit`, `artifacts:upload`, `runs:complete` |
| `mcp` | `qali_mcp_` | `mcp:read` |
