# ADR-0001: Product identity, module path, and license

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

`docs/IMPLEMENTATION_PLAN.md` section 12 requires the project name, module path,
and license to be decided before implementation. Technical identifiers leak into
the Go module path, binary name, environment variables, token prefixes, cookie
names, metrics, and container image names. Changing them after MVP-01 is costly,
and token prefixes are part of the credential model frozen by MVP-00.

The maintainer has not yet chosen the public product name.

## Decision

1. **Technical identifier.** The stable technical identifier is `qali`. It is
   used for the binary (`qali`), environment variables (`QALI_` prefix), token
   prefixes (`qali_`, see ADR-0006), cookie names (`__Host-qali_` prefix),
   metrics namespace (`qali_`), and the image repository name (`qali`).
   This identifier is frozen for the MVP independently of the display name.
2. **Display name.** The public product name is not decided. Until it is, user
   interface text and documentation use the working name "Qali". The display
   name must be defined in a single frontend constant and a single backend
   constant so a later rename touches presentation only, not migrations, API
   shapes, credentials, or roles.
3. **Go module path.** `github.com/qali-project/qali`. No hosted repository or
   remote is created at this time; the module path is an import identifier only.
4. **License.** Apache License 2.0 for all source, documentation, and examples.
   The `LICENSE` file is added with the repository skeleton in MVP-01. Each
   third-party dependency must have a license compatible with Apache-2.0;
   license scanning is part of the MVP-01 gates.
5. **Security reporting.** Until a hosted repository exists, vulnerability
   reports go to the maintainer privately. `SECURITY.md` with a disclosure
   address and supported-version policy is added in MVP-01 and updated at
   MVP-15.

## Consequences

- Renaming the product later is a presentation change. Renaming the technical
  identifier would be a breaking change requiring a new ADR and migration notes.
- Choosing a hosting service later does not change the module path unless a
  new ADR says so; a vanity import path can redirect to any host.

## Alternatives considered

- Wait for the final name before MVP-01: rejected; it blocks the credential
  model and every later item for a presentation concern.
- AGPL-3.0: rejected by the maintainer; Apache-2.0 includes a patent grant and
  is friendlier to self-hosting organizations.
- MIT: rejected; no explicit patent grant.
