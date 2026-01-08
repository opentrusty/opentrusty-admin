# AI_CONTRACT — opentrusty-admin

## Scope of Responsibility
- Management API for Administrative operations.
- Tenant, User, and OAuth2 Client lifecycle management.
- Audit log querying and reporting.
- Platform and Tenant authority management.

## Explicit Non-Goals
- **NO OIDC Protocol**: Does not handle authorize, token, or discovery endpoints.
- **NO Bootstrap**: Initial system initialization logic resides in the CLI.
- **NO Login UI**: Does not serve server-side authentication pages.

## Allowed Dependencies
- `github.com/opentrusty/opentrusty-core`

## Forbidden Dependencies
- **NO dependencies** on `opentrusty-auth` or `opentrusty-control-panel`.

## Change Discipline
- Any modification to API surface MUST update OpenAPI specs and docs/api/README.md.
- Changes to permission requirements MUST be reflected in docs/security/admin-authorization-matrix.md.

## Invariants
- **Namespace Isolation**: MUST enforce "admin" namespace for management sessions.
- **CSRF Protection**: All state-changing management operations MUST require CSRF validation.
