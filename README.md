# OpenTrusty Admin

OpenTrusty Admin is the **Management Control Plane API** of the OpenTrusty Identity Platform.

It provides a RESTful API for administrative operations such as tenant management, user provisioning, role assignments, and audit log querying.

## Role & Responsibility

- **Tenant API**: Full lifecycle management of tenants (Create, Read, Update, Delete).
- **Provisioning**: Administrative user creation and role assignment.
- **Client Management**: Registration and management of OAuth2/OIDC clients.
- **Audit Logging**: Queryable interface for platform and tenant activity.
- **Architecture**: Pure API consumer of `opentrusty-core`. Serves as the backend for the OpenTrusty Control Panel.

## Requirements

- PostgreSQL (via `DATABASE_URL`)
- OpenTrusty Core (Go module)

## Getting Started

1. Set up environment variables:
   ```bash
   cp .env.example .env
   ```
2. Build the daemon:
   ```bash
   make build
   ```
3. Run the service:
   ```bash
   ./admind
   ```

## Deployment

For production-grade deployment, we recommend using the pre-built binaries available in the [GitHub Releases](https://github.com/opentrusty/opentrusty-admin/releases).

Detailed instructions are available in the [Canonical Deployment Guide](https://github.com/opentrusty/opentrusty-core/blob/main/DEPLOYMENT.md) and the `README.md` included in each release package.

## License


Apache-2.0
