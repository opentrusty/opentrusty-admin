# OpenTrusty Admin API

This directory contains the documentation and specifications for the Management Control Plane API.

## Overview

The Admin API provides endpoints for programmatic management of the OpenTrusty system.

## Specifications

- **OpenAPI**: `docs/api/openapi.yaml` (coming soon)
- **Authorization**: All endpoints except `/health` require an active administrative session.

## Namespaces

- `/tenants`: Tenant lifecycle.
- `/users`: Provisioning and membership.
- `/clients`: OAuth2/OIDC client configuration.
- `/audit`: Activity log queries.
