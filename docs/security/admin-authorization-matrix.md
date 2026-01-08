# Admin Authorization Matrix

| Action | Required Permission | Scope |
| :--- | :--- | :--- |
| Create Tenant | `tenant:create` | Platform |
| List Tenants | `tenant:list` | Platform |
| Provision User | `user:create` | Tenant / Platform |
| Assign Role | `role:assign` | Tenant / Platform |
| Create Client | `client:create` | Tenant |
| Query Audit | `audit:query` | Tenant / Platform |
