// Copyright 2026 The OpenTrusty Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/authz"
	"github.com/opentrusty/opentrusty-core/client"
	"github.com/opentrusty/opentrusty-core/id"
	"github.com/opentrusty/opentrusty-core/role"
	"github.com/opentrusty/opentrusty-core/session"
	"github.com/opentrusty/opentrusty-core/store/postgres"
	"github.com/opentrusty/opentrusty-core/tenant"
	"github.com/opentrusty/opentrusty-core/user"
)

func TestAdminFlow_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db, cleanup := postgres.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	auditLogger := audit.NewSlogLogger() // Use real logger for simplicity, it writes to stdout
	auditRepo := postgres.NewAuditRepository(db)

	// Setup Repos
	userRepo := postgres.NewUserRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	tenantRepo := postgres.NewTenantRepository(db)
	membershipRepo := postgres.NewMembershipRepository(db)

	tenantRoleRepo := postgres.NewTenantRoleRepository(db)
	coreRoleRepo := postgres.NewRoleRepository(db)

	roleAssignmentRepo := postgres.NewAssignmentRepository(db)
	policyAssignmentRepo := postgres.NewPolicyAssignmentRepository(db)

	clientRepo := postgres.NewClientRepository(db)
	projectRepo := postgres.NewProjectRepository(db)

	// Setup Services
	hasher := user.NewPasswordHasher(65536, 1, 1, 16, 32)
	userService := user.NewService(userRepo, hasher, auditLogger, 5, 15*time.Minute, "test-key")
	sessionService := session.NewService(sessionRepo, 24*time.Hour, 1*time.Hour)
	tenantService := tenant.NewService(tenantRepo, tenantRoleRepo, policyAssignmentRepo, userService, clientRepo, membershipRepo, auditLogger)

	authzService := authz.NewService(projectRepo, coreRoleRepo, roleAssignmentRepo)
	clientService := client.NewService(clientRepo, auditLogger)

	handler := NewHandler(
		userService,
		sessionService,
		authzService,
		tenantService,
		clientService,
		auditLogger,
		auditRepo,
		types.SessionConfig{CookieName: "session_id"},
		[]byte("test-key"),
	)

	// 1. Get seeded Platform Admin Role
	platformAdminRole, err := coreRoleRepo.GetByID(ctx, role.RoleIDPlatformAdmin)
	if err != nil {
		t.Fatalf("failed to get platform admin role: %v", err)
	}

	// 2. Seed Admin User
	adminUser := &user.User{
		ID:         id.NewUUIDv7(),
		EmailHash:  "admin-hash",
		EmailPlain: stringPtr("admin@example.com"),
		Profile: user.Profile{
			FullName: "Admin User",
		},
	}
	if err := userRepo.Create(ctx, adminUser); err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	// 3. Assign Role
	assignment := &role.Assignment{
		ID:        id.NewUUIDv7(),
		UserID:    adminUser.ID,
		RoleID:    platformAdminRole.ID,
		Scope:     role.ScopePlatform,
		GrantedAt: time.Now(),
		GrantedBy: adminUser.ID,
	}
	if err := roleAssignmentRepo.Grant(ctx, assignment); err != nil {
		t.Fatalf("failed to grant platform admin role: %v", err)
	}

	// 4. Test Create Tenant
	t.Run("Create Tenant", func(t *testing.T) {
		reqBody := map[string]string{
			"name":        "Test Tenant",
			"admin_email": "tenant-admin@example.com",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/tenants", bytes.NewReader(bodyBytes))

		// Inject User ID into context (simulating authenticated request)
		ctxWithUser := context.WithValue(req.Context(), types.UserIDKey, adminUser.ID)
		req = req.WithContext(ctxWithUser)

		rr := httptest.NewRecorder()
		handler.CreateTenant(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201 Created, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if resp["name"] != "Test Tenant" {
			t.Errorf("expected tenant name 'Test Tenant', got %v", resp["name"])
		}
	})
}

func stringPtr(s string) *string {
	return &s
}
