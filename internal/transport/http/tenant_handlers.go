// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/role"
	"github.com/opentrusty/opentrusty-core/user"
)

// CreateTenantRequest represents tenant creation data
type CreateTenantRequest struct {
	Name       string `json:"name" binding:"required"`
	AdminEmail string `json:"admin_email,omitempty"`
	AdminName  string `json:"admin_name,omitempty"`
}

// CreateTenant handles tenant creation
func (h *Handler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:manage_tenants")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "platform administrative access required")
		return
	}

	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	adminPassword, _ := generateRandomPassword(16)

	t, err := h.tenantService.CreateTenant(r.Context(), req.Name, req.AdminEmail, adminPassword, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create tenant: "+err.Error())
		return
	}

	response := map[string]any{
		"id":         t.ID,
		"name":       t.Name,
		"status":     t.Status,
		"created_at": t.CreatedAt,
		"updated_at": t.UpdatedAt,
	}

	if req.AdminEmail != "" {
		response["admin_email"] = req.AdminEmail
		response["admin_password"] = adminPassword
		response["password_warning"] = "This password will not be shown again. Please copy it now."
	}

	respondJSON(w, http.StatusCreated, response)
}

// ListTenants handles listing all tenants
func (h *Handler) ListTenants(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:manage_tenants")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "platform admin administrative access required")
		return
	}

	tenants, err := h.tenantService.ListTenants(r.Context(), 100, 0)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list tenants")
		return
	}

	respondJSON(w, http.StatusOK, tenants)
}

// GetTenant returns details of a specific tenant
func (h *Handler) GetTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:view")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "tenant view access required")
		return
	}

	t, err := h.tenantService.GetTenant(r.Context(), tenantID)
	if err != nil {
		respondError(w, http.StatusNotFound, "tenant not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"id":         t.ID,
		"name":       t.Name,
		"status":     t.Status,
		"created_at": t.CreatedAt,
		"updated_at": t.UpdatedAt,
	})
}

// UpdateTenantRequest represents tenant update data
type UpdateTenantRequest struct {
	Name string `json:"name"`
}

// UpdateTenant handles tenant updates
func (h *Handler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:manage_tenants")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "platform administrative access required")
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updatedTenant, err := h.tenantService.UpdateTenant(r.Context(), tenantID, req.Name, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update tenant")
		return
	}

	respondJSON(w, http.StatusOK, updatedTenant)
}

// DeleteTenant handles tenant deletion
func (h *Handler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:manage_tenants")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "platform administrative access required")
		return
	}

	err = h.tenantService.DeleteTenant(r.Context(), tenantID, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete tenant")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// GetTenantMetrics returns summary statistics for a tenant
func (h *Handler) GetTenantMetrics(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:view")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "tenant view access required")
		return
	}

	// For Beta, we return simplified counts
	users, _ := h.tenantService.GetTenantUsers(r.Context(), tenantID)

	respondJSON(w, http.StatusOK, map[string]any{
		"total_users":     len(users),
		"total_clients":   3,  // Placeholder
		"audit_count_24h": 12, // Placeholder
	})
}

// ProvisionUserRequest represents user provisioning data
type ProvisionUserRequest struct {
	Email      string `json:"email" binding:"required"`
	Password   string `json:"password"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Role       string `json:"role"`
}

// ProvisionTenantUser handles provisioning a user in a tenant
func (h *Handler) ProvisionTenantUser(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	var req ProvisionUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:manage_users")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "tenant administrative access required")
		return
	}

	if req.Role == "" {
		req.Role = role.RoleTenantMember
	}

	// 1. Check if user exists globally
	u, err := h.userService.GetByEmail(r.Context(), req.Email)
	if err != nil {
		// Create user
		if req.Password == "" {
			respondError(w, http.StatusBadRequest, "password is required for new user")
			return
		}
		profile := user.Profile{
			GivenName:  req.GivenName,
			FamilyName: req.FamilyName,
			FullName:   req.GivenName + " " + req.FamilyName,
		}
		u, err = h.userService.ProvisionIdentity(r.Context(), req.Email, profile)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to provision user")
			return
		}

		if err := h.userService.AddPassword(r.Context(), u.ID, req.Password); err != nil {
			respondError(w, http.StatusBadRequest, "failed to set password")
			return
		}
	}

	// 2. Assign role
	err = h.tenantService.AssignRole(r.Context(), tenantID, u.ID, req.Role, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to assign role")
		return
	}

	// 3. Audit Log
	h.auditLogger.Log(r.Context(), audit.Event{
		Type:       audit.TypeUserCreated,
		TenantID:   tenantID,
		ActorID:    userID,
		Resource:   audit.ResourceUser,
		TargetID:   u.ID,
		TargetName: req.Email,
	})

	respondJSON(w, http.StatusOK, map[string]any{
		"user_id": u.ID,
		"role":    req.Role,
	})
}

// ListTenantUsers lists users with roles
func (h *Handler) ListTenantUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:view")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "tenant view access required")
		return
	}

	users, err := h.tenantService.GetTenantUsers(r.Context(), tenantID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, users)
}

// Helper function to generate random password
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[num.Int64()]
	}
	return string(b), nil
}
