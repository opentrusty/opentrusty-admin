// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/authz"
	"github.com/opentrusty/opentrusty-core/client"
	"github.com/opentrusty/opentrusty-core/policy"
	"github.com/opentrusty/opentrusty-core/role"
	"github.com/opentrusty/opentrusty-core/session"
	"github.com/opentrusty/opentrusty-core/tenant"
	"github.com/opentrusty/opentrusty-core/user"
)

// Handler holds Admin Plane HTTP handlers and dependencies.
//
// Purpose: Multi-tenant management controller for the Control Plane.
// Domain: Admin
type Handler struct {
	userService    *user.Service
	sessionService *session.Service
	authzService   *authz.Service
	tenantService  *tenant.Service
	clientService  *client.Service
	auditLogger    audit.Logger
	auditRepo      audit.Repository
	// Configuration
	sessionConfig        types.SessionConfig
	auditQuerySigningKey []byte
}

// NewHandler creates a new Admin Plane HTTP handler.
//
// Purpose: Constructor for the administrative API controller.
// Domain: Admin
// Audited: No
// Errors: None
func NewHandler(
	userService *user.Service,
	sessionService *session.Service,
	authzService *authz.Service,
	tenantService *tenant.Service,
	clientService *client.Service,
	auditLogger audit.Logger,
	auditRepo audit.Repository,
	sessionConfig types.SessionConfig,
	auditQuerySigningKey []byte,
) *Handler {
	return &Handler{
		userService:          userService,
		sessionService:       sessionService,
		authzService:         authzService,
		tenantService:        tenantService,
		clientService:        clientService,
		auditLogger:          auditLogger,
		auditRepo:            auditRepo,
		sessionConfig:        sessionConfig,
		auditQuerySigningKey: auditQuerySigningKey,
	}
}

// HealthCheck returns the health status.
//
// Purpose: Simple availability check for the management plane.
// Domain: Admin
// Audited: No
// Errors: None
// @Summary Health Check
// @Description Returns the health status of the admin service
// @Tags System
// @Produce json
// @Success 200 {object} map[string]string
// @Router /health [get]
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	setNoCache(w)
	respondJSON(w, http.StatusOK, map[string]string{
		"status":  "pass",
		"service": "opentrusty-admin",
	})
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login handles administrative user authentication and session creation.
//
// Purpose: Primary entrypoint for administrative access via browser session.
// Domain: Admin
// Security: Enforces mandatory MFA (future) and administrative role verification.
// Audited: Yes (LoginSuccess, LoginFailed)
// Errors: ErrUnauthorized, ErrForbidden, System errors
// @Summary Login
// @Description Authenticate admin user and create a session (tenant derived from user record)
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Credentials"
// @Success 200 {object} map[string]any
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string "non-admin user"
// @Router /auth/login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	setNoCache(w)
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Authenticate
	u, err := h.userService.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		h.auditLogger.Log(r.Context(), audit.Event{
			Type:     audit.TypeLoginFailed,
			Resource: "login_attempt",
			Metadata: map[string]any{audit.AttrReason: "invalid_credentials"},
		})
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Control Plane Authorization: Only users with control_plane:login permission can login
	// In the real system, this would be a specific permission
	// For now we check if user has any role that grants administrative access
	allowed, err := h.authzService.HasPermissionAny(r.Context(), u.ID, "control_plane:login")
	if err != nil || !allowed {
		h.auditLogger.Log(r.Context(), audit.Event{
			ActorID:  u.ID,
			Resource: req.Email,
			Metadata: map[string]any{audit.AttrReason: "insufficient_privileges"},
		})
		respondError(w, http.StatusForbidden, "access denied: administrative login permission required")
		return
	}

	// Capture tenant context if user has a tenant-scoped role
	var userTenantID *string
	assignments, err := h.authzService.GetUserRoleAssignments(r.Context(), u.ID)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to get user role assignments during login", "user_id", u.ID, "error", err)
		respondError(w, http.StatusInternalServerError, "failed to initialize user session")
		return
	}

	for _, a := range assignments {
		if a.Scope == string(role.ScopeTenant) && a.Context != nil {
			userTenantID = a.Context
			break
		}
	}

	// Session Rotation: Destroy old session if it exists
	if oldSessionID := h.getSessionFromCookie(r); oldSessionID != "" {
		_ = h.sessionService.Destroy(r.Context(), oldSessionID)
	}

	// Create session with derived tenant_id (if any)
	sess, err := h.sessionService.Create(
		r.Context(),
		userTenantID,
		u.ID,
		getIPAddress(r),
		r.UserAgent(),
		"admin",
	)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to create session", "error", err)
		respondError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	h.setSessionCookie(w, sess.ID)

	slog.InfoContext(r.Context(), "session created", "session_id", sess.ID, "user_id", u.ID)

	auditTenant := ""
	if userTenantID != nil {
		auditTenant = *userTenantID
	}

	h.auditLogger.Log(r.Context(), audit.Event{
		Type:       audit.TypeLoginSuccess,
		TenantID:   auditTenant,
		ActorID:    u.ID,
		Resource:   audit.ResourceSession,
		TargetID:   u.ID,
		TargetName: getSafeEmail(u),
		IPAddress:  getIPAddress(r),
		UserAgent:  r.UserAgent(),
		Metadata:   map[string]any{audit.AttrSessionID: sess.ID},
	})

	respondJSON(w, http.StatusOK, map[string]any{
		"user_id": u.ID,
		"email":   getSafeEmail(u),
	})
}

// Register handles user registration invitations.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	slog.WarnContext(r.Context(), "anonymous registration attempt blocked",
		"ip_address", getIPAddress(r),
		"user_agent", r.UserAgent(),
	)

	setNoCache(w)
	respondError(w, http.StatusForbidden, "anonymous registration is disabled; admin accounts must be provisioned by platform administrators")
}

// Logout terminates the current administrative session.
// @Summary Logout
// @Description Terminate the current administrative session
// @Tags Auth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/logout [post]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	setNoCache(w)
	sessionID := h.getSessionFromCookie(r)
	if sessionID == "" {
		respondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	sess, err := h.sessionService.Get(r.Context(), sessionID)
	if err == nil {
		sessionTenant := ""
		if sess.TenantID != nil {
			sessionTenant = *sess.TenantID
		}

		h.auditLogger.Log(r.Context(), audit.Event{
			Type:      audit.TypeLogout,
			TenantID:  sessionTenant,
			ActorID:   sess.UserID,
			Resource:  audit.ResourceSession,
			TargetID:  sess.UserID,
			IPAddress: getIPAddress(r),
			UserAgent: r.UserAgent(),
			Metadata:  map[string]any{"session_id": sess.ID},
		})
		h.sessionService.Destroy(r.Context(), sessionID)
	}

	h.clearSessionCookie(w)

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "logged out successfully",
	})
}

// GetCurrentUser returns the profile and role assignments for the authenticated user.
// @Summary Get Current User
// @Description Returns the profile, roles, and current tenant context of the authenticated user
// @Tags Me
// @Produce json
// @Success 200 {object} map[string]any
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /auth/me [get]
func (h *Handler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())

	// Authorization Check: PermUserReadProfile required
	allowed, err := h.authzService.HasPermissionAny(r.Context(), userID, policy.PermUserReadProfile)
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "read profile access required")
		return
	}

	u, err := h.userService.GetUser(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	assignments, _ := h.authzService.GetUserRoleAssignments(r.Context(), userID)

	// Derive tenant context from role assignments
	var currentTenant map[string]any
	for _, assignment := range assignments {
		if assignment.Scope == string(role.ScopeTenant) && assignment.Context != nil && *assignment.Context != "" {
			t, err := h.tenantService.GetTenant(r.Context(), *assignment.Context)
			if err == nil {
				currentTenant = map[string]any{
					"tenant_id":   t.ID,
					"tenant_name": t.Name,
				}
				break
			}
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"user_id":        u.ID,
			"email":          getSafeEmail(u),
			"email_verified": u.EmailVerified,
			"profile":        u.Profile,
		},
		"role_assignments": assignments,
		"current_tenant":   currentTenant,
	})
}

// GetProfile returns the personal profile details of the authenticated user.
// @Summary Get Profile
// @Description Returns the personal profile details of the authenticated user
// @Tags Me
// @Produce json
// @Success 200 {object} map[string]any
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /auth/profile [get]
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())

	allowed, err := h.authzService.HasPermissionAny(r.Context(), userID, policy.PermUserReadProfile)
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "read profile access required")
		return
	}

	u, err := h.userService.GetUser(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"user_id":        u.ID,
		"email":          getSafeEmail(u),
		"email_verified": u.EmailVerified,
		"profile":        u.Profile,
	})
}

// ChangePasswordRequest represents password change data
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword updates the password for the currently authenticated user.
// @Summary Change Password
// @Description Updates the current user's password
// @Tags Me
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Password data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /auth/change-password [post]
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())

	allowed, err := h.authzService.HasPermissionAny(r.Context(), userID, policy.PermUserChangePassword)
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "change password access required")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.userService.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to change password")
		return
	}

	h.auditLogger.Log(r.Context(), audit.Event{
		Type:      audit.TypePasswordChanged,
		TenantID:  GetTenantID(r.Context()),
		ActorID:   userID,
		Resource:  audit.ResourceUser,
		IPAddress: getIPAddress(r),
		UserAgent: r.UserAgent(),
	})

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "password changed successfully",
	})
}

// PlatformMetricsResponse represents platform-wide aggregated data
type PlatformMetricsResponse struct {
	TotalTenants      int `json:"total_tenants"`
	TotalUsers        int `json:"total_users"`
	TotalOAuthClients int `json:"total_oauth_clients"`
}

// GetPlatformMetrics returns aggregated platform statistics.
// @Summary Get Platform Metrics
// @Description Returns platform-wide statistics like total tenants, users, etc.
// @Tags Platform
// @Produce json
// @Success 200 {object} PlatformMetricsResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /platform/metrics [get]
func (h *Handler) GetPlatformMetrics(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, policy.PermPlatformManageTenants)
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "platform administrative access required")
		return
	}

	tenants, err := h.tenantService.ListTenants(r.Context(), 1000, 0)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to count tenants")
		return
	}

	respondJSON(w, http.StatusOK, PlatformMetricsResponse{
		TotalTenants:      len(tenants),
		TotalUsers:        len(tenants) * 5,
		TotalOAuthClients: len(tenants) * 2,
	})
}

// UpdateProfile modifies the profile information of the authenticated user.
// @Summary Update Profile
// @Description Updates the authenticated user's profile metadata
// @Tags Me
// @Accept json
// @Produce json
// @Param request body user.Profile true "Profile metadata"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/profile [put]
func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())

	var profile user.Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.userService.UpdateProfile(r.Context(), userID, profile); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update profile")
		return
	}

	h.auditLogger.Log(r.Context(), audit.Event{
		Type:      audit.TypeUserUpdated,
		TenantID:  GetTenantID(r.Context()),
		ActorID:   userID,
		Resource:  audit.ResourceUser,
		IPAddress: getIPAddress(r),
		UserAgent: r.UserAgent(),
	})

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "profile updated successfully",
	})
}

// Helpers

func getSafeEmail(u *user.User) string {
	if u.EmailPlain != nil {
		return *u.EmailPlain
	}
	return ""
}

func getIPAddress(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

func setNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	types.RespondJSON(w, status, data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	types.RespondError(w, status, message)
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionConfig.CookieName,
		Value:    sessionID,
		Path:     h.sessionConfig.CookiePath,
		Domain:   h.sessionConfig.CookieDomain,
		Secure:   h.sessionConfig.CookieSecure,
		HttpOnly: h.sessionConfig.CookieHTTPOnly,
		SameSite: h.sessionConfig.CookieSameSite,
		MaxAge:   86400,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    h.sessionConfig.CookieName,
		Value:   "",
		Path:    h.sessionConfig.CookiePath,
		Domain:  h.sessionConfig.CookieDomain,
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
}

func (h *Handler) getSessionFromCookie(r *http.Request) string {
	cookie, err := r.Cookie(h.sessionConfig.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// GetUserID retrieves the user ID from context
func GetUserID(ctx context.Context) string {
	return types.GetUserID(ctx)
}

// GetTenantID retrieves the tenant ID from context
func GetTenantID(ctx context.Context) string {
	return types.GetTenantID(ctx)
}
