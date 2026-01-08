// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/role"
)

// AuditEventResponse represents an audit event in API responses
type AuditEventResponse struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	TenantID   string         `json:"tenant_id,omitempty"`
	ActorID    string         `json:"actor_id"`
	ActorName  string         `json:"actor_name,omitempty"`
	TargetName string         `json:"target_name,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	Resource   string         `json:"resource"`
	IPAddress  string         `json:"ip_address,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	CreatedAt  string         `json:"created_at"`
}

// ListAuditEventsResponse represents the audit events list response
type ListAuditEventsResponse struct {
	Events []AuditEventResponse `json:"events"`
	Total  int                  `json:"total"`
}

// CreateAuditQueryRequest represents a request to declare audit intent
type CreateAuditQueryRequest struct {
	TenantID  string    `json:"tenant_id"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Reason    string    `json:"reason"`
}

// AuditQueryResponse represents the created query ID
type AuditQueryResponse struct {
	ID string `json:"id"`
}

// AuditQueryClaims represents the signed claims for a scoped audit query
type AuditQueryClaims struct {
	TenantID  string `json:"tenant_id"`
	StartDate int64  `json:"start_date"`
	EndDate   int64  `json:"end_date"`
	Reason    string `json:"reason"`
	jwt.RegisteredClaims
}

// ListTenantAuditEvents lists audit events for a specific tenant
func (h *Handler) ListTenantAuditEvents(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant ID is required")
		return
	}

	userID := GetUserID(r.Context())
	sessionTenantID := types.GetSessionTenantID(r.Context())

	if sessionTenantID == "" {
		isPlatformAdmin, _ := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:view_audit")
		if !isPlatformAdmin {
			respondError(w, http.StatusForbidden, "tenant context required or platform admin access required")
			return
		}
	} else if sessionTenantID != tenantID {
		respondError(w, http.StatusForbidden, "access denied: cross-tenant audit access is prohibited via this endpoint")
		return
	}

	// Authorization: Tenant Admin/Owner ONLY (checked via hasPermissionAny for simplicity in Beta)
	hasPerm, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:view_audit")
	if err != nil || !hasPerm {
		respondError(w, http.StatusForbidden, "permission denied")
		return
	}

	limit := 50
	offset := 0

	// Create filter
	filter := audit.Filter{
		TenantID: &tenantID,
		Limit:    limit,
		Offset:   offset,
	}

	events, total, err := h.auditRepo.List(r.Context(), filter)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to list audit events", "error", err)
		respondError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}

	// Map to response
	respEvents := make([]AuditEventResponse, len(events))
	for i, e := range events {
		respEvents[i] = mapAuditEvent(e)
	}

	respondJSON(w, http.StatusOK, ListAuditEventsResponse{
		Events: respEvents,
		Total:  total,
	})
}

// ListPlatformAuditEvents lists platform-level audit events
func (h *Handler) ListPlatformAuditEvents(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())

	// Authorization: Platform admin only
	isPlatformAdmin, _ := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:view_audit")
	if !isPlatformAdmin {
		respondError(w, http.StatusForbidden, "platform admin access required")
		return
	}

	limit := 50
	offset := 0

	// Platform-only logs (empty tenant_id)
	emptyTenant := ""
	filter := audit.Filter{
		TenantID: &emptyTenant,
		Limit:    limit,
		Offset:   offset,
	}

	events, total, err := h.auditRepo.List(r.Context(), filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}

	// Map to response
	respEvents := make([]AuditEventResponse, len(events))
	for i, e := range events {
		respEvents[i] = mapAuditEvent(e)
	}

	respondJSON(w, http.StatusOK, ListAuditEventsResponse{
		Events: respEvents,
		Total:  total,
	})
}

// CreateAuditQuery handles the declaration of intent for scoped audit access
func (h *Handler) CreateAuditQuery(w http.ResponseWriter, r *http.Request) {
	userID := GetUserID(r.Context())

	// Authorization: Platform admin only
	isPlatformAdmin, _ := h.authzService.HasPermission(r.Context(), userID, role.ScopePlatform, nil, "platform:view_audit")
	if !isPlatformAdmin {
		respondError(w, http.StatusForbidden, "platform admin access required")
		return
	}

	var req CreateAuditQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validation
	if _, err := uuid.Parse(req.TenantID); err != nil {
		respondError(w, http.StatusBadRequest, "invalid audit access declaration 01")
		return
	}

	t, err := h.tenantService.GetTenant(r.Context(), req.TenantID)
	if err != nil || t == nil {
		respondError(w, http.StatusBadRequest, "invalid audit access declaration 02")
		return
	}

	if req.Reason == "" || req.StartDate.IsZero() || req.EndDate.IsZero() {
		respondError(w, http.StatusBadRequest, "reason, start_date, and end_date are mandatory")
		return
	}

	if len(req.Reason) < 10 {
		respondError(w, http.StatusBadRequest, "reason must be at least 10 characters")
		return
	}

	if req.StartDate.After(req.EndDate) {
		respondError(w, http.StatusBadRequest, "start_date must be before or equal to end_date")
		return
	}

	if req.EndDate.After(time.Now()) {
		respondError(w, http.StatusBadRequest, "end_date cannot be in the future")
		return
	}

	if req.EndDate.Sub(req.StartDate) > 30*24*time.Hour {
		respondError(w, http.StatusBadRequest, "maximum query window is 30 days")
		return
	}

	// Phase 2: Audit-of-Audit
	h.auditLogger.Log(r.Context(), audit.Event{
		Type:     audit.TypeAuditReadCrossTenant,
		ActorID:  userID,
		Resource: audit.ResourceTenant,
		TenantID: req.TenantID,
		Metadata: map[string]any{
			"reason":       req.Reason,
			"window_start": req.StartDate.Format(time.RFC3339),
			"window_end":   req.EndDate.Format(time.RFC3339),
		},
	})

	// Generate a signed token as the Query ID
	claims := AuditQueryClaims{
		TenantID:  req.TenantID,
		StartDate: req.StartDate.Unix(),
		EndDate:   req.EndDate.Unix(),
		Reason:    req.Reason,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(h.auditQuerySigningKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate query ID")
		return
	}

	respondJSON(w, http.StatusCreated, AuditQueryResponse{ID: ss})
}

// GetAuditQueryResult returns the scoped audit events for a declared intent
func (h *Handler) GetAuditQueryResult(w http.ResponseWriter, r *http.Request) {
	queryID := chi.URLParam(r, "queryID")
	if queryID == "" {
		respondError(w, http.StatusBadRequest, "query ID is required")
		return
	}

	userID := GetUserID(r.Context())

	// Verify the signed intent
	token, err := jwt.ParseWithClaims(queryID, &AuditQueryClaims{}, func(token *jwt.Token) (interface{}, error) {
		return h.auditQuerySigningKey, nil
	})

	if err != nil || !token.Valid {
		respondError(w, http.StatusForbidden, "invalid or expired audit query declaration")
		return
	}

	claims, ok := token.Claims.(*AuditQueryClaims)
	if !ok || claims.Subject != userID {
		respondError(w, http.StatusForbidden, "unauthorized access to query results")
		return
	}

	// Scoped Fetch from auditRepo
	start := time.Unix(claims.StartDate, 0)
	end := time.Unix(claims.EndDate, 0)
	filter := audit.Filter{
		TenantID:  &claims.TenantID,
		StartDate: &start,
		EndDate:   &end,
		Limit:     100,
	}

	events, total, err := h.auditRepo.List(r.Context(), filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to retrieve audit results")
		return
	}

	respEvents := make([]AuditEventResponse, len(events))
	for i, e := range events {
		respEvents[i] = mapAuditEvent(e)
	}

	respondJSON(w, http.StatusOK, ListAuditEventsResponse{
		Events: respEvents,
		Total:  total,
	})
}

// Helper function to map audit event to response format
func mapAuditEvent(e audit.Event) AuditEventResponse {
	return AuditEventResponse{
		ID:         e.ID,
		Type:       e.Type,
		TenantID:   e.TenantID,
		ActorID:    e.ActorID,
		ActorName:  e.ActorName,
		Resource:   e.Resource,
		TargetName: e.TargetName,
		TargetID:   e.TargetID,
		IPAddress:  e.IPAddress,
		UserAgent:  e.UserAgent,
		Metadata:   e.Metadata,
		CreatedAt:  e.Timestamp.Format(time.RFC3339),
	}
}
