// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"encoding/json"
	"net/http"
)

// SessionConfig holds session cookie configuration.
//
// Purpose: Structured parameters for administrative session cookies.
// Domain: Admin (Infrastructure)
type SessionConfig struct {
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite
}

type contextKey string

const (
	UserIDKey          contextKey = "user_id"
	TenantIDKey        contextKey = "tenant_id"
	SessionIDKey       contextKey = "session_id"
	SessionTenantIDKey contextKey = "session_tenant_id"
)

// GetUserID retrieves the user ID from context.
//
// Purpose: Helper to extract authenticated actor identity from the request context.
// Domain: Admin (Infrastructure)
func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(UserIDKey).(string); ok {
		return id
	}
	return ""
}

// GetTenantID retrieves the tenant ID from context.
func GetTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(TenantIDKey).(string); ok {
		return id
	}
	return ""
}

// GetSessionTenantID retrieves the tenant ID from context.
func GetSessionTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(SessionTenantIDKey).(string); ok {
		return id
	}
	return ""
}

// RespondJSON sends a JSON response.
func RespondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RespondError sends a JSON error response.
func RespondError(w http.ResponseWriter, status int, message string) {
	RespondJSON(w, status, map[string]string{
		"error": message,
	})
}
