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
