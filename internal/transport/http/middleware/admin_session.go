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

package middleware

import (
	"log/slog"
	"net/http"

	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
	"github.com/opentrusty/opentrusty-core/session"
)

// AdminSession enforces that a user is authenticated with an "admin" namespace session.
// This is used by the Admin Plane for management API access.
func AdminSession(sessionSvc *session.Service, sessionCfg types.SessionConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := verifySession(w, r, sessionSvc, sessionCfg, "admin")
			if !ok {
				return
			}
			injectSessionContext(next, sess).ServeHTTP(w, r)
		})
	}
}

// CSRF protects against Cross-Site Request Forgery for state-changing requests.
// It requires the 'X-CSRF-Token' header to be present and non-empty for POST, PUT, DELETE, etc.
func CSRF() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for safe methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions || r.Method == http.MethodTrace {
				next.ServeHTTP(w, r)
				return
			}

			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				slog.WarnContext(r.Context(), "missing CSRF token header", "method", r.Method, "path", r.URL.Path)
				types.RespondError(w, http.StatusForbidden, "CSRF protection: X-CSRF-Token header is required for state-changing operations")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
