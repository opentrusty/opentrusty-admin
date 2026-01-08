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
