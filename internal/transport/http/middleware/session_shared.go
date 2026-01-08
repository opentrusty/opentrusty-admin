package middleware

import (
	"context"
	"net/http"

	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
	"github.com/opentrusty/opentrusty-core/session"
)

func verifySession(
	w http.ResponseWriter,
	r *http.Request,
	sessionSvc *session.Service,
	sessionCfg types.SessionConfig,
	allowedNamespace string,
) (*session.Session, bool) {
	cookie, err := r.Cookie(sessionCfg.CookieName)
	if err != nil || cookie.Value == "" {
		types.RespondError(w, http.StatusUnauthorized, "not authenticated")
		return nil, false
	}
	sess, err := sessionSvc.Get(r.Context(), cookie.Value)
	if err != nil {
		types.RespondError(w, http.StatusUnauthorized, "invalid session")
		return nil, false
	}
	if sess.Namespace != allowedNamespace {
		types.RespondError(w, http.StatusForbidden, "invalid namespace")
		return nil, false
	}
	_ = sessionSvc.Refresh(r.Context(), cookie.Value)
	return sess, true
}

func injectSessionContext(next http.Handler, sess *session.Session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), types.UserIDKey, sess.UserID)
		ctx = context.WithValue(ctx, types.SessionIDKey, sess.ID)
		if sess.TenantID != nil {
			ctx = context.WithValue(ctx, types.TenantIDKey, *sess.TenantID)
			ctx = context.WithValue(ctx, types.SessionTenantIDKey, *sess.TenantID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
