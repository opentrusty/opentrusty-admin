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
