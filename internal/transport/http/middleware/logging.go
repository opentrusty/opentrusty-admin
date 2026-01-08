// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chiMiddleware "github.com/go-chi/chi/v5/middleware"
)

// Logging middleware logs HTTP request details including method, path, status code, and duration.
func Logging() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			reqID := chiMiddleware.GetReqID(r.Context())

			// Log request start
			slog.InfoContext(r.Context(), "http_request_start",
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)

			ww := chiMiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				slog.InfoContext(r.Context(), "http_request_end",
					"request_id", reqID,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
					"user_agent", r.UserAgent(),
					"status", ww.Status(),
					"duration_ms", time.Since(start).Milliseconds(),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
