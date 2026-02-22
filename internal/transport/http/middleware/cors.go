// Copyright 2026 The OpenTrusty Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package middleware

import (
	"net/http"
	"strings"
)

// CORSConfig holds allowed origins for CORS.
type CORSConfig struct {
	AllowedOrigins []string
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing.
// It checks the request Origin header against the configured allowed origins,
// responds to OPTIONS preflight requests, and sets appropriate CORS headers.
func CORS(cfg CORSConfig) func(next http.Handler) http.Handler {
	allowedSet := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowedSet[strings.TrimRight(o, "/")] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			normalizedOrigin := strings.TrimRight(origin, "/")

			if !allowedSet[normalizedOrigin] {
				// Origin not allowed — skip CORS headers, let request proceed
				// (browser will block the response on the client side)
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")

			// Handle preflight
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Requested-With")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
