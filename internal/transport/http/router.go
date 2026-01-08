// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/opentrusty/opentrusty-admin/internal/transport/http/middleware"
	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
)

// NewRouter creates the Admin Plane router.
func NewRouter(h *Handler) *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(chiMiddleware.RequestID)
	r.Use(middleware.Logging())
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", h.HealthCheck)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {

		// Auth endpoints (for Control Panel API login)
		r.Group(func(r chi.Router) {
			r.Use(middleware.CSRF())
			r.Post("/auth/login", h.Login)
			r.Post("/auth/logout", h.Logout)
			r.Post("/auth/register", h.Register)
		})

		// Session check (required for Console)
		r.With(middleware.AdminSession(h.sessionService, h.sessionConfig)).Get("/auth/me", h.GetCurrentUser)

		// Protected Admin routes
		r.Group(func(r chi.Router) {
			r.Use(middleware.AdminSession(h.sessionService, h.sessionConfig))
			r.Use(middleware.CSRF())

			// User profile
			r.Get("/user/profile", h.GetProfile)
			r.Put("/user/profile", h.UpdateProfile)
			r.Post("/user/change-password", h.ChangePassword)

			// Audit Logs (Platform-level)
			r.Get("/audit", h.ListPlatformAuditEvents)
			r.Route("/audit-queries", func(r chi.Router) {
				r.Post("/", h.CreateAuditQuery)
				r.Get("/{queryID}/results", h.GetAuditQueryResult)
			})
			r.Get("/metrics", h.GetPlatformMetrics)

			// Tenant management
			r.Route("/tenants", func(r chi.Router) {
				r.Get("/", h.ListTenants)
				r.Post("/", h.CreateTenant)

				r.Route("/{tenantID}", func(r chi.Router) {
					// Middleware to inject tenantID into context from URL param
					r.Use(func(next http.Handler) http.Handler {
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							tid := chi.URLParam(r, "tenantID")
							ctx := context.WithValue(r.Context(), types.TenantIDKey, tid)
							next.ServeHTTP(w, r.WithContext(ctx))
						})
					})
					r.Get("/", h.GetTenant)
					r.Patch("/", h.UpdateTenant)
					r.Delete("/", h.DeleteTenant)
					r.Get("/metrics", h.GetTenantMetrics)

					r.Route("/users", func(r chi.Router) {
						r.Get("/", h.ListTenantUsers)
						r.Post("/", h.ProvisionTenantUser)
						// Update/Role management omitted for Beta brevity in router but can be added if handlers exist
					})

					// OAuth2 Client Management
					r.Route("/clients", func(r chi.Router) {
						r.Get("/", h.ListClients)
						r.Post("/", h.RegisterClient)
						r.Route("/{clientID}", func(r chi.Router) {
							r.Get("/", h.GetClient)
							r.Delete("/", h.DeleteClient)
							r.Post("/secret", h.RegenerateClientSecret)
						})
					})
					// Tenant Audit Logs
					r.Get("/audit", h.ListTenantAuditEvents)
				})
			})
		})
	})

	return r
}
