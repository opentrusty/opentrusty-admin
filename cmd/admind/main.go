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

package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opentrusty/opentrusty-admin/internal/config"
	transportHTTP "github.com/opentrusty/opentrusty-admin/internal/transport/http"
	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
	"github.com/opentrusty/opentrusty-core/audit"
	"github.com/opentrusty/opentrusty-core/authz"
	"github.com/opentrusty/opentrusty-core/client"
	"github.com/opentrusty/opentrusty-core/session"
	"github.com/opentrusty/opentrusty-core/store/postgres"
	"github.com/opentrusty/opentrusty-core/tenant"
	"github.com/opentrusty/opentrusty-core/user"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	slog.Info("starting admind (Admin Plane)", "version", version)

	// 0. Connect to DB
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// 1. Initialize Core dependencies
	auditRepo := postgres.NewAuditRepository(db)
	auditLogger := audit.NewRepositoryLogger(auditRepo)

	userRepo := postgres.NewUserRepository(db)
	hasher := user.NewPasswordHasher(65536, 1, 1, 16, 32)
	userService := user.NewService(userRepo, hasher, auditLogger, 5, 15*time.Minute, cfg.IdentitySecret)

	sessionRepo := postgres.NewSessionRepository(db)
	sessionService := session.NewService(sessionRepo, 24*time.Hour, 1*time.Hour)

	projectRepo := postgres.NewProjectRepository(db)
	roleRepo := postgres.NewRoleRepository(db)
	assignmentRepo := postgres.NewAssignmentRepository(db)
	authzService := authz.NewService(projectRepo, roleRepo, assignmentRepo)

	clientRepo := postgres.NewClientRepository(db)
	clientService := client.NewService(clientRepo, auditLogger)

	tenantRepo := postgres.NewTenantRepository(db)
	membershipRepo := postgres.NewMembershipRepository(db)
	tenantRoleRepo := postgres.NewTenantRoleRepository(db)
	policyAuthzRepo := postgres.NewPolicyAssignmentRepository(db)

	tenantService := tenant.NewService(
		tenantRepo,
		tenantRoleRepo,
		policyAuthzRepo,
		userService,
		clientRepo,
		membershipRepo,
		auditLogger,
	)

	// 2. Initialize Transport
	handler := transportHTTP.NewHandler(
		userService,
		sessionService,
		authzService,
		tenantService,
		clientService,
		auditLogger,
		auditRepo,
		types.SessionConfig{
			CookieName:     cfg.CookieName,
			CookiePath:     "/",
			CookieDomain:   cfg.CookieDomain,
			CookieSecure:   cfg.CookieSecure,
			CookieHTTPOnly: cfg.CookieHTTPOnly,
			CookieSameSite: cfg.GetSameSite(),
		},

		[]byte(cfg.SessionSecret),
	)

	router := transportHTTP.NewRouter(handler)

	server := &http.Server{
		Addr:    cfg.Port,
		Handler: router,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			stop()
		}
	}()

	slog.Info("admind ready", "addr", server.Addr, "db", "connected")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down admind")
	server.Shutdown(ctx)
}
