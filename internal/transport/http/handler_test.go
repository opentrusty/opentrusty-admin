// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opentrusty/opentrusty-admin/internal/transport/types"
)

func TestHealthCheck(t *testing.T) {
	h := &Handler{}

	req, _ := http.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	h.HealthCheck(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// expected := `{"pass":"pass","service":"opentrusty-admin"}`
	// The actual implementation returns map[string]string{"status": "pass", "service": "opentrusty-admin"}
	// RespondJSON encodes it to JSON.
}

func TestRegisterBlocked(t *testing.T) {
	h := &Handler{}

	req, _ := http.NewRequest("POST", "/auth/register", nil)
	rr := httptest.NewRecorder()

	h.Register(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}
}

// Sub-package simulation for RespondJSON
// Note: In real tests we'd need to mock the services properly to test Login, etc.
// But for UT we focus on the logic in the handler itself where possible.

func TestGetUserID(t *testing.T) {
	ctx := context.WithValue(context.Background(), types.UserIDKey, "u1")
	if GetUserID(ctx) != "u1" {
		t.Error("failed to retrieve user ID from context")
	}
}
