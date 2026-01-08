// Copyright 2026 The OpenTrusty Authors
// SPDX-License-Identifier: MIT

package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/opentrusty/opentrusty-core/client"
	"github.com/opentrusty/opentrusty-core/role"
)

// RegisterClientRequest represents the data for registering a new OAuth2 client
type RegisterClientRequest struct {
	ClientName              string   `json:"client_name" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	AllowedScopes           []string `json:"allowed_scopes"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// RegisterClientResponse represents the response after registering a client
type RegisterClientResponse struct {
	Client       *client.Client `json:"client"`
	ClientSecret string         `json:"client_secret,omitempty"`
}

// RegisterClient handles OAuth2 client registration
func (h *Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:manage_clients")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "client management access required")
		return
	}

	var req RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := client.ValidateOIDCScopes(req.AllowedScopes); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	clientSecret := ""
	clientSecretHash := ""
	if req.TokenEndpointAuthMethod != "none" {
		clientSecret = client.GenerateClientSecret()
		clientSecretHash = client.HashClientSecret(clientSecret)
	}

	c := &client.Client{
		TenantID:                tenantID,
		ClientName:              req.ClientName,
		ClientSecretHash:        clientSecretHash,
		RedirectURIs:            req.RedirectURIs,
		AllowedScopes:           req.AllowedScopes,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		AccessTokenLifetime:     3600,
		RefreshTokenLifetime:    2592000,
		IDTokenLifetime:         3600,
		IsActive:                true,
	}

	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []string{"authorization_code"}
	}
	if len(c.ResponseTypes) == 0 {
		c.ResponseTypes = []string{"code"}
	}

	if _, err := h.clientService.RegisterClient(r.Context(), tenantID, userID, c); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to register client: "+err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, RegisterClientResponse{
		Client:       c,
		ClientSecret: clientSecret,
	})
}

// ListClients handles listing OAuth2 clients for a tenant
func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	if tenantID == "" {
		respondError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:view")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "tenant view access required")
		return
	}

	clients, err := h.clientService.ListClients(r.Context(), tenantID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list clients: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"clients": clients,
		"total":   len(clients),
	})
}

// GetClient handles retrieving a specific OAuth2 client
func (h *Handler) GetClient(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	clientID := chi.URLParam(r, "clientID")

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:view")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "tenant view access required")
		return
	}

	c, err := h.clientService.GetClientByClientID(r.Context(), tenantID, clientID)
	if err != nil {
		respondError(w, http.StatusNotFound, "client not found")
		return
	}

	respondJSON(w, http.StatusOK, c)
}

// DeleteClient handles deleting an OAuth2 client
func (h *Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	clientID := chi.URLParam(r, "clientID")

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:manage_clients")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "client management access required")
		return
	}

	c, err := h.clientService.GetClientByClientID(r.Context(), tenantID, clientID)
	if err != nil {
		respondError(w, http.StatusNotFound, "client not found")
		return
	}

	if err := h.clientService.DeleteClient(r.Context(), tenantID, c.ID, userID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete client")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RegenerateClientSecret handles regenerating a client secret
func (h *Handler) RegenerateClientSecret(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	clientID := chi.URLParam(r, "clientID")

	userID := GetUserID(r.Context())
	allowed, err := h.authzService.HasPermission(r.Context(), userID, role.ScopeTenant, &tenantID, "tenant:manage_clients")
	if err != nil || !allowed {
		respondError(w, http.StatusForbidden, "client management access required")
		return
	}

	c, err := h.clientService.GetClientByClientID(r.Context(), tenantID, clientID)
	if err != nil {
		respondError(w, http.StatusNotFound, "client not found")
		return
	}

	if c.TokenEndpointAuthMethod == "none" {
		respondError(w, http.StatusBadRequest, "cannot regenerate secret for public client")
		return
	}

	newSecret := client.GenerateClientSecret()
	c.ClientSecretHash = client.HashClientSecret(newSecret)

	if err := h.clientService.UpdateClient(r.Context(), c, userID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update client secret")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"client_secret": newSecret,
	})
}
