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

package config

import (
	"fmt"
	"net/http"
	"os"
)

type Config struct {
	Env              string
	DatabaseURL      string
	Port             string
	LogLevel         string
	IdentitySecret   string
	SessionSecret    string
	BaseURL          string
	SessionNamespace string
	CookieSecure     bool
	CookieHTTPOnly   bool
	CookieSameSite   string
	CookieDomain     string
	CookieName       string
}

func Load() (*Config, error) {
	c := &Config{
		Env:              os.Getenv("OPENTRUSTY_ENV"),
		DatabaseURL:      os.Getenv("OPENTRUSTY_DATABASE_URL"),
		Port:             os.Getenv("OPENTRUSTY_ADMIN_LISTEN_ADDR"),
		LogLevel:         os.Getenv("OPENTRUSTY_LOG_LEVEL"),
		IdentitySecret:   os.Getenv("OPENTRUSTY_IDENTITY_SECRET"),
		SessionSecret:    os.Getenv("OPENTRUSTY_SESSION_SECRET"),
		BaseURL:          os.Getenv("OPENTRUSTY_BASE_URL"),
		SessionNamespace: os.Getenv("OPENTRUSTY_ADMIN_SESSION_NAMESPACE"),
		CookieSecure:     os.Getenv("OPENTRUSTY_COOKIE_SECURE") == "true",
		CookieHTTPOnly:   os.Getenv("OPENTRUSTY_COOKIE_HTTPONLY") != "false",
		CookieSameSite:   os.Getenv("OPENTRUSTY_COOKIE_SAMESITE"),
		CookieDomain:     os.Getenv("OPENTRUSTY_COOKIE_DOMAIN"),
		CookieName:       os.Getenv("OPENTRUSTY_COOKIE_NAME"),
	}

	if c.Env == "" {
		c.Env = "dev"
	}
	if c.Port == "" {
		// Default to use the old port if the new one is not set for compatibility during transition,
		// but we should favor the new one in systemd.
		c.Port = os.Getenv("OPENTRUSTY_PORT")
		if c.Port == "" {
			c.Port = ":8081"
		}
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.SessionNamespace == "" {
		c.SessionNamespace = "admin"
	}
	if c.CookieName == "" {
		c.CookieName = "ot_session_admin"
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) Validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("OPENTRUSTY_DATABASE_URL is required")
	}
	if c.IdentitySecret == "" {
		return fmt.Errorf("OPENTRUSTY_IDENTITY_SECRET is required")
	}
	if c.SessionSecret == "" {
		return fmt.Errorf("OPENTRUSTY_SESSION_SECRET is required")
	}
	if c.BaseURL == "" {
		return fmt.Errorf("OPENTRUSTY_BASE_URL is required")
	}
	return nil
}

func (c *Config) GetSameSite() http.SameSite {
	switch c.CookieSameSite {
	case "Lax":
		return http.SameSiteLaxMode
	case "Strict":
		return http.SameSiteStrictMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
