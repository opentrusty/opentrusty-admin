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

	// Database discrete configuration
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
}

func Load() (*Config, error) {
	c := &Config{
		Env:              os.Getenv("OPENTRUSTY_ENV"),
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

		DBHost:     os.Getenv("OPENTRUSTY_DB_HOST"),
		DBPort:     os.Getenv("OPENTRUSTY_DB_PORT"),
		DBUser:     os.Getenv("OPENTRUSTY_DB_USER"),
		DBPassword: os.Getenv("OPENTRUSTY_DB_PASSWORD"),
		DBName:     os.Getenv("OPENTRUSTY_DB_NAME"),
		DBSSLMode:  os.Getenv("OPENTRUSTY_DB_SSLMODE"),
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

	// Default DB Port and SSLMode if not specified
	if c.DBPort == "" {
		c.DBPort = "5432"
	}
	if c.DBSSLMode == "" {
		c.DBSSLMode = "disable"
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) Validate() error {
	// Discrete fields must be provided
	if c.DBHost == "" || c.DBUser == "" || c.DBName == "" {
		return fmt.Errorf("database configuration is required (provide discrete OPENTRUSTY_DB_* variables)")
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
