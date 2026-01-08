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
	"os"
)

type Config struct {
	DBURL           string
	Port            string
	LogLevel        string
	IdentitySecret  string
	AdminSigningKey string
}

func Load() (*Config, error) {
	c := &Config{
		DBURL:           os.Getenv("OPENTRUSTY_DB_URL"),
		Port:            os.Getenv("OPENTRUSTY_PORT"),
		LogLevel:        os.Getenv("OPENTRUSTY_LOG_LEVEL"),
		IdentitySecret:  os.Getenv("OPENTRUSTY_IDENTITY_SECRET"),
		AdminSigningKey: os.Getenv("OPENTRUSTY_ADMIN_SIGNING_KEY"),
	}

	if c.Port == "" {
		c.Port = "8081"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) Validate() error {
	if c.DBURL == "" {
		return fmt.Errorf("OPENTRUSTY_DB_URL is required")
	}
	if c.IdentitySecret == "" {
		return fmt.Errorf("OPENTRUSTY_IDENTITY_SECRET is required")
	}
	if c.AdminSigningKey == "" {
		return fmt.Errorf("OPENTRUSTY_ADMIN_SIGNING_KEY is required")
	}
	return nil
}
