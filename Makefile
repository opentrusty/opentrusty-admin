# Makefile for OpenTrusty Admin

BINARY_NAME=opentrusty-admind
MAIN_PATH=./cmd/admind/main.go

.PHONY: build test lint clean help run-health release

help:
	@echo "OpenTrusty Admin Makefile"
	@echo "Usage:"
	@echo "  make build       - Build the opentrusty-admin binary"
	@echo "  make test        - Run all tests"
	@echo "  make lint        - Run linter"
	@echo "  make run-health  - Check if service is healthy"
	@echo "  make release     - Build and package release tarball"
	@echo "  make clean       - Clean build artifacts"

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) $(MAIN_PATH)

deps:
	go mod download
	go mod tidy

test: test-service

test-unit:
	go test -v -short ./...

test-service:
	go test -v ./...

lint:
	golangci-lint run ./...

run-health:
	curl -f http://localhost:8081/health || (echo "Service health check failed" && exit 1)

clean:
	go clean -cache
	rm -f $(BINARY_NAME)
	rm -rf release/

# Release package - creates a deployment-ready tarball
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
RELEASE_DIR = release/opentrusty-admin-$(VERSION)

release: build
	@echo "Creating release package for $(VERSION)..."
	@mkdir -p $(RELEASE_DIR)
	@cp $(BINARY_NAME) $(RELEASE_DIR)/
	@cp -r deploy/* $(RELEASE_DIR)/
	@sed -i "s/VERSION=\"dev\"/VERSION=\"$(VERSION)\"/" $(RELEASE_DIR)/install.sh
	@cp .env.example $(RELEASE_DIR)/
	@cp LICENSE $(RELEASE_DIR)/ 2>/dev/null || echo "No LICENSE file found"
	@cd release && tar -czf opentrusty-admin-$(VERSION)-linux-amd64.tar.gz opentrusty-admin-$(VERSION)
	@echo "✓ Release package created: release/opentrusty-admin-$(VERSION)-linux-amd64.tar.gz"

