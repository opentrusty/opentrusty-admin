# Makefile for OpenTrusty Admin

BINARY_NAME=admind
MAIN_PATH=./cmd/admind/main.go

.PHONY: build test lint clean help run-health

help:
	@echo "OpenTrusty Admin Makefile"
	@echo "Usage:"
	@echo "  make build       - Build the admind binary"
	@echo "  make test        - Run all tests"
	@echo "  make lint        - Run linter"
	@echo "  make run-health  - Check if service is healthy"
	@echo "  make clean       - Clean build artifacts"

build:
	go build -o $(BINARY_NAME) $(MAIN_PATH)

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
