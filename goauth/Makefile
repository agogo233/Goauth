.PHONY: all build run test test-integration test-e2e test-e2e-headed test-all test-full lint fmt clean docker docker-run deps help

# Variables
BINARY_NAME=goauth
BUILD_DIR=bin
DOCKER_IMAGE=goauth
DOCKER_TAG=latest

# Default target
all: build

# Install dependencies
deps:
	go mod download
	go mod tidy

# Build the binary
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

# Run the application
run:
	go run ./cmd/server serve

# Run tests
test:
	go test -v ./...

# Run integration tests
test-integration:
	go test -v ./tests/integration/...

# Run E2E tests
test-e2e:
	cd tests/e2e && npm install && npx playwright test

# Run E2E tests with headed browser
test-e2e-headed:
	cd tests/e2e && npm install && npx playwright test --headed

# Run all tests
test-all: test test-integration

# Run the full test suite (unit + integration + E2E)
# E2E 需要浏览器与串行数据库状态，耗时较长，建议 CI 中单独运行
test-full: test test-integration test-e2e

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	gofmt -w .
	goimports -w .

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf data/

# Build Docker image
docker:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Run Docker container
docker-run:
	docker run -d \
		--name $(BINARY_NAME) \
		-p 3000:3000 \
		-v $(BINARY_NAME)-data:/app/data \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# Development with hot reload (requires 'air')
dev:
	air

# Generate swagger docs (optional)
docs:
	swag init -g cmd/server/main.go

# Cross-compile for Linux
build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/server

# Cross-compile for ARM64
build-arm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/server

# Show help
help:
	@echo "Available targets:"
	@echo "  deps            - Download and tidy dependencies"
	@echo "  build           - Build the binary"
	@echo "  run             - Run the application"
	@echo "  test            - Run tests"
	@echo "  test-integration- Run integration tests"
	@echo "  test-e2e        - Run E2E tests (Playwright)"
	@echo "  test-e2e-headed - Run E2E tests with headed browser"
	@echo "  test-all        - Run all tests (unit + integration)"
	@echo "  lint            - Run linter"
	@echo "  fmt             - Format code"
	@echo "  clean           - Clean build artifacts"
	@echo "  docker          - Build Docker image"
	@echo "  docker-run      - Run Docker container"
	@echo "  dev             - Run with hot reload (requires air)"
	@echo "  build-linux     - Cross-compile for Linux amd64"
	@echo "  build-arm64     - Cross-compile for Linux arm64"
