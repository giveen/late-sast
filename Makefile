.PHONY: build build-late fetch-cbm test quick-test test-race coverage fmt fmt-check vet lint ci clean install install-late run help

# Project variables — late-sast is the primary binary
BINARY_NAME=late-sast
VERSION?=v1.8.0

# Go compiler flags
LDFLAGS=-ldflags "-X late/internal/common.Version=${VERSION}"

# codebase-memory-mcp embedding
CBM_EMBED_DIR=cmd/late-sast/embedded
CBM_EMBED_PATH=$(CBM_EMBED_DIR)/codebase-memory-mcp
CBM_GOOS?=$(shell go env GOOS)
CBM_GOARCH?=$(shell go env GOARCH)
CBM_ASSET=codebase-memory-mcp-$(CBM_GOOS)-$(CBM_GOARCH)

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fetch-cbm: ## Download codebase-memory-mcp binary for embedding
	@if [ -f "$(CBM_EMBED_PATH)" ]; then \
		echo "Fetched: $(CBM_EMBED_PATH) (cached)"; \
	else \
		echo "Fetching codebase-memory-mcp ($(CBM_GOOS)/$(CBM_GOARCH))..."; \
		mkdir -p $(CBM_EMBED_DIR); \
		curl -fsSL "https://github.com/DeusData/codebase-memory-mcp/releases/latest/download/$(CBM_ASSET).tar.gz" \
			| tar -xzO $(notdir $(CBM_EMBED_PATH)) > $(CBM_EMBED_PATH) && chmod +x $(CBM_EMBED_PATH); \
		echo "Fetched: $(CBM_EMBED_PATH)"; \
	fi

build: fetch-cbm ## Build late-sast binary (primary) with codebase-memory-mcp baked in
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -tags cbm_embedded -o bin/${BINARY_NAME} ./cmd/late-sast

build-late: ## Build the late (general assistant) binary
	@echo "Building late..."
	@go build ${LDFLAGS} -o bin/late ./cmd/late

test: ## Run tests for the entire project
	@echo "Running tests..."
	@go test -v -race ./...

quick-test: ## Run fast unit tests (short mode, no race)
	@echo "Running quick tests..."
	@go test -short ./...

test-race: ## Run tests with race detector
	@echo "Running race tests..."
	@go test -race ./...

coverage: ## Generate coverage profile and summary
	@echo "Running coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -n 1

fmt: ## Format Go source files
	@echo "Formatting Go files..."
	@gofmt -w $$(find . -name '*.go' -not -path './bin/*')

fmt-check: ## Verify Go files are formatted
	@echo "Checking formatting..."
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './bin/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet: ## Run go vet on all packages
	@echo "Running go vet..."
	@go vet ./...

lint: ## Run golangci-lint when available, fallback to go vet
	@echo "Running lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, falling back to go vet"; \
		go vet ./...; \
	fi

ci: fmt-check vet lint test-race ## CI quality gate: format, static checks, lint, and race tests
	@echo "CI checks passed"

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf bin/

install: build build-late ## Build and install both binaries to ~/.local/bin
	@echo "Installing ${BINARY_NAME} to ~/.local/bin..."
	@cp bin/${BINARY_NAME} ~/.local/bin/${BINARY_NAME}
	@echo "Installing late to ~/.local/bin..."
	@cp bin/late ~/.local/bin/late

install-late: build-late ## Build and install the late general assistant to ~/.local/bin
	@echo "Installing late to ~/.local/bin..."
	@cp bin/late ~/.local/bin/late

install-desktop: ## Install .desktop launcher and icon (run once after make install)
	@echo "Installing desktop entry and icon..."
	@mkdir -p ~/.local/share/applications ~/.local/share/icons/hicolor/scalable/apps
	@cp internal/gui/late-sast.svg ~/.local/share/icons/hicolor/scalable/apps/late-sast.svg
	@printf '[Desktop Entry]\nName=Late SAST\nComment=AI Security Auditor\nExec=%s\nIcon=late-sast\nType=Application\nCategories=Development;Security;\nTerminal=false\nStartupWMClass=late-sast\n' "$(HOME)/.local/bin/late-sast" \
		> ~/.local/share/applications/late-sast.desktop
	@update-desktop-database ~/.local/share/applications 2>/dev/null || true
	@gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor 2>/dev/null || true
	@echo "Done. You may need to log out and back in for the launcher icon to appear."

run: build ## Build and run late-sast
	@./bin/${BINARY_NAME}
