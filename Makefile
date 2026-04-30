.PHONY: build build-sast fetch-cbm test clean install install-sast run help

# Project variables
BINARY_NAME=late
VERSION?=1.6.0

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

build: ## Build the late binary
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/late

fetch-cbm: ## Download codebase-memory-mcp binary for embedding
	@echo "Fetching codebase-memory-mcp ($(CBM_GOOS)/$(CBM_GOARCH))..."
	@mkdir -p $(CBM_EMBED_DIR)
	@curl -fsSL "https://github.com/DeusData/codebase-memory-mcp/releases/latest/download/$(CBM_ASSET).tar.gz" \
		| tar -xzO $(notdir $(CBM_EMBED_PATH)) > $(CBM_EMBED_PATH) && chmod +x $(CBM_EMBED_PATH)
	@echo "Fetched: $(CBM_EMBED_PATH)"

build-sast: fetch-cbm ## Build late-sast binary with codebase-memory-mcp baked in
	@echo "Building late-sast..."
	@go build ${LDFLAGS} -tags cbm_embedded -o bin/late-sast ./cmd/late-sast

test: ## Run tests for the entire project
	@echo "Running tests..."
	@go test -v -race ./...

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf bin/

install: build ## Build and install the binary to your Go bin path
	@echo "Installing to $${GOPATH:-$(HOME)/go}/bin..."
	@go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/late
	@mv bin/${BINARY_NAME} ~/.local/bin/late

install-sast: build-sast ## Build and install late-sast to ~/.local/bin
	@echo "Installing late-sast..."
	@mv bin/late-sast ~/.local/bin/late-sast

run: build ## Build and run the project
	@./bin/${BINARY_NAME}
