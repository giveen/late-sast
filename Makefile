.PHONY: build build-sast test clean install install-sast run help

# Project variables
BINARY_NAME=late
VERSION?=1.2.1

# Go compiler flags
LDFLAGS=-ldflags "-X late/internal/common.Version=${VERSION}"

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the late binary
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -o bin/${BINARY_NAME} ./cmd/late

build-sast: ## Build the late-sast binary
	@echo "Building late-sast..."
	@go build ${LDFLAGS} -o bin/late-sast ./cmd/late-sast

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
