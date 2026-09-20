# SecretGuard Makefile

BINARY_NAME := secretguard
BIN_DIR     := bin
MAIN_PKG    := ./cmd/secretguard
LDFLAGS     := -ldflags "-X main.version=0.1.0"

.PHONY: all build test lint run scan clean help

## build: Compile the secretguard binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_PKG)
	@echo "Binary: ./$(BIN_DIR)/$(BINARY_NAME)"

## test: Run all unit tests
test:
	@echo "Running tests..."
	go test ./... -v -count=1

## lint: Run go vet
lint:
	@echo "Running go vet..."
	go vet ./...
	@echo "Lint OK"

## run: Build and run doctor (quick sanity check)
run: build
	./$(BIN_DIR)/$(BINARY_NAME) doctor

## scan: Build and scan sample-repo
scan: build
	@echo ""
	@echo "Scanning sample-repo..."
	./$(BIN_DIR)/$(BINARY_NAME) scan --repo sample-repo || true

## clean: Remove build artefacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	@echo "Done."

## help: Show available targets
help:
	@grep -E '^##' Makefile | sed 's/## //'
