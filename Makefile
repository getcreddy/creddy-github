.PHONY: build test clean install dev info validate

BINARY_NAME=creddy-github
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Build the plugin
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) .

# Build for all platforms
build-all:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 .
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 .

# Push to ttl.sh for dev testing (1 hour TTL)
# Usage: make release-dev
# Then on test machine: creddy plugin install ttl.sh/creddy-<name>:dev
release-dev: build-all
	@echo "Pushing to ttl.sh (1h TTL)..."
	oras push ttl.sh/$(BINARY_NAME):dev \
		./bin/$(BINARY_NAME)-linux-amd64:application/octet-stream \
		./bin/$(BINARY_NAME)-linux-arm64:application/octet-stream \
		./bin/$(BINARY_NAME)-darwin-amd64:application/octet-stream \
		./bin/$(BINARY_NAME)-darwin-arm64:application/octet-stream
	@echo "Pushed! Install with: creddy plugin install ttl.sh/$(BINARY_NAME):dev"

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Install to local Creddy plugins directory
install: build
	mkdir -p ~/.creddy/plugins
	cp bin/$(BINARY_NAME) ~/.creddy/plugins/

# --- Development helpers ---

# Show plugin info (standalone mode)
info: build
	./bin/$(BINARY_NAME) info

# List scopes (standalone mode)
scopes: build
	./bin/$(BINARY_NAME) scopes

# Validate config (standalone mode)
# Usage: make validate CONFIG=path/to/config.json
validate: build
	./bin/$(BINARY_NAME) validate --config $(CONFIG)

# Get a credential (standalone mode)
# Usage: make get CONFIG=config.json SCOPE="github:owner/repo"
get: build
	./bin/$(BINARY_NAME) get --config $(CONFIG) --scope "$(SCOPE)" --ttl 10m

# Development mode: build and install on every change
dev:
	@echo "Watching for changes..."
	@while true; do \
		$(MAKE) install; \
		inotifywait -qre modify --include '\.go$$' . 2>/dev/null || fswatch -1 *.go 2>/dev/null || sleep 5; \
	done

# Create a test config file template
config-template:
	@echo '{'
	@echo '  "app_id": YOUR_APP_ID,'
	@echo '  "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----",'
	@echo '  "installation_id": OPTIONAL_INSTALLATION_ID'
	@echo '}'
