# creddy-github

Creddy plugin for GitHub App installation tokens.

## Overview

This plugin issues scoped, ephemeral GitHub installation tokens using a GitHub App. Tokens can be limited to specific repositories and permission levels.

## Installation

```bash
creddy plugin install github
```

Or build from source:

```bash
make build
make install  # copies to ~/.creddy/plugins/
```

## Configuration

Add the GitHub backend to Creddy:

```bash
creddy backend add github \
  --app-id 123456 \
  --installation-id 78901234 \
  --private-key /path/to/app.pem
```

### Required Settings

| Setting | Description |
|---------|-------------|
| `app_id` | Your GitHub App's ID |
| `private_key_pem` | The App's private key (PEM format) |

### Optional Settings

| Setting | Description |
|---------|-------------|
| `installation_id` | Specific installation ID (auto-discovered if not set) |

## Scopes

| Pattern | Description |
|---------|-------------|
| `github:*` | All repositories the App is installed on |
| `github:owner/*` | All repositories under an owner/org |
| `github:owner/repo` | Specific repository |
| `github:owner/repo:read` | Read-only access |
| `github:owner/repo:write` | Write access (default) |

## Usage

```bash
# Get token for specific repo
creddy get github --scope "github:myorg/myrepo"

# Get read-only token
creddy get github --scope "github:myorg/myrepo:read"

# Get token for all org repos
creddy get github --scope "github:myorg/*"
```

## Development

### Standalone Testing

The plugin can run standalone for testing without Creddy:

```bash
# Build
make build

# Show plugin info
make info

# List supported scopes
make scopes

# Test with a config file
echo '{
  "app_id": 123456,
  "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
}' > test-config.json

# Validate configuration
make validate CONFIG=test-config.json

# Get a credential
make get CONFIG=test-config.json SCOPE="github:myorg/myrepo"
```

### Dev Mode

Auto-rebuild and install on file changes:

```bash
make dev
```

### Testing

```bash
# Unit tests
make test

# Integration tests (requires real GitHub App)
make test-integration
```

#### Integration Test Setup

Integration tests require a dedicated GitHub App and test repository:

1. Create a GitHub App for testing
2. Create a private test repository (e.g., `getcreddy/creddy-test-repo`)
3. Install the App on the test repository
4. Set environment variables:

```bash
export CREDDY_TEST_GITHUB_APP_ID=123456
export CREDDY_TEST_GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"
export CREDDY_TEST_GITHUB_INSTALLATION_ID=78901234
export CREDDY_TEST_GITHUB_REPO=getcreddy/creddy-test-repo
```

Then run:

```bash
make test-integration
```

The integration tests verify that token revocation actually invalidates tokens on GitHub's side.

## How It Works

1. Plugin uses the GitHub App's private key to generate a JWT
2. JWT is used to request an installation access token from GitHub
3. Token is scoped to requested repositories and permissions
4. Token expires automatically (max 1 hour, per GitHub)

## License

Apache 2.0
