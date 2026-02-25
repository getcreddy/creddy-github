package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
	"github.com/golang-jwt/jwt/v5"
)

const PluginName = "github"

// Version is set at build time via -ldflags
var PluginVersion = "dev"

// GitHubPlugin implements the Creddy Plugin interface for GitHub
type GitHubPlugin struct {
	config *GitHubConfig
}

// GitHubConfig contains the plugin configuration
type GitHubConfig struct {
	AppID          int64  `json:"app_id"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	InstallationID int64  `json:"installation_id,omitempty"`
}

func (p *GitHubPlugin) Info(ctx context.Context) (*sdk.PluginInfo, error) {
	return &sdk.PluginInfo{
		Name:             PluginName,
		Version:          PluginVersion,
		Description:      "GitHub App installation tokens with repository scoping",
		MinCreddyVersion: "0.4.0",
	}, nil
}

func (p *GitHubPlugin) Scopes(ctx context.Context) ([]sdk.ScopeSpec, error) {
	return []sdk.ScopeSpec{
		{
			Pattern:     "github:*",
			Description: "Full access to all repositories the GitHub App is installed on",
			Examples:    []string{"github:*", "github:*:read"},
		},
		{
			Pattern:     "github:<owner>/*",
			Description: "Access to all repositories under an owner/organization",
			Examples:    []string{"github:myorg/*", "github:myorg/*:read"},
		},
		{
			Pattern:     "github:<owner>/<repo>",
			Description: "Access to a specific repository",
			Examples:    []string{"github:myorg/myrepo", "github:myorg/myrepo:read", "github:myorg/myrepo:write"},
		},
	}, nil
}

func (p *GitHubPlugin) ConfigSchema(ctx context.Context) ([]sdk.ConfigField, error) {
	return []sdk.ConfigField{
		{
			Name:        "app_id",
			Type:        "int",
			Description: "GitHub App ID (found in app settings)",
			Required:    true,
		},
		{
			Name:        "private_key_pem",
			Type:        "file",
			Description: "Path to GitHub App private key (.pem file)",
			Required:    true,
		},
		{
			Name:        "installation_id",
			Type:        "int",
			Description: "GitHub App Installation ID (optional, auto-detected if not set)",
			Required:    false,
		},
	}, nil
}

func (p *GitHubPlugin) Constraints(ctx context.Context) (*sdk.Constraints, error) {
	return &sdk.Constraints{
		MaxTTL:      time.Hour,
		Description: "GitHub installation tokens have a maximum lifetime of 1 hour",
	}, nil
}

func (p *GitHubPlugin) Configure(ctx context.Context, configJSON string) error {
	var config GitHubConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}

	if config.AppID == 0 {
		return fmt.Errorf("app_id is required")
	}
	if config.PrivateKeyPEM == "" {
		return fmt.Errorf("private_key_pem is required")
	}

	// Validate the private key can be parsed
	_, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(config.PrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	p.config = &config
	return nil
}

func (p *GitHubPlugin) Validate(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("plugin not configured")
	}

	// Try to list installations to validate the app credentials
	_, err := p.generateJWT()
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	installations, err := p.listInstallations(ctx)
	if err != nil {
		return fmt.Errorf("failed to list installations: %w", err)
	}

	if len(installations) == 0 {
		return fmt.Errorf("no installations found for this GitHub App")
	}

	return nil
}

func (p *GitHubPlugin) GetCredential(ctx context.Context, req *sdk.CredentialRequest) (*sdk.Credential, error) {
	if p.config == nil {
		return nil, fmt.Errorf("plugin not configured")
	}

	// Note: TTL constraints are validated by the Creddy server before calling GetCredential.
	// The Constraints() method declares MaxTTL = 1 hour.

	// Parse the scope
	pattern, perm, ok := parseGitHubScope(req.Scope)
	if !ok {
		return nil, fmt.Errorf("invalid github scope: %s", req.Scope)
	}

	readOnly := perm == "read"

	// Determine repos to scope the token to
	var repos []string
	if pattern != "*" && !strings.HasSuffix(pattern, "/*") {
		repos = []string{pattern}
	}

	// Get installation ID
	installationID := p.config.InstallationID
	if installationID == 0 {
		installations, err := p.listInstallations(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list installations: %w", err)
		}
		if len(installations) == 0 {
			return nil, fmt.Errorf("no installations found")
		}
		installationID = installations[0].ID
	}

	// Get the token with requested TTL
	token, err := p.getInstallationToken(ctx, installationID, repos, readOnly, req.TTL)
	if err != nil {
		return nil, err
	}

	return &sdk.Credential{
		Value:      token.Token,
		ExpiresAt:  token.ExpiresAt,
		Credential: token.Token, // Token needed for revocation via DELETE /installation/token
		Metadata: map[string]string{
			"installation_id": fmt.Sprintf("%d", installationID),
			"read_only":       fmt.Sprintf("%t", readOnly),
		},
	}, nil
}

func (p *GitHubPlugin) RevokeCredential(ctx context.Context, token string) error {
	// The token itself is passed here - use it to call GitHub's revoke endpoint
	if token == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", "https://api.github.com/installation/token", nil)
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	// 204 = success, 401 = token already expired/invalid (also fine)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub revoke failed (%d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *GitHubPlugin) MatchScope(ctx context.Context, scope string) (bool, error) {
	_, _, ok := parseGitHubScope(scope)
	return ok, nil
}

// --- GitHub API helpers ---

type githubToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
}

func (p *GitHubPlugin) generateJWT() (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(p.config.PrivateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": p.config.AppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

func (p *GitHubPlugin) listInstallations(ctx context.Context) ([]installation, error) {
	jwtToken, err := p.generateJWT()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/app/installations", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list installations: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API error (%d): %s", resp.StatusCode, string(body))
	}

	var installations []installation
	if err := json.Unmarshal(body, &installations); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return installations, nil
}

func (p *GitHubPlugin) getInstallationToken(ctx context.Context, installationID int64, repos []string, readOnly bool, ttl time.Duration) (*githubToken, error) {
	jwtToken, err := p.generateJWT()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	reqData := make(map[string]interface{})

	// Set expiration if TTL provided (GitHub max is 1 hour)
	if ttl > 0 {
		expiresAt := time.Now().Add(ttl)
		// GitHub max token lifetime is 1 hour
		maxExpiry := time.Now().Add(1 * time.Hour)
		if expiresAt.After(maxExpiry) {
			expiresAt = maxExpiry
		}
		reqData["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}

	if len(repos) > 0 {
		repoNames := make([]string, len(repos))
		for i, repo := range repos {
			parts := strings.SplitN(repo, "/", 2)
			if len(parts) == 2 {
				repoNames[i] = parts[1]
			} else {
				repoNames[i] = repo
			}
		}
		reqData["repositories"] = repoNames
	}

	if readOnly {
		reqData["permissions"] = map[string]string{
			"contents": "read",
			"metadata": "read",
		}
	}

	var reqBody io.Reader
	if len(reqData) > 0 {
		bodyJSON, _ := json.Marshal(reqData)
		reqBody = bytes.NewReader(bodyJSON)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request installation token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("github API error (%d): %s", resp.StatusCode, string(body))
	}

	var result githubToken
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// parseGitHubScope parses a scope like "github:owner/repo:read"
// Returns: pattern, permission (read/write), isGitHub
func parseGitHubScope(scope string) (pattern string, perm string, isGitHub bool) {
	if !strings.HasPrefix(scope, "github:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(scope, "github:")

	var perm_ string
	if strings.HasSuffix(rest, ":read") {
		rest = strings.TrimSuffix(rest, ":read")
		perm_ = "read"
	} else if strings.HasSuffix(rest, ":write") {
		rest = strings.TrimSuffix(rest, ":write")
		perm_ = "write"
	} else {
		perm_ = "write"
	}

	// Reject empty patterns (e.g., "github:" or "github::read")
	if rest == "" {
		return "", "", false
	}

	return rest, perm_, true
}
