//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

// Required environment variables for integration tests.
// Tests FAIL (not skip) if these are not set.
const (
	envAppID          = "CREDDY_TEST_GITHUB_APP_ID"
	envPrivateKey     = "CREDDY_TEST_GITHUB_PRIVATE_KEY"
	envInstallationID = "CREDDY_TEST_GITHUB_INSTALLATION_ID"
	envTestRepo       = "CREDDY_TEST_GITHUB_REPO" // e.g., "getcreddy/creddy-test-repo"
)

func getTestConfigJSON(t *testing.T) string {
	appID := os.Getenv(envAppID)
	privateKey := os.Getenv(envPrivateKey)
	installationID := os.Getenv(envInstallationID)

	if appID == "" {
		t.Fatalf("Required env var %s not set", envAppID)
	}
	if privateKey == "" {
		t.Fatalf("Required env var %s not set", envPrivateKey)
	}
	if installationID == "" {
		t.Fatalf("Required env var %s not set", envInstallationID)
	}

	config := map[string]interface{}{
		"app_id":          appID,
		"private_key_pem": privateKey,
		"installation_id": installationID,
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	return string(configJSON)
}

func getTestRepo(t *testing.T) string {
	repo := os.Getenv(envTestRepo)
	if repo == "" {
		t.Fatalf("Required env var %s not set", envTestRepo)
	}
	return repo
}

// githubAPICall makes a request to GitHub API with the given token
func githubAPICall(token, endpoint string) (*http.Response, error) {
	url := fmt.Sprintf("https://api.github.com%s", endpoint)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// TestRevocationInvalidatesToken verifies that calling RevokeCredential
// actually invalidates the token on GitHub's side.
func TestRevocationInvalidatesToken(t *testing.T) {
	ctx := context.Background()
	config := getTestConfigJSON(t)
	testRepo := getTestRepo(t)

	// 1. Configure plugin
	plugin := &GitHubPlugin{}
	err := plugin.Configure(ctx, config)
	if err != nil {
		t.Fatalf("Failed to configure plugin: %v", err)
	}

	// 2. Get a token
	cred, err := plugin.GetCredential(ctx, &sdk.CredentialRequest{
		Scope: fmt.Sprintf("github:%s", testRepo),
		TTL:   time.Hour, // TTL doesn't matter for this test
	})
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}

	if cred.Value == "" {
		t.Fatal("Got empty token")
	}
	if cred.Credential == "" {
		t.Fatal("Got empty Credential field (needed for revocation)")
	}

	t.Logf("Got token (first 10 chars): %s...", cred.Value[:10])

	// 3. Verify token works
	resp, err := githubAPICall(cred.Value, fmt.Sprintf("/repos/%s", testRepo))
	if err != nil {
		t.Fatalf("API call failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 before revocation, got %d", resp.StatusCode)
	}
	t.Log("Token works before revocation ✓")

	// 4. Revoke the token
	err = plugin.RevokeCredential(ctx, cred.Credential)
	if err != nil {
		t.Fatalf("Failed to revoke credential: %v", err)
	}
	t.Log("Revoked token ✓")

	// 5. Verify token no longer works
	resp, err = githubAPICall(cred.Value, fmt.Sprintf("/repos/%s", testRepo))
	if err != nil {
		t.Fatalf("API call failed after revocation: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 after revocation, got %d", resp.StatusCode)
	}
	t.Log("Token rejected after revocation ✓")
}

// TestGetCredentialReturnsValidToken verifies basic token generation works.
func TestGetCredentialReturnsValidToken(t *testing.T) {
	ctx := context.Background()
	config := getTestConfigJSON(t)
	testRepo := getTestRepo(t)

	plugin := &GitHubPlugin{}
	err := plugin.Configure(ctx, config)
	if err != nil {
		t.Fatalf("Failed to configure plugin: %v", err)
	}

	cred, err := plugin.GetCredential(ctx, &sdk.CredentialRequest{
		Scope: fmt.Sprintf("github:%s", testRepo),
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}

	// Verify we got a token
	if cred.Value == "" {
		t.Fatal("Got empty token")
	}

	// Verify expiration is set
	if cred.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt not set")
	}

	// Verify Credential field is set (for revocation)
	if cred.Credential == "" {
		t.Fatal("Credential field not set")
	}

	// Clean up - revoke the token we created
	_ = plugin.RevokeCredential(ctx, cred.Credential)
}
