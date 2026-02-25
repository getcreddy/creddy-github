//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
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
	appIDStr := os.Getenv(envAppID)
	privateKey := os.Getenv(envPrivateKey)
	installationIDStr := os.Getenv(envInstallationID)

	if appIDStr == "" {
		t.Fatalf("Required env var %s not set", envAppID)
	}
	if privateKey == "" {
		t.Fatalf("Required env var %s not set", envPrivateKey)
	}
	if installationIDStr == "" {
		t.Fatalf("Required env var %s not set", envInstallationID)
	}

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		t.Fatalf("Invalid %s: %v", envAppID, err)
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		t.Fatalf("Invalid %s: %v", envInstallationID, err)
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

// TestReadOnlyTokenCannotWrite verifies that read-only scoped tokens
// cannot perform write operations.
func TestReadOnlyTokenCannotWrite(t *testing.T) {
	ctx := context.Background()
	config := getTestConfigJSON(t)
	testRepo := getTestRepo(t)

	plugin := &GitHubPlugin{}
	err := plugin.Configure(ctx, config)
	if err != nil {
		t.Fatalf("Failed to configure plugin: %v", err)
	}

	// Get a read-only token
	cred, err := plugin.GetCredential(ctx, &sdk.CredentialRequest{
		Scope: fmt.Sprintf("github:%s:read", testRepo),
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}
	defer plugin.RevokeCredential(ctx, cred.Credential)

	t.Log("Got read-only token ✓")

	// Verify we can read
	resp, err := githubAPICall(cred.Value, fmt.Sprintf("/repos/%s", testRepo))
	if err != nil {
		t.Fatalf("API call failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for read, got %d", resp.StatusCode)
	}
	t.Log("Read operation works ✓")

	// Try to create an issue (write operation) - should fail
	issueURL := fmt.Sprintf("https://api.github.com/repos/%s/issues", testRepo)
	issueBody := `{"title":"Test issue from integration test","body":"This should fail"}`
	req, err := http.NewRequest("POST", issueURL, bytes.NewBufferString(issueBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+cred.Value)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Write request failed: %v", err)
	}
	resp.Body.Close()

	// Should get 403 Forbidden or 404 (GitHub returns 404 for permission denied on some endpoints)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 403 or 404 for write with read-only token, got %d", resp.StatusCode)
	}
	t.Logf("Write operation correctly denied with status %d ✓", resp.StatusCode)
}

// TestTTLIsRespected verifies that the token expiration matches the requested TTL.
func TestTTLIsRespected(t *testing.T) {
	ctx := context.Background()
	config := getTestConfigJSON(t)
	testRepo := getTestRepo(t)

	plugin := &GitHubPlugin{}
	err := plugin.Configure(ctx, config)
	if err != nil {
		t.Fatalf("Failed to configure plugin: %v", err)
	}

	// Request a 10-minute token
	requestedTTL := 10 * time.Minute
	before := time.Now()

	cred, err := plugin.GetCredential(ctx, &sdk.CredentialRequest{
		Scope: fmt.Sprintf("github:%s", testRepo),
		TTL:   requestedTTL,
	})
	if err != nil {
		t.Fatalf("Failed to get credential: %v", err)
	}
	defer plugin.RevokeCredential(ctx, cred.Credential)

	after := time.Now()

	// Calculate expected expiration window
	expectedMin := before.Add(requestedTTL).Add(-1 * time.Minute) // Allow 1 min slack
	expectedMax := after.Add(requestedTTL).Add(1 * time.Minute)

	if cred.ExpiresAt.Before(expectedMin) || cred.ExpiresAt.After(expectedMax) {
		t.Fatalf("Token expiration %v outside expected range [%v, %v]",
			cred.ExpiresAt, expectedMin, expectedMax)
	}

	actualTTL := cred.ExpiresAt.Sub(before)
	t.Logf("Requested TTL: %v, actual TTL: ~%v ✓", requestedTTL, actualTTL.Round(time.Second))
}

// TestConcurrentTokenGeneration verifies multiple tokens can be generated in parallel.
func TestConcurrentTokenGeneration(t *testing.T) {
	ctx := context.Background()
	config := getTestConfigJSON(t)
	testRepo := getTestRepo(t)

	plugin := &GitHubPlugin{}
	err := plugin.Configure(ctx, config)
	if err != nil {
		t.Fatalf("Failed to configure plugin: %v", err)
	}

	const numTokens = 5
	results := make(chan *sdk.Credential, numTokens)
	errors := make(chan error, numTokens)

	// Generate tokens concurrently
	for i := 0; i < numTokens; i++ {
		go func(id int) {
			cred, err := plugin.GetCredential(ctx, &sdk.CredentialRequest{
				Scope: fmt.Sprintf("github:%s", testRepo),
				TTL:   time.Hour,
			})
			if err != nil {
				errors <- fmt.Errorf("token %d: %w", id, err)
				return
			}
			results <- cred
		}(i)
	}

	// Collect results
	var tokens []*sdk.Credential
	for i := 0; i < numTokens; i++ {
		select {
		case cred := <-results:
			tokens = append(tokens, cred)
		case err := <-errors:
			t.Fatalf("Concurrent generation failed: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent tokens")
		}
	}

	t.Logf("Generated %d tokens concurrently ✓", len(tokens))

	// Verify all tokens are unique and valid
	seen := make(map[string]bool)
	for i, cred := range tokens {
		if seen[cred.Value] {
			t.Fatalf("Token %d is a duplicate", i)
		}
		seen[cred.Value] = true

		// Verify each token works
		resp, err := githubAPICall(cred.Value, fmt.Sprintf("/repos/%s", testRepo))
		if err != nil {
			t.Fatalf("Token %d API call failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Token %d got status %d", i, resp.StatusCode)
		}
	}
	t.Log("All tokens are unique and valid ✓")

	// Clean up
	for _, cred := range tokens {
		_ = plugin.RevokeCredential(ctx, cred.Credential)
	}
}

// TestInvalidScopeReturnsError verifies that invalid scopes are rejected.
func TestInvalidScopeReturnsError(t *testing.T) {
	ctx := context.Background()
	config := getTestConfigJSON(t)

	plugin := &GitHubPlugin{}
	err := plugin.Configure(ctx, config)
	if err != nil {
		t.Fatalf("Failed to configure plugin: %v", err)
	}

	testCases := []struct {
		name  string
		scope string
	}{
		{"empty scope", ""},
		{"wrong prefix", "gitlab:owner/repo"},
		{"no prefix", "owner/repo"},
		{"just github", "github"},
		{"trailing colon", "github:"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := plugin.GetCredential(ctx, &sdk.CredentialRequest{
				Scope: tc.scope,
				TTL:   time.Hour,
			})
			if err == nil {
				t.Errorf("Expected error for scope %q, got nil", tc.scope)
			} else {
				t.Logf("Scope %q correctly rejected: %v ✓", tc.scope, err)
			}
		})
	}
}

// TestConfigureValidation verifies configuration validation.
func TestConfigureValidation(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name   string
		config map[string]interface{}
	}{
		{
			name:   "missing app_id",
			config: map[string]interface{}{"private_key_pem": "fake"},
		},
		{
			name:   "missing private_key",
			config: map[string]interface{}{"app_id": int64(12345)},
		},
		{
			name: "invalid private_key",
			config: map[string]interface{}{
				"app_id":          int64(12345),
				"private_key_pem": "not-a-valid-pem-key",
			},
		},
		{
			name:   "empty config",
			config: map[string]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configJSON, _ := json.Marshal(tc.config)
			plugin := &GitHubPlugin{}
			err := plugin.Configure(ctx, string(configJSON))
			if err == nil {
				t.Errorf("Expected error for %s, got nil", tc.name)
			} else {
				t.Logf("%s correctly rejected: %v ✓", tc.name, err)
			}
		})
	}
}
