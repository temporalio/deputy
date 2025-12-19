package auth_test

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v63/github"
	"github.com/picatz/deputy/internal/auth"
	"golang.org/x/oauth2"
)

// Example_oauth2Client demonstrates using the auth package with oauth2
// to create authenticated GitHub API clients.
func Example_oauth2Client() {
	ctx := context.Background()
	store := auth.DefaultStore()

	// Get a token source for GitHub API
	ts, err := store.TokenSource(ctx, "api.github.com")
	if err != nil || ts == nil {
		fmt.Println("No GitHub credentials available (set GITHUB_TOKEN)")
		return
	}

	// Create an oauth2 HTTP client
	client := oauth2.NewClient(ctx, ts)

	// Use with go-github
	gh := github.NewClient(client)
	_ = gh // Use gh for GitHub API calls

	fmt.Println("GitHub client created with auth")
}

// Example_httpRoundTripper demonstrates using the auth package
// with custom HTTP clients.
func Example_httpRoundTripper() {
	store := auth.DefaultStore()

	// Create an HTTP client with automatic auth
	client := store.HTTPClient(nil)

	// All requests will have auth headers added automatically
	// (only for hosts that have credentials)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Request completed with status:", resp.Status)
}

// Example_gitOperations demonstrates using auth for git clone operations.
func Example_gitOperations() {
	ctx := context.Background()
	store := auth.DefaultStore()

	// Get git auth for a GitHub repository
	gitAuth, err := store.GitAuth(ctx, "https://github.com/owner/private-repo")
	if err != nil {
		fmt.Println("Failed to get git auth:", err)
		return
	}

	if gitAuth == nil {
		fmt.Println("No credentials available - will use anonymous access")
		return
	}

	fmt.Println("Git auth ready:", gitAuth.String())
}

// Example_llmAPIKey demonstrates retrieving API keys for LLM providers.
func Example_llmAPIKey() {
	ctx := context.Background()
	store := auth.DefaultStore()

	// Get API key for Anthropic
	key, err := store.LLMAPIKey(ctx, "api.anthropic.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if key == "" {
		fmt.Println("No API key configured for Anthropic")
		return
	}

	fmt.Println("Anthropic API key retrieved successfully")
}

// Example_multipleProviders demonstrates chaining multiple credential providers.
func Example_multipleProviders() {
	// Create a chain of providers with fallback behavior
	chain := auth.NewChainProvider(
		// Add custom providers here...
		auth.NewEnvProvider(), // Falls back to environment variables
	)

	store := auth.NewStore(auth.WithProvider(chain))

	ctx := context.Background()
	token, err := store.HTTPBearerToken(ctx, "api.github.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if token != "" {
		fmt.Println("Token retrieved from chain")
	} else {
		fmt.Println("No token available")
	}
}
