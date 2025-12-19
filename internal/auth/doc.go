// Package auth provides unified credential management for Deputy.
//
// This package implements secure, host-aware credential resolution to prevent
// "confused deputy" attacks where credentials are inadvertently sent to the
// wrong endpoints. It supports multiple authentication backends including:
//
//   - Git hosting services (GitHub, GitLab, Bitbucket, self-hosted)
//   - Package registries (npm, Go proxy, PyPI, container registries)
//   - REST APIs (GitHub API, GitLab API)
//   - LLM providers (Anthropic, OpenAI, etc.)
//
// # Credential Resolution
//
// Credentials are resolved through a chain of providers with host matching:
//
//	store := auth.NewStore(
//	    auth.WithProvider(auth.NewChainProvider(
//	        auth.NewEnvProvider(),   // GITHUB_TOKEN, ANTHROPIC_API_KEY, etc.
//	        // Add more providers here...
//	    )),
//	)
//
//	// Get Git auth for a specific host - safe, won't leak to other hosts
//	gitAuth, err := store.GitAuth(ctx, "https://github.com/owner/repo")
//
//	// Get HTTP bearer token for API calls
//	token, err := store.HTTPBearerToken(ctx, "api.github.com")
//
// # Security Model
//
// The package follows a principle of least privilege:
//
//   - Credentials are scoped to specific hosts or host patterns
//   - No credential is sent unless the target host explicitly matches
//   - HTTPS is required for credential transmission (configurable)
//   - Sensitive values are redacted in logs and error messages
//
// # Upstream API Integration
//
// The package provides adapters for common Go authentication interfaces:
//
// ## oauth2.TokenSource
//
// For creating authenticated HTTP clients with golang.org/x/oauth2:
//
//	ts, err := store.TokenSource(ctx, "api.github.com")
//	client := oauth2.NewClient(ctx, ts)
//	gh := github.NewClient(client)  // Use with go-github
//
// ## http.RoundTripper
//
// For automatic credential injection in HTTP requests:
//
//	rt := store.RoundTripper(http.DefaultTransport)
//	client := &http.Client{Transport: rt}
//
// ## go-git transport.AuthMethod
//
// For Git clone/fetch/push operations:
//
//	auth, err := store.GitAuth(ctx, "https://github.com/owner/repo")
//	repo, err := git.Clone(storage, worktree, &git.CloneOptions{
//	    URL:  "https://github.com/owner/repo",
//	    Auth: auth,
//	})
//
// # Supported Credential Types
//
//   - [TokenCredential]: Bearer/API tokens (GitHub PAT, Anthropic API key, JWT)
//   - [BasicCredential]: Username/password pairs (npm, PyPI)
//   - [SSHCredential]: SSH keys for Git operations
//   - [DockerCredential]: Container registry auth (from Docker config)
//
// # Environment Variable Conventions
//
// The package recognizes standard environment variables:
//
//	GITHUB_TOKEN          - GitHub Personal Access Token
//	GH_TOKEN              - GitHub CLI token (alternative)
//	GITLAB_TOKEN          - GitLab Personal Access Token
//	BITBUCKET_TOKEN       - Bitbucket App Password
//	ANTHROPIC_API_KEY     - Anthropic Claude API key
//	OPENAI_API_KEY        - OpenAI API key
//	NPM_TOKEN             - npm registry auth token
//
// For self-hosted instances:
//
//	GITHUB_ENTERPRISE_HOST=github.mycompany.com
//	GITHUB_ENTERPRISE_TOKEN=ghp_xxx
package auth
