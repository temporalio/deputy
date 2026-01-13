package secrets

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VerificationStatus represents the result of validating a secret.
type VerificationStatus string

const (
	// StatusUnknown means verification was not attempted or inconclusive.
	StatusUnknown VerificationStatus = "unknown"
	// StatusValid means the secret was confirmed active/working.
	StatusValid VerificationStatus = "valid"
	// StatusInvalid means the secret was confirmed invalid/revoked.
	StatusInvalid VerificationStatus = "invalid"
	// StatusExpired means the secret has expired.
	StatusExpired VerificationStatus = "expired"
	// StatusRateLimited means verification was blocked by rate limiting.
	StatusRateLimited VerificationStatus = "rate_limited"
	// StatusError means verification failed due to an error.
	StatusError VerificationStatus = "error"
)

// VerificationResult contains details about a secret verification attempt.
type VerificationResult struct {
	// Status is the verification outcome.
	Status VerificationStatus `json:"status"`
	// Message provides additional context about the verification.
	Message string `json:"message,omitempty"`
	// Service identifies the service the secret belongs to.
	Service string `json:"service,omitempty"`
	// Identity is the authenticated identity (e.g., username, service account).
	Identity string `json:"identity,omitempty"`
	// Scopes lists the permissions/scopes the secret has.
	Scopes []string `json:"scopes,omitempty"`
	// ExpiresAt is when the secret expires (if applicable).
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	// VerifiedAt is when verification was performed.
	VerifiedAt time.Time `json:"verifiedAt"`
	// Error contains error details if verification failed.
	Error string `json:"error,omitempty"`
}

// Verifier validates whether detected secrets are active.
type Verifier interface {
	// CanVerify returns true if this verifier handles the given secret type.
	CanVerify(secretType SecretType) bool
	// Verify checks if a secret is valid/active.
	Verify(ctx context.Context, secret string, secretType SecretType) VerificationResult
	// Name returns the verifier name for logging.
	Name() string
}

// VerificationEngine orchestrates secret verification across multiple providers.
type VerificationEngine struct {
	verifiers []Verifier
	client    *http.Client
	// RateLimiter controls verification request rate.
	rateLimit *rateLimiter
}

// VerificationConfig configures the verification engine.
type VerificationConfig struct {
	// Timeout for individual verification requests.
	Timeout time.Duration
	// MaxConcurrent limits parallel verification requests.
	MaxConcurrent int
	// SkipTLSVerify disables TLS certificate validation (for testing).
	SkipTLSVerify bool
	// RateLimit is max verifications per second (0 = unlimited).
	RateLimit int
}

// NewVerificationEngine creates a verification engine with default providers.
func NewVerificationEngine(cfg *VerificationConfig) *VerificationEngine {
	if cfg == nil {
		cfg = &VerificationConfig{
			Timeout:       10 * time.Second,
			MaxConcurrent: 5,
			RateLimit:     10, // 10 verifications per second
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		},
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}

	engine := &VerificationEngine{
		client:    client,
		rateLimit: newRateLimiter(cfg.RateLimit),
	}

	// Register built-in verifiers
	engine.verifiers = []Verifier{
		newGitHubVerifier(client),
		newGitLabVerifier(client),
		newAWSVerifier(client),
		newSlackVerifier(client),
		newStripeVerifier(client),
		newSendGridVerifier(client),
		newNpmVerifier(client),
		newOpenAIVerifier(client),
		newAnthropicVerifier(client),
		newDigitalOceanVerifier(client),
		newTerraformCloudVerifier(client),
		newLinearVerifier(client),
		newPyPIVerifier(client),
		newDatadogVerifier(client),
	}

	return engine
}

// Verify attempts to validate a secret using registered verifiers.
func (e *VerificationEngine) Verify(ctx context.Context, finding Finding) VerificationResult {
	// Wait for rate limiter
	if err := e.rateLimit.Wait(ctx); err != nil {
		return VerificationResult{
			Status:     StatusError,
			Error:      "rate limit context cancelled",
			VerifiedAt: time.Now().UTC(),
		}
	}

	// Find appropriate verifier
	for _, v := range e.verifiers {
		if v.CanVerify(finding.Type) {
			result := v.Verify(ctx, finding.Value, finding.Type)
			result.VerifiedAt = time.Now().UTC()
			return result
		}
	}

	// No verifier available
	return VerificationResult{
		Status:     StatusUnknown,
		Message:    "no verifier available for this secret type",
		VerifiedAt: time.Now().UTC(),
	}
}

// VerifyBatch verifies multiple findings concurrently.
func (e *VerificationEngine) VerifyBatch(ctx context.Context, findings []Finding) map[int]VerificationResult {
	results := make(map[int]VerificationResult)

	for i, f := range findings {
		select {
		case <-ctx.Done():
			results[i] = VerificationResult{
				Status:     StatusError,
				Error:      "context cancelled",
				VerifiedAt: time.Now().UTC(),
			}
		default:
			results[i] = e.Verify(ctx, f)
		}
	}

	return results
}

// rateLimiter provides simple rate limiting.
type rateLimiter struct {
	rate     int
	interval time.Duration
	last     time.Time
}

func newRateLimiter(ratePerSecond int) *rateLimiter {
	if ratePerSecond <= 0 {
		return &rateLimiter{rate: 0} // No limit
	}
	return &rateLimiter{
		rate:     ratePerSecond,
		interval: time.Second / time.Duration(ratePerSecond),
	}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	if r.rate == 0 {
		return nil // No limit
	}

	elapsed := time.Since(r.last)
	if elapsed < r.interval {
		select {
		case <-time.After(r.interval - elapsed):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.last = time.Now()
	return nil
}

// =============================================================================
// GitHub Token Verifier
// =============================================================================

type gitHubVerifier struct {
	client *http.Client
}

func newGitHubVerifier(client *http.Client) *gitHubVerifier {
	return &gitHubVerifier{client: client}
}

func (v *gitHubVerifier) Name() string { return "github" }

func (v *gitHubVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeGitHubToken || secretType == TypeGitHubFineGrain
}

func (v *gitHubVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var user struct {
			Login string `json:"login"`
			ID    int    `json:"id"`
			Type  string `json:"type"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			return VerificationResult{
				Status:  StatusValid,
				Service: "github",
				Message: "token is valid but failed to parse response",
			}
		}

		// Get token scopes from response header
		scopes := parseGitHubScopes(resp.Header.Get("X-OAuth-Scopes"))

		return VerificationResult{
			Status:   StatusValid,
			Service:  "github",
			Identity: user.Login,
			Scopes:   scopes,
			Message:  fmt.Sprintf("authenticated as %s (type: %s)", user.Login, user.Type),
		}

	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "github",
			Message: "token is invalid or revoked",
		}

	case http.StatusForbidden:
		// Could be rate limited or token with insufficient scopes
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return VerificationResult{
				Status:  StatusRateLimited,
				Service: "github",
				Message: "GitHub API rate limit exceeded",
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "github",
			Message: "token valid but lacks permissions for user endpoint",
		}

	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "github",
			Error:   fmt.Sprintf("unexpected status %d", resp.StatusCode),
		}
	}
}

func parseGitHubScopes(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ", ")
	scopes := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// =============================================================================
// AWS Access Key Verifier
// =============================================================================

type awsVerifier struct {
	client *http.Client
}

func newAWSVerifier(client *http.Client) *awsVerifier {
	return &awsVerifier{client: client}
}

func (v *awsVerifier) Name() string { return "aws" }

func (v *awsVerifier) CanVerify(secretType SecretType) bool {
	// AWS verification requires both access key and secret key
	// We can only validate the access key format here
	return secretType == TypeAWSAccessKey
}

func (v *awsVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	// AWS access key validation requires the secret key too
	// We can only validate format here, not actual validity
	if !strings.HasPrefix(secret, "AKIA") || len(secret) != 20 {
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "aws",
			Message: "invalid AWS access key format",
		}
	}

	return VerificationResult{
		Status:  StatusUnknown,
		Service: "aws",
		Message: "AWS keys require secret key for full verification; format appears valid",
	}
}

// =============================================================================
// Slack Token Verifier
// =============================================================================

type slackVerifier struct {
	client *http.Client
}

func newSlackVerifier(client *http.Client) *slackVerifier {
	return &slackVerifier{client: client}
}

func (v *slackVerifier) Name() string { return "slack" }

func (v *slackVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeSlackToken
}

func (v *slackVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://slack.com/api/auth.test", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		User  string `json:"user"`
		Team  string `json:"team"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	if result.OK {
		return VerificationResult{
			Status:   StatusValid,
			Service:  "slack",
			Identity: fmt.Sprintf("%s@%s", result.User, result.Team),
			Message:  fmt.Sprintf("authenticated as %s in workspace %s", result.User, result.Team),
		}
	}

	if result.Error == "invalid_auth" || result.Error == "token_revoked" {
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "slack",
			Message: result.Error,
		}
	}

	return VerificationResult{
		Status:  StatusError,
		Service: "slack",
		Error:   result.Error,
	}
}

// =============================================================================
// Stripe Key Verifier
// =============================================================================

type stripeVerifier struct {
	client *http.Client
}

func newStripeVerifier(client *http.Client) *stripeVerifier {
	return &stripeVerifier{client: client}
}

func (v *stripeVerifier) Name() string { return "stripe" }

func (v *stripeVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeStripeKey
}

func (v *stripeVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	// Determine if test or live key
	mode := "live"
	if strings.Contains(secret, "_test_") {
		mode = "test"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/balance", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.SetBasicAuth(secret, "")

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return VerificationResult{
			Status:  StatusValid,
			Service: "stripe",
			Message: fmt.Sprintf("valid %s mode API key with balance access", mode),
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "stripe",
			Message: "invalid or revoked API key",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "stripe",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// SendGrid Key Verifier
// =============================================================================

type sendGridVerifier struct {
	client *http.Client
}

func newSendGridVerifier(client *http.Client) *sendGridVerifier {
	return &sendGridVerifier{client: client}
}

func (v *sendGridVerifier) Name() string { return "sendgrid" }

func (v *sendGridVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeSendGridKey
}

func (v *sendGridVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Scopes []string `json:"scopes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			return VerificationResult{
				Status:  StatusValid,
				Service: "sendgrid",
				Scopes:  result.Scopes,
				Message: fmt.Sprintf("valid API key with %d scopes", len(result.Scopes)),
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "sendgrid",
			Message: "valid API key",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "sendgrid",
			Message: "invalid or revoked API key",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "sendgrid",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// npm Token Verifier
// =============================================================================

type npmVerifier struct {
	client *http.Client
}

func newNpmVerifier(client *http.Client) *npmVerifier {
	return &npmVerifier{client: client}
}

func (v *npmVerifier) Name() string { return "npm" }

func (v *npmVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeNpmToken
}

func (v *npmVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://registry.npmjs.org/-/npm/v1/user", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Name != "" {
			return VerificationResult{
				Status:   StatusValid,
				Service:  "npm",
				Identity: result.Name,
				Message:  fmt.Sprintf("authenticated as %s", result.Name),
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "npm",
			Message: "valid npm token",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "npm",
			Message: "invalid or revoked token",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "npm",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// GitLab Token Verifier
// =============================================================================

type gitLabVerifier struct {
	client *http.Client
}

func newGitLabVerifier(client *http.Client) *gitLabVerifier {
	return &gitLabVerifier{client: client}
}

func (v *gitLabVerifier) Name() string { return "gitlab" }

func (v *gitLabVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeGitLabToken
}

func (v *gitLabVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://gitlab.com/api/v4/user", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("PRIVATE-TOKEN", secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var user struct {
			Username string `json:"username"`
			Name     string `json:"name"`
			ID       int    `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err == nil && user.Username != "" {
			return VerificationResult{
				Status:   StatusValid,
				Service:  "gitlab",
				Identity: user.Username,
				Message:  fmt.Sprintf("authenticated as %s (%s)", user.Username, user.Name),
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "gitlab",
			Message: "valid GitLab token",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "gitlab",
			Message: "invalid or revoked token",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "gitlab",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// OpenAI API Key Verifier
// =============================================================================

type openAIVerifier struct {
	client *http.Client
}

func newOpenAIVerifier(client *http.Client) *openAIVerifier {
	return &openAIVerifier{client: client}
}

func (v *openAIVerifier) Name() string { return "openai" }

func (v *openAIVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeOpenAIKey
}

func (v *openAIVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return VerificationResult{
			Status:  StatusValid,
			Service: "openai",
			Message: "valid API key with model access",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "openai",
			Message: "invalid or revoked API key",
		}
	case http.StatusTooManyRequests:
		return VerificationResult{
			Status:  StatusRateLimited,
			Service: "openai",
			Message: "rate limited - key may be valid",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "openai",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// Anthropic API Key Verifier
// =============================================================================

type anthropicVerifier struct {
	client *http.Client
}

func newAnthropicVerifier(client *http.Client) *anthropicVerifier {
	return &anthropicVerifier{client: client}
}

func (v *anthropicVerifier) Name() string { return "anthropic" }

func (v *anthropicVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeAnthropicKey
}

func (v *anthropicVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	// Use a minimal request to check key validity
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages",
		strings.NewReader(`{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("x-api-key", secret)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // Drain body for connection reuse

	switch resp.StatusCode {
	case http.StatusOK:
		return VerificationResult{
			Status:  StatusValid,
			Service: "anthropic",
			Message: "valid API key",
		}
	case http.StatusBadRequest:
		// Bad request usually means the key is valid but request was malformed
		return VerificationResult{
			Status:  StatusValid,
			Service: "anthropic",
			Message: "API key appears valid (request validation)",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "anthropic",
			Message: "invalid or revoked API key",
		}
	case http.StatusTooManyRequests:
		return VerificationResult{
			Status:  StatusRateLimited,
			Service: "anthropic",
			Message: "rate limited - key may be valid",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "anthropic",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// DigitalOcean Token Verifier
// =============================================================================

type digitalOceanVerifier struct {
	client *http.Client
}

func newDigitalOceanVerifier(client *http.Client) *digitalOceanVerifier {
	return &digitalOceanVerifier{client: client}
}

func (v *digitalOceanVerifier) Name() string { return "digitalocean" }

func (v *digitalOceanVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeDigitalOceanToken
}

func (v *digitalOceanVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.digitalocean.com/v2/account", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Account struct {
				Email string `json:"email"`
			} `json:"account"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Account.Email != "" {
			return VerificationResult{
				Status:   StatusValid,
				Service:  "digitalocean",
				Identity: result.Account.Email,
				Message:  fmt.Sprintf("authenticated as %s", result.Account.Email),
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "digitalocean",
			Message: "valid token",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "digitalocean",
			Message: "invalid or revoked token",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "digitalocean",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// Terraform Cloud Token Verifier
// =============================================================================

type terraformCloudVerifier struct {
	client *http.Client
}

func newTerraformCloudVerifier(client *http.Client) *terraformCloudVerifier {
	return &terraformCloudVerifier{client: client}
}

func (v *terraformCloudVerifier) Name() string { return "terraform" }

func (v *terraformCloudVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeTerraformToken
}

func (v *terraformCloudVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://app.terraform.io/api/v2/account/details", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Data struct {
				Attributes struct {
					Username string `json:"username"`
					Email    string `json:"email"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Data.Attributes.Username != "" {
			return VerificationResult{
				Status:   StatusValid,
				Service:  "terraform_cloud",
				Identity: result.Data.Attributes.Username,
				Message:  fmt.Sprintf("authenticated as %s", result.Data.Attributes.Username),
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "terraform_cloud",
			Message: "valid token",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "terraform_cloud",
			Message: "invalid or revoked token",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "terraform_cloud",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// Linear API Key Verifier
// =============================================================================

type linearVerifier struct {
	client *http.Client
}

func newLinearVerifier(client *http.Client) *linearVerifier {
	return &linearVerifier{client: client}
}

func (v *linearVerifier) Name() string { return "linear" }

func (v *linearVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeLinearAPIKey
}

func (v *linearVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.linear.app/graphql",
		strings.NewReader(`{"query":"{ viewer { id name email } }"}`))
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Data struct {
				Viewer struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"viewer"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Data.Viewer.Email != "" {
			return VerificationResult{
				Status:   StatusValid,
				Service:  "linear",
				Identity: result.Data.Viewer.Email,
				Message:  fmt.Sprintf("authenticated as %s", result.Data.Viewer.Name),
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "linear",
			Message: "valid API key",
		}
	case http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "linear",
			Message: "invalid or revoked API key",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "linear",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}

// =============================================================================
// PyPI Token Verifier
// =============================================================================

type pyPIVerifier struct {
	client *http.Client
}

func newPyPIVerifier(client *http.Client) *pyPIVerifier {
	return &pyPIVerifier{client: client}
}

func (v *pyPIVerifier) Name() string { return "pypi" }

func (v *pyPIVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypePyPIToken
}

func (v *pyPIVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	// PyPI doesn't have a simple whoami endpoint, but we can check token format
	// and attempt to list user's packages
	if !strings.HasPrefix(secret, "pypi-") {
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "pypi",
			Message: "invalid PyPI token format",
		}
	}

	// PyPI tokens can be verified by attempting to get upload permissions
	// This is a minimal check - full verification would require upload attempt
	return VerificationResult{
		Status:  StatusUnknown,
		Service: "pypi",
		Message: "PyPI token format valid; full verification requires upload attempt",
	}
}

// =============================================================================
// Datadog API Key Verifier
// =============================================================================

type datadogVerifier struct {
	client *http.Client
}

func newDatadogVerifier(client *http.Client) *datadogVerifier {
	return &datadogVerifier{client: client}
}

func (v *datadogVerifier) Name() string { return "datadog" }

func (v *datadogVerifier) CanVerify(secretType SecretType) bool {
	return secretType == TypeDatadogAPIKey
}

func (v *datadogVerifier) Verify(ctx context.Context, secret string, _ SecretType) VerificationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.datadoghq.com/api/v1/validate", nil)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}

	req.Header.Set("DD-API-KEY", secret)

	resp, err := v.client.Do(req)
	if err != nil {
		return VerificationResult{Status: StatusError, Error: err.Error()}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Valid bool `json:"valid"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if result.Valid {
				return VerificationResult{
					Status:  StatusValid,
					Service: "datadog",
					Message: "valid API key",
				}
			}
			return VerificationResult{
				Status:  StatusInvalid,
				Service: "datadog",
				Message: "API key validation returned false",
			}
		}
		return VerificationResult{
			Status:  StatusValid,
			Service: "datadog",
			Message: "valid API key",
		}
	case http.StatusForbidden, http.StatusUnauthorized:
		return VerificationResult{
			Status:  StatusInvalid,
			Service: "datadog",
			Message: "invalid or revoked API key",
		}
	default:
		return VerificationResult{
			Status:  StatusError,
			Service: "datadog",
			Error:   fmt.Sprintf("unexpected status: %d", resp.StatusCode),
		}
	}
}
