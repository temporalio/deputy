package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// Registry type constants for detection and specialized handling.
const (
	RegistryTypeUnknown      = "unknown"
	RegistryTypeDockerHub    = "dockerhub"
	RegistryTypeGHCR         = "ghcr"
	RegistryTypeECR          = "ecr"
	RegistryTypeECRPublic    = "ecr-public"
	RegistryTypeGCR          = "gcr"
	RegistryTypeGAR          = "gar" // Google Artifact Registry
	RegistryTypeACR          = "acr" // Azure Container Registry
	RegistryTypeQuay         = "quay"
	RegistryTypeGitLab       = "gitlab"
	RegistryTypeSelfHosted   = "self-hosted"
)

// RegistryInfo contains detected information about a container registry.
type RegistryInfo struct {
	// Type identifies the registry (ecr, ghcr, dockerhub, etc.)
	Type string

	// Host is the registry hostname (e.g., "123456789.dkr.ecr.us-east-1.amazonaws.com")
	Host string

	// Region is the AWS region for ECR registries (empty for others)
	Region string

	// AccountID is the AWS account ID for ECR registries (empty for others)
	AccountID string

	// Project is the GCP project for GCR/GAR (empty for others)
	Project string
}

// detectRegistry analyzes a repository path and returns registry information.
func detectRegistry(repoPath string) RegistryInfo {
	// Parse to get the registry host
	repo, err := name.NewRepository(repoPath, name.WeakValidation)
	if err != nil {
		return RegistryInfo{Type: RegistryTypeUnknown, Host: repoPath}
	}

	host := repo.RegistryStr()
	info := RegistryInfo{Host: host}

	switch {
	// AWS ECR (private): 123456789.dkr.ecr.us-east-1.amazonaws.com
	case isECRHost(host):
		info.Type = RegistryTypeECR
		info.AccountID, info.Region = parseECRHost(host)

	// AWS ECR Public: public.ecr.aws
	case host == "public.ecr.aws":
		info.Type = RegistryTypeECRPublic

	// Docker Hub: index.docker.io, docker.io, registry-1.docker.io
	case host == "index.docker.io" || host == "docker.io" || host == "registry-1.docker.io":
		info.Type = RegistryTypeDockerHub

	// GitHub Container Registry: ghcr.io
	case host == "ghcr.io":
		info.Type = RegistryTypeGHCR

	// Google Container Registry: gcr.io, us.gcr.io, eu.gcr.io, asia.gcr.io
	case strings.HasSuffix(host, "gcr.io"):
		info.Type = RegistryTypeGCR
		info.Project = extractGCRProject(repoPath)

	// Google Artifact Registry: *-docker.pkg.dev
	case strings.HasSuffix(host, "-docker.pkg.dev"):
		info.Type = RegistryTypeGAR
		info.Project = extractGARProject(repoPath)

	// Azure Container Registry: *.azurecr.io
	case strings.HasSuffix(host, ".azurecr.io"):
		info.Type = RegistryTypeACR

	// Quay.io
	case host == "quay.io":
		info.Type = RegistryTypeQuay

	// GitLab Registry: registry.gitlab.com
	case host == "registry.gitlab.com":
		info.Type = RegistryTypeGitLab

	default:
		info.Type = RegistryTypeSelfHosted
	}

	return info
}

// ECR host pattern: 123456789012.dkr.ecr.us-east-1.amazonaws.com
var ecrHostPattern = regexp.MustCompile(`^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$`)

// isECRHost checks if a host is an AWS ECR private registry.
func isECRHost(host string) bool {
	return ecrHostPattern.MatchString(host)
}

// parseECRHost extracts account ID and region from an ECR host.
func parseECRHost(host string) (accountID, region string) {
	matches := ecrHostPattern.FindStringSubmatch(host)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

// extractGCRProject extracts the GCP project from a GCR repository path.
func extractGCRProject(repoPath string) string {
	// gcr.io/project/image → project
	parts := strings.SplitN(repoPath, "/", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// extractGARProject extracts the GCP project from a GAR repository path.
func extractGARProject(repoPath string) string {
	// us-docker.pkg.dev/project/repo/image → project
	parts := strings.SplitN(repoPath, "/", 4)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// RegistryKeychain implements authn.Keychain with enhanced support for
// various container registries, including direct AWS ECR authentication.
type RegistryKeychain struct {
	// fallback is the default keychain (docker config)
	fallback authn.Keychain

	// ecrCache caches ECR authentication tokens
	ecrCache *ecrTokenCache
}

// NewRegistryKeychain creates a keychain with enhanced registry support.
func NewRegistryKeychain() *RegistryKeychain {
	return &RegistryKeychain{
		fallback: authn.DefaultKeychain,
		ecrCache: newECRTokenCache(),
	}
}

// Resolve implements authn.Keychain.
// The resolution order prioritizes existing user credentials:
//  1. Docker config (~/.docker/config.json) and credential helpers
//  2. Environment variables (GITHUB_TOKEN, AWS credentials)
//  3. Anonymous access
//
// This ensures users who have already run `docker login` or configured
// credential helpers don't have their setup bypassed.
func (k *RegistryKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	host := target.RegistryStr()
	info := detectRegistry(host)

	// Always try docker config first - respect existing user credentials
	auth, err := k.fallback.Resolve(target)
	if err == nil && auth != authn.Anonymous {
		// User has credentials configured via docker login or credential helper
		return auth, nil
	}

	// No existing credentials found, try registry-specific fallbacks
	switch info.Type {
	case RegistryTypeECR:
		// Try direct ECR authentication via AWS SDK
		// This helps users who have AWS credentials but haven't run `docker login`
		ecrAuth, ecrErr := k.resolveECR(info)
		if ecrErr == nil && ecrAuth != nil {
			return ecrAuth, nil
		}
		// If both docker config and AWS SDK failed, return the original result
		// (which might be anonymous or an error)
		if err != nil {
			return nil, err
		}
		return auth, nil

	case RegistryTypeGHCR:
		// Try GITHUB_TOKEN as fallback for users who haven't run `docker login ghcr.io`
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			return &authn.Basic{
				Username: "oauth2",
				Password: token,
			}, nil
		}
		// Return original result (might be anonymous)
		if err != nil {
			return nil, err
		}
		return auth, nil

	default:
		// For other registries, return whatever docker config gave us
		if err != nil {
			return nil, err
		}
		return auth, nil
	}
}

// resolveECR attempts direct ECR authentication using AWS SDK.
func (k *RegistryKeychain) resolveECR(info RegistryInfo) (authn.Authenticator, error) {
	// Check cache first
	if auth := k.ecrCache.get(info.Host); auth != nil {
		return auth, nil
	}

	// Try to get ECR token using AWS SDK
	ctx := context.Background()

	// Load AWS configuration (respects AWS_REGION, AWS_PROFILE, etc.)
	opts := []func(*config.LoadOptions) error{}
	if info.Region != "" {
		opts = append(opts, config.WithRegion(info.Region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	// Create ECR client
	client := ecr.NewFromConfig(cfg)

	// Get authorization token
	result, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("get ECR token: %w", err)
	}

	if len(result.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no ECR authorization data returned")
	}

	authData := result.AuthorizationData[0]
	if authData.AuthorizationToken == nil {
		return nil, fmt.Errorf("ECR authorization token is nil")
	}

	// Decode base64 token (format: "AWS:password")
	decoded, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	if err != nil {
		return nil, fmt.Errorf("decode ECR token: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid ECR token format")
	}

	auth := &authn.Basic{
		Username: parts[0], // "AWS"
		Password: parts[1],
	}

	// Cache the token (ECR tokens are valid for 12 hours)
	expiry := time.Now().Add(11 * time.Hour) // Use 11 hours to be safe
	if authData.ExpiresAt != nil {
		expiry = *authData.ExpiresAt
	}
	k.ecrCache.set(info.Host, auth, expiry)

	return auth, nil
}

// ecrTokenCache caches ECR authentication tokens.
type ecrTokenCache struct {
	mu     sync.RWMutex
	tokens map[string]*cachedECRToken
}

type cachedECRToken struct {
	auth   *authn.Basic
	expiry time.Time
}

func newECRTokenCache() *ecrTokenCache {
	return &ecrTokenCache{
		tokens: make(map[string]*cachedECRToken),
	}
}

func (c *ecrTokenCache) get(host string) *authn.Basic {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cached, ok := c.tokens[host]
	if !ok {
		return nil
	}

	// Check if token is expired (with 5-minute buffer)
	if time.Now().Add(5 * time.Minute).After(cached.expiry) {
		return nil
	}

	return cached.auth
}

func (c *ecrTokenCache) set(host string, auth *authn.Basic, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tokens[host] = &cachedECRToken{
		auth:   auth,
		expiry: expiry,
	}
}

// Global keychain instance with enhanced registry support.
var registryKeychain = NewRegistryKeychain()

// GetRegistryKeychain returns the enhanced registry keychain.
func GetRegistryKeychain() authn.Keychain {
	return registryKeychain
}

// wrapRegistryListErrorWithContext provides registry-specific error messages with actionable hints.
// This is an enhanced version that detects registry types and provides tailored guidance.
func wrapRegistryListErrorWithContext(err error, repoPath string) error {
	if err == nil {
		return nil
	}

	info := detectRegistry(repoPath)
	errStr := err.Error()

	// Detect error type
	isAuthError := strings.Contains(errStr, "UNAUTHORIZED") ||
		strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "DENIED") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "no basic auth credentials")

	isNotFound := strings.Contains(errStr, "NOT_FOUND") ||
		strings.Contains(errStr, "NAME_UNKNOWN") ||
		strings.Contains(errStr, "404") ||
		strings.Contains(errStr, "repository name not known")

	isRateLimit := strings.Contains(errStr, "TOOMANYREQUESTS") ||
		strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "rate limit")

	// Generate registry-specific error message
	switch info.Type {
	case RegistryTypeECR:
		return wrapECRError(err, repoPath, info, isAuthError, isNotFound, isRateLimit)
	case RegistryTypeGHCR:
		return wrapGHCRError(err, repoPath, isAuthError, isNotFound, isRateLimit)
	case RegistryTypeDockerHub:
		return wrapDockerHubError(err, repoPath, isAuthError, isNotFound, isRateLimit)
	case RegistryTypeGCR, RegistryTypeGAR:
		return wrapGoogleError(err, repoPath, info, isAuthError, isNotFound, isRateLimit)
	case RegistryTypeACR:
		return wrapACRError(err, repoPath, isAuthError, isNotFound, isRateLimit)
	default:
		return wrapGenericRegistryError(err, repoPath, isAuthError, isNotFound, isRateLimit)
	}
}

func wrapECRError(err error, repoPath string, info RegistryInfo, isAuth, isNotFound, isRateLimit bool) error {
	switch {
	case isAuth:
		return fmt.Errorf(`ECR authentication failed for %s

Ensure AWS credentials are configured:

  Option 1: Use environment variables
    export AWS_ACCESS_KEY_ID=<your-access-key>
    export AWS_SECRET_ACCESS_KEY=<your-secret-key>
    export AWS_REGION=%s

  Option 2: Use AWS CLI to configure credentials
    aws configure

  Option 3: Use docker credential helper
    Install: https://github.com/awslabs/amazon-ecr-credential-helper
    Then run: aws ecr get-login-password --region %s | \
      docker login --username AWS --password-stdin %s

Original error: %v`, repoPath, info.Region, info.Region, info.Host, err)

	case isNotFound:
		return fmt.Errorf(`ECR repository not found: %s

Verify:
  1. The repository exists in account %s, region %s
  2. Your AWS credentials have ecr:DescribeRepositories permission
  3. The repository name is spelled correctly

Create the repository:
  aws ecr create-repository --repository-name <name> --region %s

Original error: %v`, repoPath, info.AccountID, info.Region, info.Region, err)

	case isRateLimit:
		return fmt.Errorf(`ECR rate limit exceeded for %s

ECR has request throttling. Wait a moment and retry.
Consider using batch operations for bulk scanning.

Original error: %v`, repoPath, err)

	default:
		return fmt.Errorf("ECR error for %s: %w", repoPath, err)
	}
}

func wrapGHCRError(err error, repoPath string, isAuth, isNotFound, isRateLimit bool) error {
	switch {
	case isAuth:
		return fmt.Errorf(`GHCR authentication failed for %s

Ensure you have a valid GitHub token:

  Option 1: Set GITHUB_TOKEN environment variable
    export GITHUB_TOKEN=<your-personal-access-token>

  Option 2: Use docker login
    echo $GITHUB_TOKEN | docker login ghcr.io -u <username> --password-stdin

Token requirements:
  - Fine-grained PAT: read:packages permission
  - Classic PAT: read:packages scope

Create a token at: https://github.com/settings/tokens

Original error: %v`, repoPath, err)

	case isNotFound:
		return fmt.Errorf(`GHCR repository not found: %s

Verify:
  1. The repository/package exists at https://github.com/<owner>/packages
  2. You have permission to access the package (it may be private)
  3. The repository path is correct (format: ghcr.io/owner/image)

Original error: %v`, repoPath, err)

	case isRateLimit:
		return fmt.Errorf(`GHCR rate limit exceeded for %s

Authenticate with GITHUB_TOKEN to increase rate limits:
  export GITHUB_TOKEN=<your-token>

Original error: %v`, repoPath, err)

	default:
		return fmt.Errorf("GHCR error for %s: %w", repoPath, err)
	}
}

func wrapDockerHubError(err error, repoPath string, isAuth, isNotFound, isRateLimit bool) error {
	switch {
	case isAuth:
		return fmt.Errorf(`Docker Hub authentication failed for %s

Run docker login to authenticate:
  docker login

Or set credentials via environment:
  export DOCKER_USERNAME=<username>
  export DOCKER_PASSWORD=<password-or-token>

For automated access, create an access token at:
  https://hub.docker.com/settings/security

Original error: %v`, repoPath, err)

	case isNotFound:
		return fmt.Errorf(`Docker Hub repository not found: %s

Verify:
  1. The repository exists at https://hub.docker.com/r/<owner>/<repo>
  2. For private repos, ensure you're authenticated
  3. The repository path is correct

Original error: %v`, repoPath, err)

	case isRateLimit:
		return fmt.Errorf(`Docker Hub rate limit exceeded for %s

Unauthenticated users: 100 pulls per 6 hours
Authenticated users: 200 pulls per 6 hours
Paid plans: higher limits

Authenticate to increase limits:
  docker login

Or wait for the rate limit window to reset.

Original error: %v`, repoPath, err)

	default:
		return fmt.Errorf("Docker Hub error for %s: %w", repoPath, err)
	}
}

func wrapGoogleError(err error, repoPath string, info RegistryInfo, isAuth, isNotFound, isRateLimit bool) error {
	registryName := "GCR"
	if info.Type == RegistryTypeGAR {
		registryName = "Artifact Registry"
	}

	switch {
	case isAuth:
		return fmt.Errorf(`%s authentication failed for %s

Ensure Google Cloud credentials are configured:

  Option 1: Use gcloud to configure docker
    gcloud auth configure-docker %s

  Option 2: Use service account key
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json

  Option 3: Use docker login with service account
    cat key.json | docker login -u _json_key --password-stdin https://%s

Required IAM permissions:
  - roles/artifactregistry.reader (Artifact Registry)
  - roles/storage.objectViewer (GCR)

Original error: %v`, registryName, repoPath, info.Host, info.Host, err)

	case isNotFound:
		return fmt.Errorf(`%s repository not found: %s

Verify:
  1. The repository exists in project %s
  2. Your credentials have read access
  3. The repository path is correct

Original error: %v`, registryName, repoPath, info.Project, err)

	default:
		return fmt.Errorf("%s error for %s: %w", registryName, repoPath, err)
	}
}

func wrapACRError(err error, repoPath string, isAuth, isNotFound, isRateLimit bool) error {
	switch {
	case isAuth:
		return fmt.Errorf(`ACR authentication failed for %s

Ensure Azure credentials are configured:

  Option 1: Use Azure CLI
    az acr login --name <registry-name>

  Option 2: Use service principal
    docker login <registry>.azurecr.io -u <client-id> -p <client-secret>

  Option 3: Use managed identity (in Azure)
    Ensure the VM/container has AcrPull role

Original error: %v`, repoPath, err)

	case isNotFound:
		return fmt.Errorf(`ACR repository not found: %s

Verify:
  1. The repository exists in your ACR instance
  2. Your credentials have Reader or AcrPull role
  3. The repository path is correct

Original error: %v`, repoPath, err)

	default:
		return fmt.Errorf("ACR error for %s: %w", repoPath, err)
	}
}

func wrapGenericRegistryError(err error, repoPath string, isAuth, isNotFound, isRateLimit bool) error {
	switch {
	case isAuth:
		return fmt.Errorf(`authentication failed for %s

Run docker login to authenticate:
  docker login <registry-host>

Original error: %v`, repoPath, err)

	case isNotFound:
		return fmt.Errorf(`repository not found: %s

Verify:
  1. The repository exists
  2. You have permission to access it
  3. The repository path is correct

Original error: %v`, repoPath, err)

	case isRateLimit:
		return fmt.Errorf(`rate limit exceeded for %s

Authenticate to increase limits, or wait and retry.

Original error: %v`, repoPath, err)

	default:
		return fmt.Errorf("registry error for %s: %w", repoPath, err)
	}
}
