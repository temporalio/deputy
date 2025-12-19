package auth

import (
	"context"
	"os"
	"strings"
)

// EnvProvider reads credentials from environment variables.
// It follows common conventions for credential environment variables.
type EnvProvider struct {
	// Prefix is prepended to environment variable names.
	// Defaults to no prefix.
	Prefix string

	// getenv is used for testing; defaults to os.Getenv.
	getenv func(string) string
}

// Compile-time interface assertion.
var _ Provider = (*EnvProvider)(nil)

// NewEnvProvider creates a provider that reads from environment variables.
func NewEnvProvider() *EnvProvider {
	return &EnvProvider{getenv: os.Getenv}
}

// NewEnvProviderWithPrefix creates a provider with a custom prefix.
func NewEnvProviderWithPrefix(prefix string) *EnvProvider {
	return &EnvProvider{Prefix: prefix, getenv: os.Getenv}
}

// Name implements [Provider].
func (e *EnvProvider) Name() string {
	if e.Prefix != "" {
		return "env:" + e.Prefix
	}
	return "env"
}

// Lookup implements [Provider]. It checks environment variables based on
// the requested host and hint type.
func (e *EnvProvider) Lookup(ctx context.Context, scope Scope) (Credential, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	getenv := e.getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	host := normalizeHost(scope.Host)
	hint := scope.Hint

	// Try hint-specific lookups first
	switch hint {
	case "git", "api", "":
		return e.lookupGitOrAPI(getenv, host)
	case "llm":
		return e.lookupLLM(getenv, host)
	case "registry":
		return e.lookupRegistry(getenv, host)
	case "container":
		return e.lookupContainer(getenv, host)
	}

	// Fallback: try common patterns
	return e.lookupGeneric(getenv, host)
}

// lookupGitOrAPI handles GitHub, GitLab, Bitbucket, etc.
func (e *EnvProvider) lookupGitOrAPI(getenv func(string) string, host string) (Credential, error) {
	prefix := e.Prefix

	// GitHub
	if host == "github.com" || host == "api.github.com" {
		if token := strings.TrimSpace(getenv(prefix + "GITHUB_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: gitHubHosts,
				Source:       prefix + "GITHUB_TOKEN",
			}, nil
		}
		// Also check GH_TOKEN (GitHub CLI convention)
		if token := strings.TrimSpace(getenv(prefix + "GH_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: gitHubHosts,
				Source:       prefix + "GH_TOKEN",
			}, nil
		}
	}

	// GitLab
	if host == "gitlab.com" || strings.HasSuffix(host, ".gitlab.com") {
		if token := strings.TrimSpace(getenv(prefix + "GITLAB_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{"gitlab.com", "*.gitlab.com"},
				Source:       prefix + "GITLAB_TOKEN",
			}, nil
		}
		// Also check CI token for GitLab CI
		if token := strings.TrimSpace(getenv("CI_JOB_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{"gitlab.com", "*.gitlab.com"},
				Source:       "CI_JOB_TOKEN",
			}, nil
		}
	}

	// Bitbucket
	if host == "bitbucket.org" || strings.HasSuffix(host, ".bitbucket.org") {
		if token := strings.TrimSpace(getenv(prefix + "BITBUCKET_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{"bitbucket.org", "*.bitbucket.org"},
				Source:       prefix + "BITBUCKET_TOKEN",
			}, nil
		}
		// App password format: user:app_password
		user := strings.TrimSpace(getenv(prefix + "BITBUCKET_USERNAME"))
		pass := strings.TrimSpace(getenv(prefix + "BITBUCKET_APP_PASSWORD"))
		if user != "" && pass != "" {
			return &BasicCredential{
				Username:     user,
				Password:     pass,
				AllowedHosts: []string{"bitbucket.org", "*.bitbucket.org"},
				Source:       prefix + "BITBUCKET_USERNAME/BITBUCKET_APP_PASSWORD",
			}, nil
		}
	}

	// GitHub Enterprise / Self-hosted
	// Check for DEPUTY_AUTH_GITHUB_ENTERPRISE_* pattern
	ghEntHost := strings.TrimSpace(getenv(prefix + "DEPUTY_AUTH_GITHUB_ENTERPRISE_HOST"))
	if ghEntHost != "" && matchHost(host, ghEntHost) {
		if token := strings.TrimSpace(getenv(prefix + "DEPUTY_AUTH_GITHUB_ENTERPRISE_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{ghEntHost},
				Source:       prefix + "DEPUTY_AUTH_GITHUB_ENTERPRISE_TOKEN",
			}, nil
		}
	}

	// GitLab Self-hosted
	glHost := strings.TrimSpace(getenv(prefix + "DEPUTY_AUTH_GITLAB_HOST"))
	if glHost != "" && matchHost(host, glHost) {
		if token := strings.TrimSpace(getenv(prefix + "DEPUTY_AUTH_GITLAB_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{glHost},
				Source:       prefix + "DEPUTY_AUTH_GITLAB_TOKEN",
			}, nil
		}
	}

	return nil, nil
}

// lookupLLM handles LLM provider credentials.
func (e *EnvProvider) lookupLLM(getenv func(string) string, host string) (Credential, error) {
	prefix := e.Prefix

	// Anthropic
	if host == "api.anthropic.com" {
		if key := strings.TrimSpace(getenv(prefix + "ANTHROPIC_API_KEY")); key != "" {
			return &TokenCredential{
				Token:        key,
				AllowedHosts: []string{"api.anthropic.com"},
				Source:       prefix + "ANTHROPIC_API_KEY",
			}, nil
		}
	}

	// OpenAI
	if host == "api.openai.com" {
		if key := strings.TrimSpace(getenv(prefix + "OPENAI_API_KEY")); key != "" {
			return &TokenCredential{
				Token:        key,
				AllowedHosts: []string{"api.openai.com"},
				Source:       prefix + "OPENAI_API_KEY",
			}, nil
		}
	}

	// Azure OpenAI
	if strings.HasSuffix(host, ".openai.azure.com") {
		if key := strings.TrimSpace(getenv(prefix + "AZURE_OPENAI_API_KEY")); key != "" {
			return &TokenCredential{
				Token:        key,
				AllowedHosts: []string{"*.openai.azure.com"},
				Source:       prefix + "AZURE_OPENAI_API_KEY",
			}, nil
		}
	}

	return nil, nil
}

// lookupRegistry handles package registry credentials.
func (e *EnvProvider) lookupRegistry(getenv func(string) string, host string) (Credential, error) {
	prefix := e.Prefix

	// npm registry
	if host == "registry.npmjs.org" || host == "npm.pkg.github.com" {
		if token := strings.TrimSpace(getenv(prefix + "NPM_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{host},
				Source:       prefix + "NPM_TOKEN",
			}, nil
		}
	}

	// PyPI
	if host == "pypi.org" || host == "upload.pypi.org" {
		if token := strings.TrimSpace(getenv(prefix + "PYPI_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{"pypi.org", "upload.pypi.org"},
				Source:       prefix + "PYPI_TOKEN",
			}, nil
		}
	}

	// Go proxy (private)
	if host == "proxy.golang.org" || strings.Contains(host, "goproxy") {
		if token := strings.TrimSpace(getenv("GOPRIVATE_TOKEN")); token != "" {
			return &TokenCredential{
				Token:        token,
				AllowedHosts: []string{host},
				Source:       "GOPRIVATE_TOKEN",
			}, nil
		}
	}

	return nil, nil
}

// lookupContainer handles container registry credentials.
func (e *EnvProvider) lookupContainer(getenv func(string) string, host string) (Credential, error) {
	prefix := e.Prefix

	// Docker Hub
	if host == "index.docker.io" || host == "registry-1.docker.io" || host == "docker.io" {
		user := strings.TrimSpace(getenv(prefix + "DOCKER_USERNAME"))
		pass := strings.TrimSpace(getenv(prefix + "DOCKER_PASSWORD"))
		if user != "" && pass != "" {
			return &DockerCredential{
				Username:      user,
				Password:      pass,
				ServerAddress: "https://index.docker.io/v1/",
				Source:        prefix + "DOCKER_USERNAME/DOCKER_PASSWORD",
			}, nil
		}
	}

	// GitHub Container Registry
	if host == "ghcr.io" {
		if token := strings.TrimSpace(getenv(prefix + "GITHUB_TOKEN")); token != "" {
			return &DockerCredential{
				Username:      "oauth2",
				Password:      token,
				ServerAddress: "https://ghcr.io",
				Source:        prefix + "GITHUB_TOKEN",
			}, nil
		}
	}

	// Google Container Registry / Artifact Registry
	if host == "gcr.io" || strings.HasSuffix(host, ".gcr.io") || strings.HasSuffix(host, "-docker.pkg.dev") {
		if creds := strings.TrimSpace(getenv("GOOGLE_APPLICATION_CREDENTIALS")); creds != "" {
			// Service account JSON - return basic auth with _json_key
			if data, err := os.ReadFile(creds); err == nil {
				return &DockerCredential{
					Username:      "_json_key",
					Password:      string(data),
					ServerAddress: "https://" + host,
					Source:        "GOOGLE_APPLICATION_CREDENTIALS",
				}, nil
			}
		}
	}

	// AWS ECR
	if strings.Contains(host, ".dkr.ecr.") && strings.Contains(host, ".amazonaws.com") {
		// AWS ECR uses docker credential helper typically
		// Return nil to let docker config provider handle it
		return nil, nil
	}

	return nil, nil
}

// lookupGeneric tries generic patterns.
func (e *EnvProvider) lookupGeneric(getenv func(string) string, host string) (Credential, error) {
	// Try DEPUTY_AUTH_<HOST>_TOKEN pattern
	// Convert host to env var safe name: github.com -> GITHUB_COM
	envHost := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(host, ".", "_"), "-", "_"))
	if token := strings.TrimSpace(getenv("DEPUTY_AUTH_" + envHost + "_TOKEN")); token != "" {
		return &TokenCredential{
			Token:        token,
			AllowedHosts: []string{host},
			Source:       "DEPUTY_AUTH_" + envHost + "_TOKEN",
		}, nil
	}

	return nil, nil
}

// gitHubHosts are the hosts that GitHub tokens are valid for.
var gitHubHosts = []string{
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
	"gist.github.com",
	"objects.githubusercontent.com",
}

// GitHubHosts returns the list of hosts that GitHub tokens are valid for.
// This is useful for creating credentials that should only be sent to GitHub.
func GitHubHosts() []string {
	result := make([]string, len(gitHubHosts))
	copy(result, gitHubHosts)
	return result
}
