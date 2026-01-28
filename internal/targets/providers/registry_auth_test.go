package providers

import (
	"fmt"
	"testing"
)

func TestDetectRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		repoPath string
		wantType string
		wantHost string
	}{
		// AWS ECR
		{
			name:     "ECR private registry",
			repoPath: "123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo",
			wantType: RegistryTypeECR,
			wantHost: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		},
		{
			name:     "ECR with different region",
			repoPath: "111122223333.dkr.ecr.eu-west-1.amazonaws.com/app/backend",
			wantType: RegistryTypeECR,
			wantHost: "111122223333.dkr.ecr.eu-west-1.amazonaws.com",
		},
		{
			name:     "ECR public",
			repoPath: "public.ecr.aws/amazonlinux/amazonlinux",
			wantType: RegistryTypeECRPublic,
			wantHost: "public.ecr.aws",
		},

		// Docker Hub
		{
			name:     "Docker Hub official image (index.docker.io)",
			repoPath: "index.docker.io/library/nginx",
			wantType: RegistryTypeDockerHub,
			wantHost: "index.docker.io",
		},
		{
			name:     "Docker Hub user image (docker.io normalized to index.docker.io)",
			repoPath: "docker.io/myuser/myimage",
			wantType: RegistryTypeDockerHub,
			wantHost: "index.docker.io", // go-containerregistry normalizes docker.io to index.docker.io
		},

		// GHCR
		{
			name:     "GitHub Container Registry",
			repoPath: "ghcr.io/owner/repo",
			wantType: RegistryTypeGHCR,
			wantHost: "ghcr.io",
		},

		// GCR
		{
			name:     "Google Container Registry (gcr.io)",
			repoPath: "gcr.io/myproject/myimage",
			wantType: RegistryTypeGCR,
			wantHost: "gcr.io",
		},
		{
			name:     "GCR regional (us.gcr.io)",
			repoPath: "us.gcr.io/myproject/myimage",
			wantType: RegistryTypeGCR,
			wantHost: "us.gcr.io",
		},
		{
			name:     "GCR regional (eu.gcr.io)",
			repoPath: "eu.gcr.io/myproject/myimage",
			wantType: RegistryTypeGCR,
			wantHost: "eu.gcr.io",
		},

		// Google Artifact Registry
		{
			name:     "Artifact Registry",
			repoPath: "us-docker.pkg.dev/myproject/myrepo/myimage",
			wantType: RegistryTypeGAR,
			wantHost: "us-docker.pkg.dev",
		},
		{
			name:     "Artifact Registry (europe)",
			repoPath: "europe-docker.pkg.dev/myproject/myrepo/myimage",
			wantType: RegistryTypeGAR,
			wantHost: "europe-docker.pkg.dev",
		},

		// Azure Container Registry
		{
			name:     "Azure Container Registry",
			repoPath: "myregistry.azurecr.io/myimage",
			wantType: RegistryTypeACR,
			wantHost: "myregistry.azurecr.io",
		},

		// Quay.io
		{
			name:     "Quay.io",
			repoPath: "quay.io/coreos/etcd",
			wantType: RegistryTypeQuay,
			wantHost: "quay.io",
		},

		// GitLab
		{
			name:     "GitLab Registry",
			repoPath: "registry.gitlab.com/group/project",
			wantType: RegistryTypeGitLab,
			wantHost: "registry.gitlab.com",
		},

		// Self-hosted
		{
			name:     "Self-hosted registry",
			repoPath: "registry.example.com/myimage",
			wantType: RegistryTypeSelfHosted,
			wantHost: "registry.example.com",
		},
		{
			name:     "Harbor registry",
			repoPath: "harbor.mycompany.com/project/image",
			wantType: RegistryTypeSelfHosted,
			wantHost: "harbor.mycompany.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			info := detectRegistry(tt.repoPath)
			if info.Type != tt.wantType {
				t.Errorf("detectRegistry(%q).Type = %q, want %q", tt.repoPath, info.Type, tt.wantType)
			}
			if info.Host != tt.wantHost {
				t.Errorf("detectRegistry(%q).Host = %q, want %q", tt.repoPath, info.Host, tt.wantHost)
			}
		})
	}
}

func TestIsECRHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want bool
	}{
		{"valid ECR host", "123456789012.dkr.ecr.us-east-1.amazonaws.com", true},
		{"valid ECR host (different region)", "111122223333.dkr.ecr.eu-west-1.amazonaws.com", true},
		{"valid ECR host (gov cloud)", "123456789012.dkr.ecr.us-gov-west-1.amazonaws.com", true},
		{"ECR public (not private)", "public.ecr.aws", false},
		{"Docker Hub", "docker.io", false},
		{"GHCR", "ghcr.io", false},
		{"Invalid account ID (too short)", "12345678901.dkr.ecr.us-east-1.amazonaws.com", false},
		{"Invalid account ID (too long)", "1234567890123.dkr.ecr.us-east-1.amazonaws.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := isECRHost(tt.host)
			if got != tt.want {
				t.Errorf("isECRHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestParseECRHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		host          string
		wantAccountID string
		wantRegion    string
	}{
		{
			name:          "standard ECR host",
			host:          "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			wantAccountID: "123456789012",
			wantRegion:    "us-east-1",
		},
		{
			name:          "EU region",
			host:          "111122223333.dkr.ecr.eu-west-1.amazonaws.com",
			wantAccountID: "111122223333",
			wantRegion:    "eu-west-1",
		},
		{
			name:          "invalid host",
			host:          "ghcr.io",
			wantAccountID: "",
			wantRegion:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			accountID, region := parseECRHost(tt.host)
			if accountID != tt.wantAccountID {
				t.Errorf("parseECRHost(%q) accountID = %q, want %q", tt.host, accountID, tt.wantAccountID)
			}
			if region != tt.wantRegion {
				t.Errorf("parseECRHost(%q) region = %q, want %q", tt.host, region, tt.wantRegion)
			}
		})
	}
}

func TestExtractGCRProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		repoPath string
		want     string
	}{
		{"simple path", "gcr.io/myproject/myimage", "myproject"},
		{"nested path", "gcr.io/myproject/subdir/myimage", "myproject"},
		{"regional", "us.gcr.io/myproject/myimage", "myproject"},
		{"no project", "gcr.io", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := extractGCRProject(tt.repoPath)
			if got != tt.want {
				t.Errorf("extractGCRProject(%q) = %q, want %q", tt.repoPath, got, tt.want)
			}
		})
	}
}

func TestExtractGARProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		repoPath string
		want     string
	}{
		{"standard path", "us-docker.pkg.dev/myproject/myrepo/myimage", "myproject"},
		{"europe region", "europe-docker.pkg.dev/myproject/repo/image", "myproject"},
		{"no project", "us-docker.pkg.dev", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := extractGARProject(tt.repoPath)
			if got != tt.want {
				t.Errorf("extractGARProject(%q) = %q, want %q", tt.repoPath, got, tt.want)
			}
		})
	}
}

func TestRegistryKeychain_Creation(t *testing.T) {
	t.Parallel()

	// Test that keychain creation works
	kc := NewRegistryKeychain()
	if kc == nil {
		t.Fatal("NewRegistryKeychain() returned nil")
	}
	if kc.fallback == nil {
		t.Error("keychain fallback is nil")
	}
	if kc.ecrCache == nil {
		t.Error("keychain ecrCache is nil")
	}
}

func TestGetRegistryKeychain(t *testing.T) {
	t.Parallel()

	// Test that global keychain is available
	kc := GetRegistryKeychain()
	if kc == nil {
		t.Fatal("GetRegistryKeychain() returned nil")
	}
}

func TestECRTokenCache(t *testing.T) {
	t.Parallel()

	cache := newECRTokenCache()

	// Test cache miss
	if got := cache.get("test-host"); got != nil {
		t.Errorf("cache.get() on empty cache = %v, want nil", got)
	}

	// Test cache set and get
	// We can't easily test the actual caching without creating real auth tokens,
	// but we can verify the cache structure works
	if cache.tokens == nil {
		t.Error("cache.tokens is nil after creation")
	}
}

func TestRegistryKeychain_PrioritizesDockerConfig(t *testing.T) {
	t.Parallel()

	// This test documents the expected credential resolution order:
	// 1. Docker config (~/.docker/config.json) and credential helpers - FIRST
	// 2. Environment variables (GITHUB_TOKEN, AWS SDK) - FALLBACK
	// 3. Anonymous access - LAST RESORT
	//
	// This ensures users who have already run `docker login` or configured
	// credential helpers have their existing setup respected.

	kc := NewRegistryKeychain()

	// Verify the keychain has a fallback (docker config keychain)
	if kc.fallback == nil {
		t.Error("keychain should have fallback to docker config")
	}

	// The actual resolution behavior can't be easily unit tested without
	// mocking the docker config, but this test documents the expected behavior.
	// Integration tests or manual testing should verify:
	// - `docker login ghcr.io` credentials are used before GITHUB_TOKEN
	// - `docker-credential-ecr-login` results are used before AWS SDK calls
	// - Existing credentials are not overwritten or bypassed
}

func TestWrapRegistryListErrorWithContext_RegistryDetection(t *testing.T) {
	t.Parallel()

	// Test that error wrapping includes registry-specific hints
	tests := []struct {
		name         string
		repoPath     string
		wantContains string
	}{
		{
			name:         "ECR auth error hint",
			repoPath:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo",
			wantContains: "AWS credentials",
		},
		{
			name:         "GHCR auth error hint",
			repoPath:     "ghcr.io/owner/repo",
			wantContains: "GITHUB_TOKEN",
		},
		{
			name:         "Docker Hub auth error hint",
			repoPath:     "docker.io/myuser/myimage",
			wantContains: "docker login",
		},
		{
			name:         "GCR auth error hint",
			repoPath:     "gcr.io/myproject/myimage",
			wantContains: "gcloud",
		},
		{
			name:         "ACR auth error hint",
			repoPath:     "myregistry.azurecr.io/myimage",
			wantContains: "az acr login",
		},
	}

	// Simulate auth error
	authErr := fmt.Errorf("UNAUTHORIZED: authentication required")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := wrapRegistryListErrorWithContext(authErr, tt.repoPath)
			if err == nil {
				t.Fatal("wrapRegistryListErrorWithContext() returned nil for error")
			}
			errMsg := err.Error()
			if !contains(errMsg, tt.wantContains) {
				t.Errorf("error message %q does not contain %q", errMsg, tt.wantContains)
			}
		})
	}
}

func TestWrapRegistryListErrorWithContext_ErrorTypes(t *testing.T) {
	t.Parallel()

	repoPath := "ghcr.io/owner/repo"

	tests := []struct {
		name         string
		err          error
		wantContains string
	}{
		{
			name:         "401 error",
			err:          fmt.Errorf("UNAUTHORIZED: 401"),
			wantContains: "authentication",
		},
		{
			name:         "403 error",
			err:          fmt.Errorf("DENIED: 403"),
			wantContains: "authentication",
		},
		{
			name:         "404 error",
			err:          fmt.Errorf("NOT_FOUND: 404"),
			wantContains: "not found",
		},
		{
			name:         "429 rate limit",
			err:          fmt.Errorf("TOOMANYREQUESTS: 429"),
			wantContains: "rate limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := wrapRegistryListErrorWithContext(tt.err, repoPath)
			if err == nil {
				t.Fatal("wrapRegistryListErrorWithContext() returned nil")
			}
			errMsg := err.Error()
			if !contains(errMsg, tt.wantContains) {
				t.Errorf("error message %q does not contain %q", errMsg, tt.wantContains)
			}
		})
	}
}

func TestWrapRegistryListErrorWithContext_NilError(t *testing.T) {
	t.Parallel()

	err := wrapRegistryListErrorWithContext(nil, "any/repo")
	if err != nil {
		t.Errorf("wrapRegistryListErrorWithContext(nil) = %v, want nil", err)
	}
}

// Helper function for case-insensitive contains
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsIgnoreCase(s, substr)))
}

func containsIgnoreCase(s, substr string) bool {
	s = toLowerCase(s)
	substr = toLowerCase(substr)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLowerCase(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
