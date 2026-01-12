package targets_test

import (
	"testing"

	"github.com/picatz/deputy/internal/targets"
)

func TestLooksLikeContainerRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// Docker Hub library images with tag
		{"docker hub library image with tag", "alpine:3.19", true},
		{"docker hub library image with tag", "nginx:1.25", true},
		{"docker hub library image with latest", "alpine:latest", true},

		// Docker Hub user/org images with tag (owner/repo:tag pattern)
		{"docker hub user image with semver", "temporalio/server:1.28.1", true},
		{"docker hub user image with v-prefix", "hashicorp/consul:v1.18.0", true},
		{"docker hub user image with latest", "bitnami/redis:latest", true},
		{"docker hub user image with version dot", "library/nginx:1.25.3", true},
		{"docker hub user image with sha prefix", "myorg/app:sha-abc123", true},
		{"docker hub user image with stable", "myorg/app:stable", true},
		{"docker hub user image with edge", "myorg/app:edge", true},
		{"docker hub user image with dev", "myorg/app:dev", true},
		{"docker hub user image with main", "myorg/app:main", true},
		{"docker hub user image with master", "myorg/app:master", true},

		// NOT container refs - ambiguous owner/repo:ref patterns
		{"owner/repo no tag", "owner/repo", false},                       // no tag - could be git repo
		{"owner/repo with feature branch", "owner/repo:feature-xyz", false}, // doesn't look like version

		// Well-known registries
		{"ghcr.io image", "ghcr.io/owner/repo:v1.0.0", true},
		{"gcr.io image", "gcr.io/project/image:tag", true},
		{"quay.io image", "quay.io/repo/image:tag", true},
		{"docker.io image", "docker.io/library/nginx:1.25", true},
		{"gitlab registry", "registry.gitlab.com/group/project:tag", true},
		{"mcr image", "mcr.microsoft.com/dotnet/sdk:6.0", true},
		{"ecr public image", "public.ecr.aws/amazoncorretto/amazoncorretto:11", true},

		// AWS ECR pattern
		{"aws ecr", "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag", true},

		// Azure ACR pattern
		{"azure acr", "myregistry.azurecr.io/app:v1", true},

		// Google Artifact Registry
		{"google artifact registry", "us-docker.pkg.dev/project/repo/image:tag", true},

		// Localhost registry (development)
		{"localhost with port", "localhost:5000/myapp:latest", true},
		{"localhost without port", "localhost/myapp:latest", true},

		// NOT container refs
		{"local path with dot", "./local/path", false},
		{"local path relative", "../other/path", false},
		{"absolute path", "/absolute/path", false},
		{"home directory path", "~/some/path", false},
		{"current directory", ".", false},

		// Git-like patterns that should NOT match as containers
		{"github.com repo (no tag)", "github.com/owner/repo", false},
		{"git branch ref pattern", "repo:refs/heads/main", false},
		{"git range pattern", "main..HEAD", false},

		// Empty and edge cases
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := targets.LooksLikeContainerRef(tt.target)
			if got != tt.want {
				t.Errorf("LooksLikeContainerRef(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestValidateRemoteTarget_SSRFProtection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		wantErr bool
		errMsg  string
	}{
		// Valid remote targets
		{
			name:    "valid github repo",
			target:  "github.com/owner/repo",
			wantErr: false,
		},
		{
			name:    "valid container image",
			target:  "nginx:1.25",
			wantErr: false,
		},
		{
			name:    "valid GHCR image",
			target:  "ghcr.io/owner/app:v1.0.0",
			wantErr: false,
		},
		{
			name:    "valid with oci scheme",
			target:  "oci://gcr.io/project/image:tag",
			wantErr: false,
		},

		// Loopback bypass attempts
		{
			name:    "plain localhost",
			target:  "localhost:5000/image",
			wantErr: true,
			errMsg:  "localhost",
		},
		{
			name:    "127.0.0.1 direct",
			target:  "127.0.0.1:5000/image",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "127.0.0.1 with oci scheme",
			target:  "oci://127.0.0.1/malicious",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "IPv6 loopback ::1",
			target:  "oci://[::1]/malicious",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "0.0.0.0 unspecified",
			target:  "0.0.0.0:5000/image",
			wantErr: true,
			errMsg:  "loopback",
		},

		// Metadata endpoint bypass attempts
		{
			name:    "AWS metadata IP",
			target:  "169.254.169.254/latest/meta-data",
			wantErr: true,
			errMsg:  "metadata",
		},
		{
			name:    "AWS metadata with scheme",
			target:  "http://169.254.169.254/latest/meta-data",
			wantErr: true,
			errMsg:  "metadata",
		},
		{
			name:    "GCP metadata hostname",
			target:  "metadata.google.internal/computeMetadata",
			wantErr: true,
			errMsg:  "metadata",
		},
		{
			name:    "Azure metadata",
			target:  "metadata.azure.com/metadata/instance",
			wantErr: true,
			errMsg:  "metadata",
		},

		// Private network bypass attempts
		{
			name:    "10.x.x.x private",
			target:  "10.0.0.1:5000/internal",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "10.x.x.x with scheme",
			target:  "oci://10.255.255.255/internal",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "172.16.x.x private",
			target:  "172.16.0.1:5000/internal",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "172.31.x.x private (edge of range)",
			target:  "oci://172.31.255.255/internal",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "172.32.x.x is NOT private",
			target:  "172.32.0.1:5000/public",
			wantErr: false, // 172.32+ is not private
		},
		{
			name:    "192.168.x.x private",
			target:  "192.168.1.1:5000/internal",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "192.168.x.x with scheme",
			target:  "oci://192.168.0.1/internal",
			wantErr: true,
			errMsg:  "private",
		},

		// Local filesystem (already covered but verify)
		{
			name:    "absolute path",
			target:  "/etc/passwd",
			wantErr: true,
			errMsg:  "absolute",
		},
		{
			name:    "relative path",
			target:  "./local/file",
			wantErr: true,
			errMsg:  "relative",
		},
		{
			name:    "docker daemon",
			target:  "docker-daemon://myimage:latest",
			wantErr: true,
			errMsg:  "docker-daemon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := targets.ValidateRemoteTarget(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateRemoteTarget(%q) = nil, want error containing %q", tt.target, tt.errMsg)
				} else if tt.errMsg != "" && !containsIgnoreCase(err.Error(), tt.errMsg) {
					t.Errorf("ValidateRemoteTarget(%q) error = %q, want error containing %q", tt.target, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateRemoteTarget(%q) = %v, want nil", tt.target, err)
				}
			}
		})
	}
}

func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			subc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 'a' - 'A'
			}
			if subc >= 'A' && subc <= 'Z' {
				subc += 'a' - 'A'
			}
			if sc != subc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestDetectKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   targets.Kind
	}{
		// PURL detection
		{"purl go", "pkg:golang/github.com/example/pkg@v1.0.0", targets.KindPURL},
		{"purl npm", "pkg:npm/lodash@4.17.21", targets.KindPURL},

		// Container image URI schemes
		{"docker scheme", "docker://alpine:3.19", targets.KindContainerImage},
		{"oci scheme", "oci://ghcr.io/owner/repo:v1", targets.KindContainerImage},
		{"docker-daemon scheme", "docker-daemon://myapp:latest", targets.KindContainerImage},
		{"tarball scheme", "tarball:///path/to/image.tar", targets.KindContainerImage},
		{"oci-archive scheme", "oci-archive:///tmp/image.tar", targets.KindContainerImage},
		{"oci-layout scheme", "oci-layout:///tmp/layout", targets.KindContainerImage},

		// Bare container refs (detected via LooksLikeContainerRef)
		{"bare docker hub image", "alpine:3.19", targets.KindContainerImage},
		{"bare registry image", "ghcr.io/owner/repo:v1.0.0", targets.KindContainerImage},
		{"bare ecr image", "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag", targets.KindContainerImage},
		{"bare docker hub user image", "temporalio/server:1.28.1", targets.KindContainerImage},
		{"bare docker hub user image v-prefix", "hashicorp/consul:v1.18.0", targets.KindContainerImage},

		// SBOM detection
		{"stdin sbom", "-", targets.KindSBOM},
		{"json sbom", "sbom.json", targets.KindSBOM},
		{"spdx sbom", "sbom.spdx", targets.KindSBOM},
		{"cdx sbom", "sbom.cdx", targets.KindSBOM},
		{"sbom extension", "report.sbom", targets.KindSBOM},

		// Dockerfile detection
		{"Dockerfile", "Dockerfile", targets.KindDockerfile},
		{"Dockerfile.prod", "Dockerfile.prod", targets.KindDockerfile},
		{"app.dockerfile", "app.dockerfile", targets.KindDockerfile},

		// Unspecified (caller decides)
		{"plain directory path", "./src", targets.KindUnspecified},
		{"github repo url", "github.com/owner/repo", targets.KindUnspecified},
		{"random file", "main.go", targets.KindUnspecified},
		{"empty string", "", targets.KindUnspecified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := targets.DetectKind(tt.target)
			if got != tt.want {
				t.Errorf("DetectKind(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
