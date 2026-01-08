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
