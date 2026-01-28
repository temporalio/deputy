package providers

import (
	"context"
	"testing"

	"github.com/picatz/deputy/internal/targets"
)

func TestContainerRegistryProvider_Detect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// Repository collection URIs (should match - trailing slash indicates "list tags")
		{"docker scheme with trailing slash", "docker://gcr.io/myproject/", true},
		{"oci scheme with trailing slash", "oci://ghcr.io/owner/", true},
		{"container scheme with trailing slash", "container://registry.example.com/namespace/", true},

		// Specific image references (should NOT match - these have tag or digest)
		{"docker with tag - specific reference", "docker://nginx:latest", false},
		{"docker with digest - specific reference", "docker://nginx@sha256:abc123", false},
		{"docker without trailing slash - specific image", "docker://gcr.io/myproject/image", false},
		{"no scheme", "gcr.io/myproject/", false},
		{"http scheme", "https://gcr.io/myproject/", false},
		{"empty after scheme", "docker:///", false},
	}

	provider := containerRegistryProvider{}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := provider.Detect(ctx, tt.target)
			if got != tt.want {
				t.Errorf("Detect(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestContainerRegistryProvider_IsCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"valid repository collection", "docker://gcr.io/myproject/", true},
		{"not a collection - has tag reference", "docker://nginx:latest", false},
		{"not a collection - specific image path", "docker://gcr.io/myproject/image", false},
	}

	provider := containerRegistryProvider{}
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := provider.IsCollection(ctx, tt.target)
			if got != tt.want {
				t.Errorf("IsCollection(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestParseRegistryCollectionTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		want    string // expected fully-qualified repository name
		wantErr bool
	}{
		{"gcr.io repository", "docker://gcr.io/myproject/", "gcr.io/myproject", false},
		{"ghcr.io repository", "docker://ghcr.io/owner/", "ghcr.io/owner", false},
		// Note: go-containerregistry normalizes "library" as a namespace for Docker Hub
		{"docker hub library namespace", "docker://index.docker.io/library/", "index.docker.io/library/library", false},
		{"custom registry repository", "oci://registry.example.com/namespace/", "registry.example.com/namespace", false},
		{"empty repository path", "docker:///", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseRegistryCollectionTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRegistryCollectionTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseRegistryCollectionTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestContainerRegistryProvider_Priority(t *testing.T) {
	t.Parallel()

	provider := containerRegistryProvider{}
	p := provider.Priority()

	// Should be lower than specific container image provider (75)
	// because specific image references (with tag/digest) should take precedence
	if p >= 75 {
		t.Errorf("Priority() = %d, should be < 75 (containerImageProvider)", p)
	}

	// Should be higher than directory provider (50)
	if p <= 50 {
		t.Errorf("Priority() = %d, should be > 50 (localDirProvider)", p)
	}
}

func TestContainerRegistryProvider_Open_ReturnsError(t *testing.T) {
	t.Parallel()

	provider := containerRegistryProvider{}
	ctx := context.Background()

	// Repository collections cannot be opened directly - must list tags first
	_, err := provider.Open(ctx, "docker://gcr.io/myproject/", nil)
	if err == nil {
		t.Error("Open() should return error for repository collection URI")
	}
}

func TestContainerRegistryProvider_Implements_Interfaces(t *testing.T) {
	t.Parallel()

	var _ targets.Provider = (*containerRegistryProvider)(nil)
	var _ targets.PriorityProvider = (*containerRegistryProvider)(nil)
	var _ targets.CollectionProvider = (*containerRegistryProvider)(nil)
}
