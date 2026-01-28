package providers

import (
	"context"
	"testing"

	"github.com/picatz/deputy/internal/targets"
)

func TestGitHubOrgProvider_Detect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// Collection URIs (should match)
		{"github scheme with trailing slash", "github://myorg/", true},
		{"github.com URL with trailing slash", "github.com/myorg/", true},
		{"https github.com with trailing slash", "https://github.com/myorg/", true},

		// Non-collection URIs (should not match)
		{"github with repo - not collection", "github://myorg/myrepo", false},
		{"github without trailing slash", "github://myorg", false},
		{"github.com with repo", "github.com/myorg/myrepo", false},
		{"https github with repo", "https://github.com/myorg/myrepo", false},
		{"no scheme and no trailing slash", "myorg", false},
		{"empty org", "github:///", false},
		{"gitlab scheme", "gitlab://myorg/", false},
	}

	provider := githubOrgProvider{}
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

func TestGitHubOrgProvider_IsCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"valid github collection", "github://myorg/", true},
		{"valid github.com collection", "github.com/myorg/", true},
		{"not a collection - has repo", "github://myorg/myrepo", false},
		{"not a collection - no trailing slash", "github://myorg", false},
	}

	provider := githubOrgProvider{}
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

func TestParseGitHubCollectionOwner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		wantOwner  string
		wantScheme bool
	}{
		{"github scheme with trailing slash", "github://kubernetes/", "kubernetes", true},
		{"github.com URL with trailing slash", "github.com/golang/", "golang", true},
		{"https github.com with trailing slash", "https://github.com/docker/", "docker", true},
		// Note: parseGitHubCollectionOwner extracts the owner regardless of trailing slash
		// The trailing slash check is in isGitHubOrgCollection
		{"no trailing slash - still parses owner", "github://myorg", "myorg", true},
		{"has repo", "github://myorg/myrepo/", "", false},
		{"invalid scheme", "gitlab://myorg/", "", false},
		{"empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			owner, hasScheme := parseGitHubCollectionOwner(tt.target)
			if owner != tt.wantOwner {
				t.Errorf("parseGitHubCollectionOwner(%q) owner = %q, want %q", tt.target, owner, tt.wantOwner)
			}
			if hasScheme != tt.wantScheme {
				t.Errorf("parseGitHubCollectionOwner(%q) hasScheme = %v, want %v", tt.target, hasScheme, tt.wantScheme)
			}
		})
	}
}

func TestGitHubOrgProvider_Priority(t *testing.T) {
	t.Parallel()

	provider := githubOrgProvider{}
	p := provider.Priority()

	// Should be lower than specific repo provider (if it exists, typically 80)
	if p >= 80 {
		t.Errorf("Priority() = %d, should be < 80", p)
	}

	// Should be higher than directory provider (50)
	if p <= 50 {
		t.Errorf("Priority() = %d, should be > 50 (localDirProvider)", p)
	}
}

func TestGitHubOrgProvider_Open_ReturnsError(t *testing.T) {
	t.Parallel()

	provider := githubOrgProvider{}
	ctx := context.Background()

	_, err := provider.Open(ctx, "github://myorg/", nil)
	if err == nil {
		t.Error("Open() should return error for collection URI")
	}
}

func TestGitHubOrgProvider_Implements_Interfaces(t *testing.T) {
	t.Parallel()

	var _ targets.Provider = (*githubOrgProvider)(nil)
	var _ targets.PriorityProvider = (*githubOrgProvider)(nil)
	var _ targets.CollectionProvider = (*githubOrgProvider)(nil)
}

func TestParseGitHubListOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    *targets.ListOptions
		want    GitHubListOptions
	}{
		{
			name: "nil options",
			opts: nil,
			want: GitHubListOptions{
				IncludeForks:    true,
				IncludeArchived: true,
				Type:            "all",
			},
		},
		{
			name: "empty context",
			opts: &targets.ListOptions{},
			want: GitHubListOptions{
				IncludeForks:    true,
				IncludeArchived: true,
				Type:            "all",
			},
		},
		{
			name: "custom settings",
			opts: &targets.ListOptions{
				Context: &targets.ProviderContext{
					Extra: map[string]string{
						"include_forks":    "false",
						"include_archived": "false",
						"type":             "public",
					},
				},
			},
			want: GitHubListOptions{
				IncludeForks:    false,
				IncludeArchived: false,
				Type:            "public",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseGitHubListOptions(tt.opts)
			if got.IncludeForks != tt.want.IncludeForks {
				t.Errorf("IncludeForks = %v, want %v", got.IncludeForks, tt.want.IncludeForks)
			}
			if got.IncludeArchived != tt.want.IncludeArchived {
				t.Errorf("IncludeArchived = %v, want %v", got.IncludeArchived, tt.want.IncludeArchived)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type = %q, want %q", got.Type, tt.want.Type)
			}
		})
	}
}
