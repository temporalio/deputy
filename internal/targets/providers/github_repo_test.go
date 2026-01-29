package providers

import (
	"context"
	"testing"

	"github.com/picatz/deputy/internal/targets"
)

func TestGitHubRepoProvider_Detect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// Collection URIs (should match)
		{"github scheme owner/repo/", "github://kubernetes/kubectl/", true},
		{"github scheme owner/repo/branches/", "github://kubernetes/kubectl/branches/", true},
		{"github scheme owner/repo/tags/", "github://kubernetes/kubectl/tags/", true},
		{"github scheme owner/repo/refs/", "github://kubernetes/kubectl/refs/", true},
		{"github.com URL owner/repo/", "github.com/golang/go/", true},
		{"https github.com owner/repo/", "https://github.com/docker/cli/", true},
		{"https github.com owner/repo/branches/", "https://github.com/docker/cli/branches/", true},
		{"https github.com owner/repo/tags/", "https://github.com/docker/cli/tags/", true},

		// Non-collection URIs (should not match)
		{"github with ref - not collection", "github://kubernetes/kubectl@main", false},
		{"github without trailing slash", "github://kubernetes/kubectl", false},
		{"org only - handled by github_org", "github://kubernetes/", false},
		{"empty repo", "github://kubernetes//", false},
		{"gitlab scheme", "gitlab://owner/repo/", false},
		{"unknown suffix", "github://owner/repo/commits/", false},
	}

	provider := githubRepoProvider{}
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

func TestGitHubRepoProvider_IsCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{"valid repo collection", "github://owner/repo/", true},
		{"valid branches collection", "github://owner/repo/branches/", true},
		{"valid tags collection", "github://owner/repo/tags/", true},
		{"not a collection - has ref", "github://owner/repo@main", false},
		{"not a collection - no trailing slash", "github://owner/repo", false},
		{"org level - different provider", "github://owner/", false},
	}

	provider := githubRepoProvider{}
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

func TestParseGitHubRepoCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		wantOwner  string
		wantRepo   string
		wantFilter RefFilter
		wantScheme bool
	}{
		{
			name:       "github scheme owner/repo/",
			target:     "github://kubernetes/kubectl/",
			wantOwner:  "kubernetes",
			wantRepo:   "kubectl",
			wantFilter: RefFilterAll,
			wantScheme: true,
		},
		{
			name:       "github scheme owner/repo/branches/",
			target:     "github://golang/go/branches/",
			wantOwner:  "golang",
			wantRepo:   "go",
			wantFilter: RefFilterBranches,
			wantScheme: true,
		},
		{
			name:       "github scheme owner/repo/tags/",
			target:     "github://docker/cli/tags/",
			wantOwner:  "docker",
			wantRepo:   "cli",
			wantFilter: RefFilterTags,
			wantScheme: true,
		},
		{
			name:       "github.com URL owner/repo/",
			target:     "github.com/hashicorp/terraform/",
			wantOwner:  "hashicorp",
			wantRepo:   "terraform",
			wantFilter: RefFilterAll,
			wantScheme: true,
		},
		{
			name:       "https github.com URL owner/repo/tags/",
			target:     "https://github.com/rust-lang/rust/tags/",
			wantOwner:  "rust-lang",
			wantRepo:   "rust",
			wantFilter: RefFilterTags,
			wantScheme: true,
		},
		{
			name:       "branch singular alias",
			target:     "github://owner/repo/branch/",
			wantOwner:  "owner",
			wantRepo:   "repo",
			wantFilter: RefFilterBranches,
			wantScheme: true,
		},
		{
			name:       "tag singular alias",
			target:     "github://owner/repo/tag/",
			wantOwner:  "owner",
			wantRepo:   "repo",
			wantFilter: RefFilterTags,
			wantScheme: true,
		},
		{
			name:       "releases alias for tags",
			target:     "github://owner/repo/releases/",
			wantOwner:  "owner",
			wantRepo:   "repo",
			wantFilter: RefFilterTags,
			wantScheme: true,
		},
		{
			name:       "refs alias for all",
			target:     "github://owner/repo/refs/",
			wantOwner:  "owner",
			wantRepo:   "repo",
			wantFilter: RefFilterAll,
			wantScheme: true,
		},
		{
			name:       "no trailing slash - not collection",
			target:     "github://owner/repo",
			wantOwner:  "",
			wantRepo:   "",
			wantFilter: RefFilterAll,
			wantScheme: false,
		},
		{
			name:       "org only - not repo collection",
			target:     "github://owner/",
			wantOwner:  "",
			wantRepo:   "",
			wantFilter: RefFilterAll,
			wantScheme: false,
		},
		{
			name:       "invalid suffix",
			target:     "github://owner/repo/commits/",
			wantOwner:  "",
			wantRepo:   "",
			wantFilter: RefFilterAll,
			wantScheme: false,
		},
		{
			name:       "invalid scheme",
			target:     "gitlab://owner/repo/",
			wantOwner:  "",
			wantRepo:   "",
			wantFilter: RefFilterAll,
			wantScheme: false,
		},
		{
			name:       "empty",
			target:     "",
			wantOwner:  "",
			wantRepo:   "",
			wantFilter: RefFilterAll,
			wantScheme: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			owner, repo, filter, hasScheme := parseGitHubRepoCollection(tt.target)
			if owner != tt.wantOwner {
				t.Errorf("parseGitHubRepoCollection(%q) owner = %q, want %q", tt.target, owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("parseGitHubRepoCollection(%q) repo = %q, want %q", tt.target, repo, tt.wantRepo)
			}
			if filter != tt.wantFilter {
				t.Errorf("parseGitHubRepoCollection(%q) filter = %v, want %v", tt.target, filter, tt.wantFilter)
			}
			if hasScheme != tt.wantScheme {
				t.Errorf("parseGitHubRepoCollection(%q) hasScheme = %v, want %v", tt.target, hasScheme, tt.wantScheme)
			}
		})
	}
}

func TestGitHubRepoProvider_Priority(t *testing.T) {
	t.Parallel()

	repoProvider := githubRepoProvider{}
	orgProvider := githubOrgProvider{}

	repoPriority := repoProvider.Priority()
	orgPriority := orgProvider.Priority()

	// Repo provider should have higher priority than org provider
	// because it's a more specific match
	if repoPriority <= orgPriority {
		t.Errorf("Repo Priority() = %d should be > Org Priority() = %d", repoPriority, orgPriority)
	}

	// Should be lower than specific target provider (80)
	if repoPriority >= 80 {
		t.Errorf("Priority() = %d, should be < 80", repoPriority)
	}
}

func TestGitHubRepoProvider_Open_ReturnsError(t *testing.T) {
	t.Parallel()

	provider := githubRepoProvider{}
	ctx := context.Background()

	_, err := provider.Open(ctx, "github://owner/repo/", nil)
	if err == nil {
		t.Error("Open() should return error for collection URI")
	}
}

func TestGitHubRepoProvider_Implements_Interfaces(t *testing.T) {
	t.Parallel()

	var _ targets.Provider = (*githubRepoProvider)(nil)
	var _ targets.PriorityProvider = (*githubRepoProvider)(nil)
	var _ targets.CollectionProvider = (*githubRepoProvider)(nil)
}
