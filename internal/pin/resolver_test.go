package pin

import (
	"testing"
)

func TestBestSemverTag(t *testing.T) {
	tests := []struct {
		name       string
		candidates []string
		want       string
	}{
		{
			name:       "most specific wins",
			candidates: []string{"v4", "v4.2", "v4.2.2"},
			want:       "v4.2.2",
		},
		{
			name:       "highest version among same specificity",
			candidates: []string{"v4.2.1", "v4.2.2", "v4.2.0"},
			want:       "v4.2.2",
		},
		{
			name:       "single candidate",
			candidates: []string{"v1.0.0"},
			want:       "v1.0.0",
		},
		{
			name:       "prerelease less specific",
			candidates: []string{"v4.2.2-rc1", "v4.2.2"},
			want:       "v4.2.2",
		},
		{
			name:       "major only",
			candidates: []string{"v4"},
			want:       "v4",
		},
		{
			name:       "non-semver fallback",
			candidates: []string{"latest"},
			want:       "latest",
		},
		{
			name:       "empty returns empty",
			candidates: nil,
			want:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bestSemverTag(tc.candidates)
			if got != tc.want {
				t.Errorf("bestSemverTag(%v) = %q, want %q", tc.candidates, got, tc.want)
			}
		})
	}
}

func TestSplitOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		wantOwner string
		wantRepo  string
	}{
		{"actions/checkout", "actions", "checkout"},
		{"github/codeql-action", "github", "codeql-action"},
		{"org/repo/subpath", "org", "repo"},
		{"single", "", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo := splitOwnerRepo(tc.name)
			if owner != tc.wantOwner || repo != tc.wantRepo {
				t.Errorf("splitOwnerRepo(%q) = (%q, %q), want (%q, %q)",
					tc.name, owner, repo, tc.wantOwner, tc.wantRepo)
			}
		})
	}
}

func TestSegmentCount(t *testing.T) {
	tests := []struct {
		v    string
		want int
	}{
		{"v4", 1},
		{"v4.2", 2},
		{"v4.2.2", 3},
		{"v4.2.2-rc1", 3},
		{"v4.2.2+build", 3},
	}

	for _, tc := range tests {
		t.Run(tc.v, func(t *testing.T) {
			got := segmentCount(tc.v)
			if got != tc.want {
				t.Errorf("segmentCount(%q) = %d, want %d", tc.v, got, tc.want)
			}
		})
	}
}

func TestGitRemoteURL(t *testing.T) {
	got := gitRemoteURL("actions", "checkout")
	want := "https://github.com/actions/checkout.git"
	if got != want {
		t.Errorf("gitRemoteURL = %q, want %q", got, want)
	}
}
