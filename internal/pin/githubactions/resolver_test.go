package githubactions

import (
	"testing"
)

func TestBestSemverTag(t *testing.T) {
	tests := []struct {
		candidates []string
		want       string
	}{
		{[]string{"v4", "v4.2", "v4.2.2"}, "v4.2.2"},
		{[]string{"v4.2.2", "v4.2", "v4"}, "v4.2.2"},
		{[]string{"v4"}, "v4"},
		{[]string{"main"}, "main"}, // non-semver fallback
		{nil, ""},
	}
	for _, tc := range tests {
		got := bestSemverTag(tc.candidates)
		if got != tc.want {
			t.Errorf("bestSemverTag(%v) = %q, want %q", tc.candidates, got, tc.want)
		}
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
		{"singlename", "", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		owner, repo := splitOwnerRepo(tc.name)
		if owner != tc.wantOwner || repo != tc.wantRepo {
			t.Errorf("splitOwnerRepo(%q) = (%q, %q), want (%q, %q)",
				tc.name, owner, repo, tc.wantOwner, tc.wantRepo)
		}
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
	}
	for _, tc := range tests {
		got := segmentCount(tc.v)
		if got != tc.want {
			t.Errorf("segmentCount(%q) = %d, want %d", tc.v, got, tc.want)
		}
	}
}

func TestGitRemoteURL(t *testing.T) {
	got := gitRemoteURL("actions", "checkout")
	want := "https://github.com/actions/checkout.git"
	if got != want {
		t.Errorf("gitRemoteURL = %q, want %q", got, want)
	}
}
