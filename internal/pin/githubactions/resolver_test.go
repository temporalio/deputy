package githubactions

import (
	"context"
	"fmt"
	"strings"
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

func TestResolveSHA(t *testing.T) {
	fakeRefs := []refEntry{
		{name: "refs/tags/v4", sha: "aaaa" + "aaaa" + "aaaa" + "aaaa" + "aaaa" + "aaaa" + "aaaa" + "aaaa" + "aaaa" + "aaaa"},
		{name: "refs/tags/v4.2.2", sha: "bbbb" + "bbbb" + "bbbb" + "bbbb" + "bbbb" + "bbbb" + "bbbb" + "bbbb" + "bbbb" + "bbbb"},
		{name: "refs/heads/main", sha: "cccc" + "cccc" + "cccc" + "cccc" + "cccc" + "cccc" + "cccc" + "cccc" + "cccc" + "cccc"},
	}

	r := &Resolver{refCache: make(map[string][]refEntry)}
	r.listRefsFunc = func(ctx context.Context, remoteURL string) ([]refEntry, error) {
		return fakeRefs, nil
	}

	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"tag", "v4", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"specific tag", "v4.2.2", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", false},
		{"branch", "main", "cccccccccccccccccccccccccccccccccccccccc", false},
		{"passthrough SHA", "dddddddddddddddddddddddddddddddddddddddd", "dddddddddddddddddddddddddddddddddddddddd", false},
		{"missing ref", "nonexistent", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Clear cache between tests
			r.refCacheMu.Lock()
			r.refCache = make(map[string][]refEntry)
			r.refCacheMu.Unlock()

			got, err := r.ResolveSHA(t.Context(), "owner", "repo", tc.ref)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveSHA_NetworkError(t *testing.T) {
	r := &Resolver{refCache: make(map[string][]refEntry)}
	r.listRefsFunc = func(ctx context.Context, remoteURL string) ([]refEntry, error) {
		return nil, fmt.Errorf("network timeout")
	}

	_, err := r.ResolveSHA(t.Context(), "owner", "repo", "main")
	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "network timeout") {
		t.Errorf("expected network timeout in error, got: %v", err)
	}
}

func TestResolveTag(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	fakeRefs := []refEntry{
		{name: "refs/tags/v4", sha: sha},
		{name: "refs/tags/v4.2", sha: sha},
		{name: "refs/tags/v4.2.2", sha: sha},
		{name: "refs/tags/v5.0.0", sha: otherSHA},
		{name: "refs/heads/main", sha: sha},
	}

	r := &Resolver{refCache: make(map[string][]refEntry)}
	r.listRefsFunc = func(ctx context.Context, remoteURL string) ([]refEntry, error) {
		return fakeRefs, nil
	}

	// Should return the most specific semver tag
	tag, err := r.ResolveTag(t.Context(), "owner", "repo", sha)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v4.2.2" {
		t.Errorf("got %q, want v4.2.2", tag)
	}
}

func TestResolveTag_NotFound(t *testing.T) {
	r := &Resolver{refCache: make(map[string][]refEntry)}
	r.listRefsFunc = func(ctx context.Context, remoteURL string) ([]refEntry, error) {
		return []refEntry{
			{name: "refs/heads/main", sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}, nil
	}

	_, err := r.ResolveTag(t.Context(), "owner", "repo", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err == nil {
		t.Fatal("expected error for SHA with no tags")
	}
}
