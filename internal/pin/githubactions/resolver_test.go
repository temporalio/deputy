package githubactions

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
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

// TestResolveSHA_FaithfulNoDowngrade locks in the no-silent-downgrade
// guarantee. A floating major tag (v7) points at the LATEST release commit,
// while an older patch tag (v7.1.6) points at a different, older commit.
// Resolving @v7 must return the commit v7 currently points to — never the
// older release. (Modeled on the real astral-sh/setup-uv layout, where a
// substitution bug would pin v7.1.6 instead of the live v7.6.0.)
func TestResolveSHA_FaithfulNoDowngrade(t *testing.T) {
	const (
		latestCommit = "37802adc94f370d6bfd71619e3f0bf239e1f3b78" // what v7 → v7.6.0 points to now
		oldCommit    = "681c641aba71e4a1c380be3ab5e12ad51f415867" // older v7.1.6 release
	)
	fakeRefs := []refEntry{
		{name: "refs/tags/v7", sha: latestCommit},      // floating major → latest
		{name: "refs/tags/v7.6.0", sha: latestCommit},  // precise tag on same commit
		{name: "refs/tags/v7.1.6", sha: oldCommit},     // older release, different commit
		{name: "refs/heads/main", sha: latestCommit},
	}

	r := &Resolver{refCache: make(map[string][]refEntry)}
	r.listRefsFunc = func(ctx context.Context, remoteURL string) ([]refEntry, error) {
		return fakeRefs, nil
	}

	// @v7 must resolve to the commit v7 points to now, not the older v7.1.6.
	sha, err := r.ResolveSHA(t.Context(), "astral-sh", "setup-uv", "v7")
	if err != nil {
		t.Fatal(err)
	}
	if sha != latestCommit {
		t.Fatalf("resolving @v7 = %s, want current target %s (must NOT downgrade to %s)",
			sha, latestCommit, oldCommit)
	}

	// And the annotation should be the precise tag on that exact commit (v7.6.0),
	// never the older release tag.
	tag, err := r.ResolveTag(t.Context(), "astral-sh", "setup-uv", sha)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v7.6.0" {
		t.Errorf("tag annotation = %q, want v7.6.0", tag)
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

func TestMergeRefs_PrefersPeeledCommitOverTagObject(t *testing.T) {
	// Regression for the annotated-tag pinning bug: when a tag is annotated,
	// ls-remote (with AppendPeeled) advertises both the tag object ref and a
	// peeled "^{}" ref. We must pin the peeled COMMIT, never the tag object.
	const (
		tagObjectSHA = "42dc69e1aa15d09112580998cf2ef0119e2e91ae" // annotated tag object
		commitSHA    = "e18b497796c12c097a38f9edb9d0641fb99eee32" // underlying commit
		lwTagSHA     = "de0fac2e4500dabe0009e67214ff5f5447ce83dd" // lightweight tag → commit
		branchSHA    = "cccccccccccccccccccccccccccccccccccccccc"
	)

	raw := []*plumbing.Reference{
		// Annotated tag: object ref + peeled ref.
		plumbing.NewReferenceFromStrings("refs/tags/v2", tagObjectSHA),
		plumbing.NewReferenceFromStrings("refs/tags/v2^{}", commitSHA),
		// Lightweight tag: no peeled ref.
		plumbing.NewReferenceFromStrings("refs/tags/v6", lwTagSHA),
		// Branch.
		plumbing.NewReferenceFromStrings("refs/heads/main", branchSHA),
		// HEAD should be ignored.
		plumbing.NewReferenceFromStrings("HEAD", branchSHA),
	}

	got := map[string]string{}
	for _, e := range mergeRefs(raw) {
		got[e.name] = e.sha
	}

	if got["refs/tags/v2"] != commitSHA {
		t.Errorf("annotated tag v2: got %s, want peeled commit %s (not tag object %s)",
			got["refs/tags/v2"], commitSHA, tagObjectSHA)
	}
	if got["refs/tags/v6"] != lwTagSHA {
		t.Errorf("lightweight tag v6: got %s, want %s", got["refs/tags/v6"], lwTagSHA)
	}
	if got["refs/heads/main"] != branchSHA {
		t.Errorf("branch main: got %s, want %s", got["refs/heads/main"], branchSHA)
	}
	if _, ok := got["HEAD"]; ok {
		t.Error("HEAD should be excluded from merged refs")
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
