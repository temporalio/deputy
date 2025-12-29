package gitutil

import (
	"strings"
	"testing"
)

func Test_ToHTTPSGitURL(t *testing.T) {
	cases := map[string]string{
		"":                           "",
		"github.com/foo/bar":         "https://github.com/foo/bar.git",
		"https://github.com/foo/bar": "https://github.com/foo/bar.git",
		"http://github.com/foo/bar":  "http://github.com/foo/bar.git",
	}
	for in, want := range cases {
		if got := ToHTTPSGitURL(in); got != want {
			t.Errorf("ToHTTPSGitURL(%q)=%q want %q", in, got, want)
		}
	}
}

func Test_ResolveReferenceName_DefaultBranch(t *testing.T) {
	ctx := t.Context()
	ref, err := ResolveReferenceName(ctx, "https://github.com/this/should-not-exist-12345.git", nil, "")
	if err != nil {
		t.Fatalf("ResolveReferenceName unexpected error: %v", err)
	}
	if ref.String() == "" {
		t.Fatalf("expected non-empty default branch ref")
	}
}

func Test_LooksLikeTag(t *testing.T) {
	if !looksLikeTag("v1.2.3") {
		t.Error("expected v1.2.3 to look like tag")
	}
	if looksLikeTag("feature-branch") {
		t.Error("feature-branch shouldn't look like a tag")
	}
}

func Test_DiscoverDefaultBranch_Fallback(t *testing.T) {
	ctx := t.Context()
	got := discoverDefaultBranch(ctx, "https://github.com/example/nonexistent-one-two-three.git", nil)
	if got != "refs/heads/main" {
		t.Fatalf("expected fallback refs/heads/main got %s", got)
	}
}

func Test_ResolveReferenceName_Variants(t *testing.T) {
	ctx := t.Context()
	remote := "https://github.com/example/nonexistent-one-two-three.git"
	cases := []struct{ in string }{
		{in: "HEAD"}, {in: ""}, {in: "main"}, {in: "master"}, {in: "v1.2.3"}, {in: "refs/heads/feature"}, {in: "refs/tags/v0.1.0"},
	}
	for _, c := range cases {
		ref, _ := ResolveReferenceName(ctx, remote, nil, c.in)
		if c.in == "refs/heads/feature" && !strings.HasPrefix(ref.String(), "refs/heads/") {
			t.Errorf("expected heads prefix for feature, got %s", ref)
		}
		if c.in == "refs/tags/v0.1.0" && !strings.HasPrefix(ref.String(), "refs/tags/") {
			t.Errorf("expected tags prefix for tag, got %s", ref)
		}
	}
}
