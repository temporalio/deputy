package purlx

import (
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestParseLoose_Table(t *testing.T) {
	tests := []struct {
		in          string
		wantType    string
		wantNS      string
		wantName    string
		wantVersion string
		wantSubpath string
	}{
		{
			in:          "pkg:githubactions/foo-org/actions-repo@1.1.1#.github/workflows/some.yml",
			wantType:    "githubactions",
			wantNS:      "foo-org",
			wantName:    "actions-repo",
			wantVersion: "1.1.1",
			wantSubpath: ".github/workflows/some.yml",
		},
		{
			in:          "pkg:github/owner/repo@v4",
			wantType:    "github",
			wantNS:      "owner",
			wantName:    "repo",
			wantVersion: "v4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseLoose(tc.in)
			if err != nil {
				t.Fatalf("ParseLoose(%q): %v", tc.in, err)
			}
			if got.Type != tc.wantType || got.Namespace != tc.wantNS || got.Name != tc.wantName || got.Version != tc.wantVersion || got.Subpath != tc.wantSubpath {
				t.Fatalf("ParseLoose(%q) = %+v, want type=%q ns=%q name=%q ver=%q subpath=%q", tc.in, got, tc.wantType, tc.wantNS, tc.wantName, tc.wantVersion, tc.wantSubpath)
			}
		})
	}
}

func TestGitHubActionsPURL_Table(t *testing.T) {
	tests := []struct {
		owner   string
		repo    string
		version string
		subpath string
		want    string
	}{
		{
			owner:   "actions",
			repo:    "checkout",
			version: "v4",
			want:    "pkg:githubactions/actions/checkout@v4",
		},
		{
			owner:   "foo-org",
			repo:    "actions-repo",
			version: "1.1.1",
			subpath: ".github/workflows/some-action.yml",
			want:    "pkg:githubactions/foo-org/actions-repo@1.1.1#.github/workflows/some-action.yml",
		},
	}
	for _, tc := range tests {
		label := tc.owner + "/" + tc.repo
		t.Run(label, func(t *testing.T) {
			got := GitHubActionsPURL(tc.owner, tc.repo, tc.version, tc.subpath)
			if got != tc.want {
				t.Fatalf("GitHubActionsPURL(%q,%q,%q,%q) = %q, want %q", tc.owner, tc.repo, tc.version, tc.subpath, got, tc.want)
			}
		})
	}
}

func TestGitHubActionsPURLFromPackage_UsesMetadataSubpath(t *testing.T) {
	p := &extractor.Package{
		Name:     "foo-org/actions-repo",
		Version:  "1.1.1",
		PURLType: TypeGitHubActions,
		Metadata: &struct {
			Raw     string
			Subpath string
		}{Raw: "foo-org/actions-repo/.github/workflows/some.yml@1.1.1", Subpath: ".github/workflows/some.yml"},
	}
	got := GitHubActionsPURLFromPackage(p)
	if !strings.Contains(got, "#.github/workflows/some.yml") {
		t.Fatalf("expected subpath in purl, got %q", got)
	}
}

func TestEquivalentIgnoringVersion_Table(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"pkg:githubactions/foo/bar@1.0.0", "pkg:githubactions/foo/bar@2.0.0", true},
		{"pkg:githubactions/foo/bar", "pkg:githubactions/foo/baz", false},
		{"pkg:npm/left-pad@1.0.0", "pkg:npm/left-pad@1.0.1", true},
	}
	for _, tc := range tests {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			if got := EquivalentIgnoringVersion(tc.a, tc.b); got != tc.want {
				t.Fatalf("EquivalentIgnoringVersion(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestIsGitHubActionsType_Table(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"githubactions", true},
		{"github", true},
		{"npm", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := IsGitHubActionsType(tc.in); got != tc.want {
				t.Fatalf("IsGitHubActionsType(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
