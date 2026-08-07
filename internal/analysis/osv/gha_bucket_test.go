package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/temporalio/deputy/internal/cache/disk"
	"golang.org/x/sync/singleflight"
)

func TestNormalizeSemverVersion_Table(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"1.2.3", "v1.2.3"},
		{"v1.2.3", "v1.2.3"},
		{"1.2.3-beta.1", "v1.2.3-beta.1"},
		{"not-a-version", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeSemverVersion(tc.in); got != tc.want {
				t.Fatalf("normalizeSemverVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeGitHubActionsInput_Table(t *testing.T) {
	tests := []struct {
		name string
		in   PkgInput
		want PkgInput
	}{
		{
			name: "strip github.com prefix",
			in:   PkgInput{QueryKey: QueryKey{Name: "github.com/owner/repo", Version: "1.0.0", Ecosystem: "github"}},
			want: PkgInput{QueryKey: QueryKey{Name: "owner/repo", Version: "1.0.0", Ecosystem: "GitHub Actions"}},
		},
		{
			name: "derive from purl",
			in:   PkgInput{QueryKey: QueryKey{PURL: "pkg:github/owner/repo@v2"}},
			want: PkgInput{QueryKey: QueryKey{Name: "owner/repo", Version: "v2", PURL: "pkg:github/owner/repo@v2", Ecosystem: "GitHub Actions"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeGitHubActionsInput(tc.in)
			if got.Name != tc.want.Name || got.Ecosystem != tc.want.Ecosystem || got.PURL != tc.want.PURL || got.Version != tc.want.Version {
				t.Fatalf("normalizeGitHubActionsInput(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestVersionAffectedByGHARanges_Table(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID: "GHSA-test",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.6"},
						},
					},
				},
			},
		},
	}
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.5", true},
		{"1.0.6", false},
		{"0.9.0", true},
		{"not-semver", false}, // unresolved refs are not assumed affected by semver ranges
		{"v1", false},         // unresolved moving tags are not interpreted as v1.0.0
		{"v1.2", false},       // unresolved moving minor tags are not interpreted as v1.2.0
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			pkg := PkgInput{QueryKey: QueryKey{Name: "owner/repo", Version: tc.version, Ecosystem: "GitHub Actions"}}
			if got := versionAffectedByGHARanges(vuln, pkg, tc.version); got != tc.want {
				t.Fatalf("versionAffectedByGHARanges(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestVersionAffectedByGHARanges_LastAffected(t *testing.T) {
	// Advisory bounded with last_affected rather than fixed: versions above the
	// bound must not be reported as affected via the open-ended fallback.
	vuln := osvschema.Vulnerability{
		ID: "GHSA-lastaffected",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{{
					Type:   osvschema.RangeEcosystem,
					Events: []osvschema.Event{{Introduced: "0"}, {LastAffected: "1.0.6"}},
				}},
			},
		},
	}
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.5", true},
		{"1.0.6", true},  // last_affected is inclusive
		{"1.0.7", false}, // above the bound: not affected
		{"2.0.0", false},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			pkg := PkgInput{QueryKey: QueryKey{Name: "owner/repo", Version: tc.version, Ecosystem: "GitHub Actions"}}
			if got := versionAffectedByGHARanges(vuln, pkg, tc.version); got != tc.want {
				t.Fatalf("versionAffectedByGHARanges(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestVersionAffectedByGHARanges_UnresolvedRefMatchesOnlyPackageLevelOrOpenEndedAdvisories(t *testing.T) {
	pkg := PkgInput{QueryKey: QueryKey{Name: "owner/repo", Version: "abcdef1", Ecosystem: "GitHub Actions"}}

	ranged := osvschema.Vulnerability{
		ID: "GHSA-ranged",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{{
					Type:   osvschema.RangeEcosystem,
					Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "1.0.74"}},
				}},
			},
		},
	}
	if versionAffectedByGHARanges(ranged, pkg, pkg.Version) {
		t.Fatal("unresolved SHA ref matched a semver range; want unknown rather than affected")
	}

	unranged := osvschema.Vulnerability{
		ID: "GHSA-unranged",
		Affected: []osvschema.Affected{
			{Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)}},
		},
	}
	if !versionAffectedByGHARanges(unranged, pkg, pkg.Version) {
		t.Fatal("unresolved SHA ref did not match unranged advisory; want package-level advisory to apply")
	}

	openEnded := osvschema.Vulnerability{
		ID: "GHSA-open-ended",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{{
					Type:   osvschema.RangeEcosystem,
					Events: []osvschema.Event{{Introduced: "0"}},
				}},
			},
		},
	}
	if !versionAffectedByGHARanges(openEnded, pkg, pkg.Version) {
		t.Fatal("unresolved SHA ref did not match open-ended advisory introduced at 0")
	}
}

func TestParseGHAFloatingRefPrefix_Table(t *testing.T) {
	tests := []struct {
		in         string
		wantPrefix string
		ok         bool
	}{
		{"v4", "v4.", true},
		{"4", "v4.", true},
		{" v4 ", "v4.", true},
		{"v04", "v4.", true},
		{"v4.2", "v4.2.", true},
		{"4.2", "v4.2.", true},
		{"v4.02", "v4.2.", true},
		{"v0", "", false},
		{"0", "", false},
		{"v4.2.0", "", false},
		{"4.2.0", "", false},
		{"", "", false},
		{"deadbeef", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseGHAFloatingRefPrefix(tc.in)
			if ok != tc.ok || got != tc.wantPrefix {
				t.Fatalf("parseGHAFloatingRefPrefix(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.wantPrefix, tc.ok)
			}
		})
	}
}

func TestResolveGitHubActionsVersion_Table(t *testing.T) {
	origList := ghaListRemoteRefs
	origListWithHashes := ghaListRemoteRefsWithHashes
	t.Cleanup(func() {
		ghaListRemoteRefs = origList
		ghaListRemoteRefsWithHashes = origListWithHashes
	})

	tests := []struct {
		name                 string
		repo                 string
		version              string
		refs                 []string
		refsWithHashes       []ghaRemoteRef
		want                 string
		wantListCalled       bool
		wantListHashesCalled bool
	}{
		{
			name:    "fully specified semver skips lookup",
			repo:    "owner/repo",
			version: "v4.2.0",
			refs:    []string{"refs/tags/v4.3.0"},
			want:    "",
		},
		{
			name:           "rolling major resolves to highest patch",
			repo:           "owner/repo",
			version:        "v4",
			refs:           []string{"refs/tags/v4", "refs/tags/v4.1.3", "refs/tags/v4.2.0", "refs/tags/v3.9.9"},
			want:           "v4.2.0",
			wantListCalled: true,
		},
		{
			name:           "annotated major tags are handled",
			repo:           "owner/repo",
			version:        "v4",
			refs:           []string{"refs/tags/v4.2.0^{}", "refs/tags/v4.1.3"},
			want:           "v4.2.0",
			wantListCalled: true,
		},
		{
			name:           "no matching tags yields empty",
			repo:           "owner/repo",
			version:        "v4",
			refs:           []string{"refs/tags/v5.0.0"},
			want:           "",
			wantListCalled: true,
		},
		{
			name:           "rolling minor resolves to highest patch",
			repo:           "owner/repo",
			version:        "v4.2",
			refs:           []string{"refs/tags/v4.2", "refs/tags/v4.2.1", "refs/tags/v4.2.3", "refs/tags/v4.3.0"},
			want:           "v4.2.3",
			wantListCalled: true,
		},
		{
			name:    "commit sha resolves to highest semver tag pointing at commit",
			repo:    "owner/repo",
			version: "fad22eb3fa582b7357fc0ea48af6645851b884fd",
			refsWithHashes: []ghaRemoteRef{
				{Name: "refs/tags/v1.0.74", Hash: "fad22eb3fa582b7357fc0ea48af6645851b884fd"},
				{Name: "refs/tags/v1.0.161", Hash: "fad22eb3fa582b7357fc0ea48af6645851b884fd"},
				{Name: "refs/tags/v1.0.200", Hash: "0123456789abcdef0123456789abcdef01234567"},
			},
			want:                 "v1.0.161",
			wantListHashesCalled: true,
		},
		{
			name:    "commit sha resolves through peeled annotated tag",
			repo:    "owner/repo",
			version: "fad22eb",
			refsWithHashes: []ghaRemoteRef{
				{Name: "refs/tags/v1.0.161", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{Name: "refs/tags/v1.0.161^{}", Hash: "fad22eb3fa582b7357fc0ea48af6645851b884fd"},
			},
			want:                 "v1.0.161",
			wantListHashesCalled: true,
		},
		{
			name:    "ambiguous short commit sha stays unresolved",
			repo:    "owner/repo",
			version: "fad22eb",
			refsWithHashes: []ghaRemoteRef{
				{Name: "refs/tags/v1.0.161", Hash: "fad22eb3fa582b7357fc0ea48af6645851b884fd"},
				{Name: "refs/tags/v1.0.200", Hash: "fad22ebaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			},
			want:                 "",
			wantListHashesCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listCalled := false
			listHashesCalled := false
			ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
				listCalled = true
				if remoteURL != "https://github.com/"+tc.repo+".git" {
					t.Fatalf("unexpected remoteURL %q", remoteURL)
				}
				return tc.refs, nil
			}
			ghaListRemoteRefsWithHashes = func(_ context.Context, remoteURL string) ([]ghaRemoteRef, error) {
				listHashesCalled = true
				if remoteURL != "https://github.com/"+tc.repo+".git" {
					t.Fatalf("unexpected remoteURL %q", remoteURL)
				}
				return tc.refsWithHashes, nil
			}
			got := resolveGitHubActionsVersion(t.Context(), &sync.Map{}, tc.repo, tc.version)
			if got != tc.want {
				t.Fatalf("resolveGitHubActionsVersion(%q,%q)=%q want %q", tc.repo, tc.version, got, tc.want)
			}
			if listCalled != tc.wantListCalled {
				t.Fatalf("listCalled=%v want %v", listCalled, tc.wantListCalled)
			}
			if listHashesCalled != tc.wantListHashesCalled {
				t.Fatalf("listHashesCalled=%v want %v", listHashesCalled, tc.wantListHashesCalled)
			}
		})
	}
}

func TestQueryOSVGHABucketBatch_MajorTagResolutionAvoidsFalsePositive(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-major-tag",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "actions/download-artifact", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "4.1.3"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-major-tag.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	origList := ghaListRemoteRefs
	ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
		if remoteURL != "https://github.com/actions/download-artifact.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []string{
			"refs/tags/v4",
			"refs/tags/v4.2.0",
			"refs/tags/v4.1.3",
		}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	got, err := queryOSVGHABucketBatch(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/download-artifact", Version: "v4", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no vulnerabilities for rolling v4 tag that resolves >= fixed, got %#v", got)
	}
}

func TestQueryOSVGHABucketBatch_UnresolvedFloatingTagDoesNotDefaultToAffected(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-floating-tag",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "actions/download-artifact", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "4.2.0"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-floating-tag.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	origList := ghaListRemoteRefs
	ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
		if remoteURL != "https://github.com/actions/download-artifact.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []string{"refs/tags/v5.0.0"}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	got, err := queryOSVGHABucketBatch(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/download-artifact", Version: "v4.1", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected unresolved floating ref to remain unknown, got vulnerabilities %#v", got)
	}
}

func TestQueryOSVGHABucketBatch_MajorTagResolutionReportsEffectiveVersion(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-major-tag-vuln",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "actions/download-artifact", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "4.2.0"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-major-tag-vuln.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	origList := ghaListRemoteRefs
	ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
		if remoteURL != "https://github.com/actions/download-artifact.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		// Highest v4.x.y is below fixed.
		return []string{"refs/tags/v4", "refs/tags/v4.1.3"}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	got, err := queryOSVGHABucketBatch(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/download-artifact", Version: "v4", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %#v", got)
	}
	if got[0].Version != "v4.1.3" {
		t.Fatalf("expected effective version v4.1.3, got %q", got[0].Version)
	}
}

func TestQueryOSVGHABucketBatch_SHAResolutionAvoidsFalsePositive(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID:      "GHSA-8q5r-mmjf-575q",
		Aliases: []string{"CVE-2026-47751"},
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "anthropics/claude-code-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.74"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-8q5r-mmjf-575q.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	sha := "fad22eb3fa582b7357fc0ea48af6645851b884fd"
	origListWithHashes := ghaListRemoteRefsWithHashes
	ghaListRemoteRefsWithHashes = func(_ context.Context, remoteURL string) ([]ghaRemoteRef, error) {
		if remoteURL != "https://github.com/anthropics/claude-code-action.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []ghaRemoteRef{
			{Name: "refs/tags/v1.0.161", Hash: sha},
			{Name: "refs/tags/v1.0.161^{}", Hash: sha},
		}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefsWithHashes = origListWithHashes })

	got, err := queryOSVGHABucketBatch(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "anthropics/claude-code-action", Version: sha, Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no vulnerabilities for SHA resolving to v1.0.161 >= v1.0.74, got %#v", got)
	}
}

func TestQueryRaw_GitHubActionsPURLOnlySHAResolutionAvoidsFalsePositive(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-8q5r-mmjf-575q",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "anthropics/claude-code-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.74"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-8q5r-mmjf-575q.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	sha := "fad22eb3fa582b7357fc0ea48af6645851b884fd"
	origListWithHashes := ghaListRemoteRefsWithHashes
	ghaListRemoteRefsWithHashes = func(_ context.Context, remoteURL string) ([]ghaRemoteRef, error) {
		if remoteURL != "https://github.com/anthropics/claude-code-action.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []ghaRemoteRef{{Name: "refs/tags/v1.0.161^{}", Hash: sha}}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefsWithHashes = origListWithHashes })

	got, err := QueryRaw(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{PURL: "pkg:githubactions/anthropics/claude-code-action@" + sha + "#sub/action.yml"}},
	})
	if err != nil {
		t.Fatalf("QueryRaw: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no vulnerabilities for PURL-only SHA resolving to patched tag, got %#v", got)
	}
}

func TestQueryOSVGHABucketBatch_SHAResolutionReportsEffectiveVersion(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-sha-vuln",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.74"},
						},
					},
				},
			},
		},
	}
	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-sha-vuln.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	sha := "1111111111111111111111111111111111111111"
	origListWithHashes := ghaListRemoteRefsWithHashes
	ghaListRemoteRefsWithHashes = func(_ context.Context, remoteURL string) ([]ghaRemoteRef, error) {
		if remoteURL != "https://github.com/owner/repo.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []ghaRemoteRef{{Name: "refs/tags/v1.0.73", Hash: sha}}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefsWithHashes = origListWithHashes })

	got, err := queryOSVGHABucketBatch(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "owner/repo", Version: sha, Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %#v", got)
	}
	if got[0].Version != "v1.0.73" {
		t.Fatalf("effective version = %q, want v1.0.73", got[0].Version)
	}
}

func TestQueryOSVGHABucketBatch_UnresolvedSHADoesNotDefaultToAffected(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-unresolved-sha",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.74"},
						},
					},
				},
			},
		},
	}
	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-unresolved-sha.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	origListWithHashes := ghaListRemoteRefsWithHashes
	ghaListRemoteRefsWithHashes = func(_ context.Context, remoteURL string) ([]ghaRemoteRef, error) {
		if remoteURL != "https://github.com/owner/repo.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []ghaRemoteRef{{Name: "refs/tags/v1.0.200", Hash: "2222222222222222222222222222222222222222"}}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefsWithHashes = origListWithHashes })

	got, err := queryOSVGHABucketBatch(t.Context(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "owner/repo", Version: "1111111111111111111111111111111111111111", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected unresolved SHA to remain unknown, got vulnerabilities %#v", got)
	}
}

func TestBuildGHAVulnIndex_UsesCacheZip(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	v1 := osvschema.Vulnerability{
		ID: "GHSA-one",
		Affected: []osvschema.Affected{
			{Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)}},
		},
	}
	v2 := osvschema.Vulnerability{
		ID: "GHSA-two",
		Affected: []osvschema.Affected{
			{Package: osvschema.Package{Name: "other/ecos", Ecosystem: "npm"}},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-one.json": v1,
		"GHSA-two.json": v2,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	// Ensure it looks fresh.
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	idx, err := buildGHAVulnIndex(t.Context())
	if err != nil {
		t.Fatalf("buildGHAVulnIndex: %v", err)
	}
	if idx == nil || len(idx.byPkg) != 1 {
		t.Fatalf("expected 1 indexed package, got %v", idx.byPkg)
	}
	if got := idx.byPkg["owner/repo"]; len(got) != 1 || got[0].ID != "GHSA-one" {
		t.Fatalf("owner/repo index = %#v", got)
	}

	// Confirm normalize+matching uses purl without github.com prefix.
	in := PkgInput{QueryKey: QueryKey{PURL: purl.PackageURL{Type: purl.TypeGithub, Namespace: "owner", Name: "repo", Version: "v1"}.String(), Version: "1.0.0"}}
	norm := normalizeGitHubActionsInput(in)
	if norm.Name != "owner/repo" || norm.Ecosystem != "GitHub Actions" {
		t.Fatalf("normalized input = %+v", norm)
	}
}

func TestEnsureGHACacheZip_UsesETagConditionalRequest(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	var (
		requests     int
		lastIfNone   string
		zipBodyBytes []byte
	)
	zipBodyBytes = mustGHATestZipBytes(t, map[string]osvschema.Vulnerability{
		"GHSA-one.json": {
			ID: "GHSA-one",
			Affected: []osvschema.Affected{
				{Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)}},
			},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		lastIfNone = r.Header.Get("If-None-Match")
		if lastIfNone == `W/"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `W/"abc"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zipBodyBytes)
	}))
	defer srv.Close()

	origURL := ghaAllZipURL
	origClient := ghaHTTPClient
	origTTL := ghaDownloadTTL
	ghaAllZipURL = srv.URL
	ghaHTTPClient = srv.Client()
	ghaDownloadTTL = 0
	t.Cleanup(func() {
		ghaAllZipURL = origURL
		ghaHTTPClient = origClient
		ghaDownloadTTL = origTTL
	})

	p1, err := ensureGHACacheZip(t.Context())
	if err != nil {
		t.Fatalf("ensureGHACacheZip (first): %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d want=1", requests)
	}
	if fi, err := os.Stat(p1); err != nil || fi.Size() == 0 {
		t.Fatalf("expected zip file to exist, err=%v size=%d", err, fi.Size())
	}

	// Second call should send If-None-Match and receive 304.
	p2, err := ensureGHACacheZip(t.Context())
	if err != nil {
		t.Fatalf("ensureGHACacheZip (second): %v", err)
	}
	if p2 != p1 {
		t.Fatalf("path changed: %q vs %q", p1, p2)
	}
	if requests != 2 {
		t.Fatalf("requests=%d want=2", requests)
	}
	if lastIfNone != `W/"abc"` {
		t.Fatalf("If-None-Match=%q want=%q", lastIfNone, `W/"abc"`)
	}
}

// TestEnsureGHACacheZipDownloadCapBoundary pins the safety-cap boundary: a
// body of exactly ghaDownloadLimit bytes is a complete download and must
// succeed; only a body that exceeds the cap is truncated and must fail.
func TestEnsureGHACacheZipDownloadCapBoundary(t *testing.T) {
	body := mustGHATestZipBytes(t, map[string]osvschema.Vulnerability{
		"GHSA-cap.json": {
			ID: "GHSA-cap",
			Affected: []osvschema.Affected{
				{Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)}},
			},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origURL := ghaAllZipURL
	origClient := ghaHTTPClient
	origTTL := ghaDownloadTTL
	origLimit := ghaDownloadLimit
	ghaAllZipURL = srv.URL
	ghaHTTPClient = srv.Client()
	ghaDownloadTTL = 0
	t.Cleanup(func() {
		ghaAllZipURL = origURL
		ghaHTTPClient = origClient
		ghaDownloadTTL = origTTL
		ghaDownloadLimit = origLimit
	})

	t.Run("exactly at cap succeeds", func(t *testing.T) {
		resetGHATestState()
		restore := disk.SetBaseDirForTest(t.TempDir())
		t.Cleanup(restore)
		ghaDownloadLimit = int64(len(body))
		if _, err := ensureGHACacheZip(t.Context()); err != nil {
			t.Fatalf("ensureGHACacheZip at exact cap: %v", err)
		}
	})

	t.Run("over cap fails loudly", func(t *testing.T) {
		resetGHATestState()
		restore := disk.SetBaseDirForTest(t.TempDir())
		t.Cleanup(restore)
		ghaDownloadLimit = int64(len(body)) - 1
		if _, err := ensureGHACacheZip(t.Context()); err == nil {
			t.Fatal("ensureGHACacheZip over cap: want safety-cap error, got nil")
		}
	})
}

func TestLoadGHAVulnIndex_RefreshesAfterTTL(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipV1 := mustGHATestZipBytes(t, map[string]osvschema.Vulnerability{
		"GHSA-one.json": {
			ID: "GHSA-one",
			Affected: []osvschema.Affected{
				{Package: osvschema.Package{Name: "owner/repo", Ecosystem: string(osvschema.EcosystemGitHubActions)}},
			},
		},
	})
	zipV2 := mustGHATestZipBytes(t, map[string]osvschema.Vulnerability{
		"GHSA-two.json": {
			ID: "GHSA-two",
			Affected: []osvschema.Affected{
				{Package: osvschema.Package{Name: "owner/repo2", Ecosystem: string(osvschema.EcosystemGitHubActions)}},
			},
		},
	})

	var body []byte
	var etag string
	body = zipV1
	etag = `W/"v1"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	origURL := ghaAllZipURL
	origClient := ghaHTTPClient
	origDownloadTTL := ghaDownloadTTL
	origIndexTTL := ghaIndexTTL
	t.Cleanup(func() {
		ghaAllZipURL = origURL
		ghaHTTPClient = origClient
		ghaDownloadTTL = origDownloadTTL
		ghaIndexTTL = origIndexTTL
		resetGHATestState()
	})

	ghaAllZipURL = srv.URL
	ghaHTTPClient = srv.Client()
	ghaDownloadTTL = 0

	ghaIndexTTL = time.Hour
	idx1, err := loadGHAVulnIndex(t.Context())
	if err != nil {
		t.Fatalf("loadGHAVulnIndex (v1): %v", err)
	}
	if idx1 == nil || len(idx1.byPkg["owner/repo"]) != 1 {
		t.Fatalf("expected owner/repo in v1 index, got %#v", idx1.byPkg)
	}

	// Change the upstream zip, but keep in-memory TTL long enough that the index should not rebuild.
	body = zipV2
	etag = `W/"v2"`

	idx2, err := loadGHAVulnIndex(t.Context())
	if err != nil {
		t.Fatalf("loadGHAVulnIndex (still cached): %v", err)
	}
	if idx2 != idx1 {
		t.Fatalf("expected cached index reuse")
	}
	if _, ok := idx2.byPkg["owner/repo2"]; ok {
		t.Fatalf("unexpected refresh while TTL valid")
	}

	// Force refresh and confirm new content appears.
	ghaIndexTTL = 0
	idx3, err := loadGHAVulnIndex(t.Context())
	if err != nil {
		t.Fatalf("loadGHAVulnIndex (refresh): %v", err)
	}
	if idx3 == nil || len(idx3.byPkg["owner/repo2"]) != 1 {
		t.Fatalf("expected owner/repo2 in refreshed index, got %#v", idx3.byPkg)
	}
}

func mustGHATestZipBytes(t *testing.T, files map[string]osvschema.Vulnerability) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, vuln := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		b, err := json.Marshal(vuln)
		if err != nil {
			t.Fatalf("json marshal: %v", err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	out, err := io.ReadAll(&buf)
	if err != nil {
		t.Fatalf("read buf: %v", err)
	}
	return out
}

func resetGHATestState() {
	ghaIndexBuildGroup = singleflight.Group{}
	ghaIndexMu = sync.RWMutex{}
	ghaIndex = nil
	ghaIndexBuiltAt = time.Time{}
	ghaIndexTTL = ghaDownloadTTL
}

func writeGHATestZip(path string, files map[string]osvschema.Vulnerability) error {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, vuln := range files {
		w, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()
			return err
		}
		b, err := json.Marshal(vuln)
		if err != nil {
			_ = zw.Close()
			return err
		}
		if _, err := w.Write(b); err != nil {
			_ = zw.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func TestIsGitHubActionsInput_Table(t *testing.T) {
	tests := []struct {
		in   PkgInput
		want bool
	}{
		{PkgInput{QueryKey: QueryKey{Ecosystem: "GitHub Actions"}}, true},
		{PkgInput{QueryKey: QueryKey{Ecosystem: "gha"}}, true},
		{PkgInput{QueryKey: QueryKey{PURL: "pkg:github/owner/repo@v1"}}, true},
		{PkgInput{QueryKey: QueryKey{Ecosystem: "npm"}}, false},
	}
	for _, tc := range tests {
		label := strings.TrimSpace(tc.in.Ecosystem)
		if label == "" {
			label = tc.in.PURL
		}
		t.Run(label, func(t *testing.T) {
			if got := isGitHubActionsInput(tc.in); got != tc.want {
				t.Fatalf("isGitHubActionsInput(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
