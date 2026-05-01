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
	"github.com/picatz/deputy/internal/cache/disk"
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
			want: PkgInput{QueryKey: QueryKey{Name: "owner/repo", PURL: "pkg:github/owner/repo@v2", Ecosystem: "GitHub Actions"}},
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
		{"not-semver", true}, // falls back to name/ecosystem match
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

func TestParseGHAMajorRef_Table(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"v4", 4, true},
		{"4", 4, true},
		{" v4 ", 4, true},
		{"v04", 4, true},
		{"v0", 0, false},
		{"0", 0, false},
		{"v4.2.0", 0, false},
		{"4.2.0", 0, false},
		{"", 0, false},
		{"deadbeef", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := parseGHAMajorRef(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseGHAMajorRef(%q) = %d,%v want %d,%v", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestResolveGitHubActionsVersion_Table(t *testing.T) {
	origList := ghaListRemoteRefs
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	tests := []struct {
		name       string
		repo       string
		version    string
		refs       []string
		want       string
		wantCalled bool
	}{
		{
			name:       "fully specified semver skips lookup",
			repo:       "owner/repo",
			version:    "v4.2.0",
			refs:       []string{"refs/tags/v4.3.0"},
			want:       "",
			wantCalled: false,
		},
		{
			name:       "rolling major resolves to highest patch",
			repo:       "owner/repo",
			version:    "v4",
			refs:       []string{"refs/tags/v4", "refs/tags/v4.1.3", "refs/tags/v4.2.0", "refs/tags/v3.9.9"},
			want:       "v4.2.0",
			wantCalled: true,
		},
		{
			name:       "annotated tags are handled",
			repo:       "owner/repo",
			version:    "v4",
			refs:       []string{"refs/tags/v4.2.0^{}", "refs/tags/v4.1.3"},
			want:       "v4.2.0",
			wantCalled: true,
		},
		{
			name:       "no matching tags yields empty",
			repo:       "owner/repo",
			version:    "v4",
			refs:       []string{"refs/tags/v5.0.0"},
			want:       "",
			wantCalled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
				called = true
				if remoteURL != "https://github.com/"+tc.repo+".git" {
					t.Fatalf("unexpected remoteURL %q", remoteURL)
				}
				return tc.refs, nil
			}
			got := resolveGitHubActionsVersion(context.Background(), &sync.Map{}, tc.repo, tc.version)
			if got != tc.want {
				t.Fatalf("resolveGitHubActionsVersion(%q,%q)=%q want %q", tc.repo, tc.version, got, tc.want)
			}
			if called != tc.wantCalled {
				t.Fatalf("called=%v want %v", called, tc.wantCalled)
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

	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/download-artifact", Version: "v4", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no vulnerabilities for rolling v4 tag that resolves >= fixed, got %#v", got)
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

	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
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

	idx, err := buildGHAVulnIndex(context.Background())
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

	p1, err := ensureGHACacheZip(context.Background())
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
	p2, err := ensureGHACacheZip(context.Background())
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
	idx1, err := loadGHAVulnIndex(context.Background())
	if err != nil {
		t.Fatalf("loadGHAVulnIndex (v1): %v", err)
	}
	if idx1 == nil || len(idx1.byPkg["owner/repo"]) != 1 {
		t.Fatalf("expected owner/repo in v1 index, got %#v", idx1.byPkg)
	}

	// Change the upstream zip, but keep in-memory TTL long enough that the index should not rebuild.
	body = zipV2
	etag = `W/"v2"`

	idx2, err := loadGHAVulnIndex(context.Background())
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
	idx3, err := loadGHAVulnIndex(context.Background())
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

func TestIsCommitSHA_Table(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		// Full SHA-1 (exactly 40 hex chars)
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", true},
		{"ABCDEF1234567890ABCDEF1234567890ABCDEF12", true},
		{"abcdef1234567890abcdef1234567890abcdef12", true},
		// Not full SHA-1
		{"deadbeef", false},                                  // abbreviated — handled by isAbbreviatedSHA
		{"a1b2c3d", false},                                   // abbreviated
		{"", false},
		{"v4.2.0", false},
		{"v4", false},
		{"main", false},
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7", false},   // 39 chars
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7cc", false},  // 41 chars
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461eZZ", false},   // non-hex
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := isCommitSHA(tc.in); got != tc.want {
				t.Fatalf("isCommitSHA(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsAbbreviatedSHA_Table(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"a1b2c3d", true},           // 7 chars — Git's default abbreviation
		{"deadbeef", true},          // 8 chars
		{"abc1234567890", true},     // 13 chars
		{"abcdef1", true},           // 7 chars
		{"1234abc", true},           // 7 chars, mixed
		{"abcdef1234567890abcdef1234567890abcdef1", true}, // 39 chars
		// Not abbreviated SHAs
		{"abcdef", false},           // 6 chars — too short
		{"a1b2c", false},            // 5 chars — too short
		{"", false},
		{"v4.2.0", false},           // not hex
		{"main", false},             // 4 chars, not hex
		{"deadbez", false},          // non-hex char
		// Full SHA-1 is not abbreviated
		{"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", false}, // exactly 40
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := isAbbreviatedSHA(tc.in); got != tc.want {
				t.Fatalf("isAbbreviatedSHA(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveGitHubActionsVersion_CommitSHA(t *testing.T) {
	origListHash := ghaListRemoteRefsWithHash
	t.Cleanup(func() { ghaListRemoteRefsWithHash = origListHash })

	tests := []struct {
		name       string
		repo       string
		version    string
		refs       []remoteRefEntry
		want       string
		wantCalled bool
	}{
		{
			name:    "full SHA resolves to tag via dereferenced annotated tag",
			repo:    "actions/download-artifact",
			version: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v8", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{Name: "refs/tags/v8.0.1", Hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
				{Name: "refs/tags/v8.0.1^{}", Hash: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"},
			},
			want:       "v8.0.1",
			wantCalled: true,
		},
		{
			name:    "full SHA resolves to lightweight tag directly",
			repo:    "owner/repo",
			version: "abcdef1234567890abcdef1234567890abcdef12",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v2.0.0", Hash: "abcdef1234567890abcdef1234567890abcdef12"},
			},
			want:       "v2.0.0",
			wantCalled: true,
		},
		{
			name:    "full SHA matches multiple tags returns highest",
			repo:    "owner/repo",
			version: "abcdef1234567890abcdef1234567890abcdef12",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v2.0.0", Hash: "abcdef1234567890abcdef1234567890abcdef12"},
				{Name: "refs/tags/v2.1.0", Hash: "abcdef1234567890abcdef1234567890abcdef12"},
			},
			want:       "v2.1.0",
			wantCalled: true,
		},
		{
			name:    "full SHA with no matching tag returns empty",
			repo:    "owner/repo",
			version: "1234567890abcdef1234567890abcdef12345678",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v1.0.0", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			},
			want:       "",
			wantCalled: true,
		},
		// Abbreviated SHA tests
		{
			name:    "abbreviated SHA resolves via prefix match",
			repo:    "owner/repo",
			version: "3e5f45b",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v8.0.1", Hash: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"},
			},
			want:       "v8.0.1",
			wantCalled: true,
		},
		{
			name:    "abbreviated SHA matches dereferenced annotated tag",
			repo:    "owner/repo",
			version: "deadbeef",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v3.0.0", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				{Name: "refs/tags/v3.0.0^{}", Hash: "deadbeef01234567890abcdef1234567890abcd"},
			},
			want:       "v3.0.0",
			wantCalled: true,
		},
		{
			name:    "abbreviated SHA no prefix match returns empty",
			repo:    "owner/repo",
			version: "cafebabe",
			refs: []remoteRefEntry{
				{Name: "refs/tags/v1.0.0", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			},
			want:       "",
			wantCalled: true,
		},
		// Non-SHA strings
		{
			name:       "6-char hex too short for resolution",
			repo:       "owner/repo",
			version:    "abcdef",
			refs:       nil,
			want:       "",
			wantCalled: false,
		},
		{
			name:       "branch name does not trigger lookup",
			repo:       "owner/repo",
			version:    "main",
			refs:       nil,
			want:       "",
			wantCalled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			ghaListRemoteRefsWithHash = func(_ context.Context, remoteURL string) ([]remoteRefEntry, error) {
				called = true
				return tc.refs, nil
			}
			got := resolveGitHubActionsVersion(context.Background(), &sync.Map{}, tc.repo, tc.version)
			if got != tc.want {
				t.Fatalf("resolveGitHubActionsVersion(%q, %q) = %q, want %q", tc.repo, tc.version, got, tc.want)
			}
			if called != tc.wantCalled {
				t.Fatalf("called=%v want %v", called, tc.wantCalled)
			}
		})
	}
}

func TestQueryOSVGHABucketBatch_CommitSHAResolutionAvoidsFalsePositive(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-cxww-7g56-2vh6",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "actions/download-artifact", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "4.0.0"},
							{Fixed: "4.1.3"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-cxww-7g56-2vh6.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// SHA maps to v8.0.1, which is outside the affected range (4.0.0–4.1.2).
	origListHash := ghaListRemoteRefsWithHash
	ghaListRemoteRefsWithHash = func(_ context.Context, remoteURL string) ([]remoteRefEntry, error) {
		return []remoteRefEntry{
			{Name: "refs/tags/v8", Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{Name: "refs/tags/v8.0.1", Hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			{Name: "refs/tags/v8.0.1^{}", Hash: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"},
		}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefsWithHash = origListHash })

	origList := ghaListRemoteRefs
	ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
		t.Error("ghaListRemoteRefs should not be called for SHA resolution")
		return nil, nil
	}
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/download-artifact", Version: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no vulnerabilities for SHA resolving to v8.0.1 (outside range 4.0.0–4.1.2), got %d: %#v", len(got), got)
	}
}

func TestQueryOSVGHABucketBatch_CommitSHAInVulnerableRangeStillFlagged(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID: "GHSA-cxww-7g56-2vh6",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "actions/download-artifact", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "4.0.0"},
							{Fixed: "4.1.3"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-cxww-7g56-2vh6.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// SHA maps to v4.1.1, which IS within the affected range (4.0.0–4.1.2).
	vulnSHA := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	origListHash := ghaListRemoteRefsWithHash
	ghaListRemoteRefsWithHash = func(_ context.Context, remoteURL string) ([]remoteRefEntry, error) {
		return []remoteRefEntry{
			{Name: "refs/tags/v4.1.1", Hash: vulnSHA},
			{Name: "refs/tags/v4.1.1^{}", Hash: vulnSHA},
		}, nil
	}
	t.Cleanup(func() { ghaListRemoteRefsWithHash = origListHash })

	origList := ghaListRemoteRefs
	ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
		t.Error("ghaListRemoteRefs should not be called for SHA resolution")
		return nil, nil
	}
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/download-artifact", Version: vulnSHA, Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability for SHA resolving to v4.1.1 (in range 4.0.0–4.1.2), got %d", len(got))
	}
}
