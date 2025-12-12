package analysis

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
			in:   PkgInput{Name: "github.com/owner/repo", Version: "1.0.0", Ecosystem: "github"},
			want: PkgInput{Name: "owner/repo", Version: "1.0.0", Ecosystem: "GitHub Actions"},
		},
		{
			name: "derive from purl",
			in:   PkgInput{PURL: "pkg:github/owner/repo@v2"},
			want: PkgInput{Name: "owner/repo", PURL: "pkg:github/owner/repo@v2", Ecosystem: "GitHub Actions"},
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
			pkg := PkgInput{Name: "owner/repo", Version: tc.version, Ecosystem: "GitHub Actions"}
			if got := versionAffectedByGHARanges(vuln, pkg); got != tc.want {
				t.Fatalf("versionAffectedByGHARanges(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestBuildGHAVulnIndex_UsesCacheZip(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	t.Setenv("DEPUTY_CACHE_DIR", tmp)
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""

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
	in := PkgInput{PURL: purl.PackageURL{Type: purl.TypeGithub, Namespace: "owner", Name: "repo", Version: "v1"}.String(), Version: "1.0.0"}
	norm := normalizeGitHubActionsInput(in)
	if norm.Name != "owner/repo" || norm.Ecosystem != "GitHub Actions" {
		t.Fatalf("normalized input = %+v", norm)
	}
}

func TestEnsureGHACacheZip_UsesETagConditionalRequest(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	t.Setenv("DEPUTY_CACHE_DIR", tmp)
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""

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
	t.Setenv("DEPUTY_CACHE_DIR", tmp)
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""

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
		{PkgInput{Ecosystem: "GitHub Actions"}, true},
		{PkgInput{Ecosystem: "gha"}, true},
		{PkgInput{PURL: "pkg:github/owner/repo@v1"}, true},
		{PkgInput{Ecosystem: "npm"}, false},
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
