package analysis

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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

func resetGHATestState() {
	ghaIndexOnce = sync.Once{}
	ghaIndex = nil
	ghaIndexErr = nil
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
