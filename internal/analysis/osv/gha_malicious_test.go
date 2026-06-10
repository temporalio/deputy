package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/temporalio/deputy/internal/cache/disk"
)

// TestGitHubActionsMALDetection verifies that Deputy detects malicious GitHub Actions
// that have OSSF MAL advisories. MAL advisories are identified by their ID prefix "MAL-"
// and indicate confirmed malicious packages.
func TestGitHubActionsMALDetection(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Simulate a MAL advisory for a malicious GitHub Action
	// MAL advisories typically indicate credential stealing, data exfiltration, etc.
	// For malicious actions without a fix, use "Introduced: 0" with no Fixed event.
	malVuln := osvschema.Vulnerability{
		ID:      "MAL-2024-1234",
		Summary: "Malicious GitHub Action steals secrets",
		Details: "This action exfiltrates GITHUB_TOKEN and other secrets to an external server. It was discovered to be part of a supply chain attack.",
		Aliases: []string{},
		Affected: []osvschema.Affected{
			{
				Package:  osvschema.Package{Name: "malicious-actor/evil-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Versions: []string{"1.0.0", "1.0.1", "1.1.0"},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"}, // All versions from beginning, no fix
						},
					},
				},
			},
		},
		Severity: []osvschema.Severity{
			{Type: osvschema.SeverityCVSSV3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"},
		},
		DatabaseSpecific: map[string]any{
			"severity": "CRITICAL",
			"malware":  true,
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"MAL-2024-1234.json": malVuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "malicious-actor/evil-action", Version: "1.0.0", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability for malicious action, got %d", len(got))
	}
	if got[0].ID != "MAL-2024-1234" {
		t.Fatalf("expected MAL-2024-1234, got %q", got[0].ID)
	}
	if got[0].Summary != "Malicious GitHub Action steals secrets" {
		t.Fatalf("expected malicious summary, got %q", got[0].Summary)
	}
}

// TestGitHubActionsMALMultipleVersions tests that all compromised versions of a malicious
// action are properly detected.
func TestGitHubActionsMALMultipleVersions(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// MAL advisory with specific version ranges
	malVuln := osvschema.Vulnerability{
		ID:      "MAL-2024-5678",
		Summary: "Cryptocurrency miner injected into action",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "crypto-miner/hidden-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "2.0.0"},
							{Fixed: "2.5.0"}, // Maintainer regained control and fixed
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"MAL-2024-5678.json": malVuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	tests := []struct {
		version string
		wantHit bool
	}{
		{"1.9.0", false}, // Before compromised range
		{"2.0.0", true},  // First compromised version
		{"2.3.5", true},  // Within compromised range
		{"2.4.9", true},  // Just before fix
		{"2.5.0", false}, // Fixed version
		{"3.0.0", false}, // After fix
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: "crypto-miner/hidden-action", Version: tc.version, Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if tc.wantHit && len(got) == 0 {
				t.Fatalf("expected vulnerability for version %s, got none", tc.version)
			}
			if !tc.wantHit && len(got) > 0 {
				t.Fatalf("expected no vulnerability for version %s, got %d", tc.version, len(got))
			}
		})
	}
}

// TestGitHubActionsTyposquattingDetection tests detection of typosquatting attacks
// where malicious actions use names similar to popular actions.
func TestGitHubActionsTyposquattingDetection(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Typosquatting advisories - similar to popular actions
	typosquatVuln := osvschema.Vulnerability{
		ID:      "MAL-2024-TYPO-001",
		Summary: "Typosquatting attack on actions/checkout",
		Details: "This action is a typosquatting attack mimicking actions/checkout. It exfiltrates repository contents.",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "action/checkout", Ecosystem: string(osvschema.EcosystemGitHubActions)}, // Missing 's'
				Ranges: []osvschema.Range{
					{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}}}, // All versions, no fix
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"MAL-2024-TYPO-001.json": typosquatVuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// Test the malicious typosquat is detected
	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "action/checkout", Version: "v4", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability for typosquat, got %d", len(got))
	}

	// The legitimate action should not match
	got2, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "actions/checkout", Version: "v4", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got2) != 0 {
		t.Fatalf("expected no vulnerabilities for legitimate action, got %d", len(got2))
	}
}

// TestGitHubActionsSHAPinnedVersions tests that SHA-pinned actions are properly handled.
func TestGitHubActionsSHAPinnedVersions(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Vulnerability with specific affected versions
	vuln := osvschema.Vulnerability{
		ID:      "GHSA-sha-test",
		Summary: "Vulnerability in specific versions",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/vulnerable-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "1.0.0"},
							{Fixed: "1.5.0"},
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-sha-test.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	tests := []struct {
		name    string
		version string
		wantHit bool
	}{
		{
			name:    "SHA commit hash",
			version: "abc123def456789012345678901234567890abcd",
			wantHit: true, // SHA without semver falls back to name/ecosystem match
		},
		{
			name:    "vulnerable semver",
			version: "1.3.0",
			wantHit: true,
		},
		{
			name:    "fixed semver",
			version: "1.5.0",
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: "owner/vulnerable-action", Version: tc.version, Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if tc.wantHit && len(got) == 0 {
				t.Fatalf("expected vulnerability for version %q, got none", tc.version)
			}
			if !tc.wantHit && len(got) > 0 {
				t.Fatalf("expected no vulnerability for version %q, got %d", tc.version, len(got))
			}
		})
	}
}

// TestGitHubActionsMultipleVulnerabilities tests detection of multiple advisories
// affecting the same action.
func TestGitHubActionsMultipleVulnerabilities(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Multiple vulnerabilities for the same action
	vuln1 := osvschema.Vulnerability{
		ID:      "GHSA-vuln-001",
		Summary: "First vulnerability",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/multi-vuln-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}},
				},
			},
		},
	}
	vuln2 := osvschema.Vulnerability{
		ID:      "GHSA-vuln-002",
		Summary: "Second vulnerability",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "owner/multi-vuln-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "1.5.0"}, {Fixed: "2.5.0"}}},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-vuln-001.json": vuln1,
		"GHSA-vuln-002.json": vuln2,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	tests := []struct {
		version   string
		wantVulns []string
		wantCount int
	}{
		{"1.0.0", []string{"GHSA-vuln-001"}, 1},
		{"1.8.0", []string{"GHSA-vuln-001", "GHSA-vuln-002"}, 2}, // Both vulnerabilities
		{"2.2.0", []string{"GHSA-vuln-002"}, 1},
		{"3.0.0", nil, 0},
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: "owner/multi-vuln-action", Version: tc.version, Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if len(got) != tc.wantCount {
				t.Fatalf("expected %d vulnerabilities, got %d", tc.wantCount, len(got))
			}
			gotIDs := make([]string, len(got))
			for i, v := range got {
				gotIDs[i] = v.ID
			}
			slices.Sort(gotIDs)
			slices.Sort(tc.wantVulns)
			if len(tc.wantVulns) > 0 && !slices.Equal(gotIDs, tc.wantVulns) {
				t.Fatalf("expected vuln IDs %v, got %v", tc.wantVulns, gotIDs)
			}
		})
	}
}

// TestGitHubActionsReusableWorkflowDetection tests that reusable workflows are
// properly detected and queried (they use owner/repo/.github/workflows/name.yml@ref format).
func TestGitHubActionsReusableWorkflowDetection(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Vulnerability affecting a reusable workflow
	vuln := osvschema.Vulnerability{
		ID:      "GHSA-workflow-001",
		Summary: "Vulnerable reusable workflow",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "org/shared-workflows", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-workflow-001.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// The workflow name includes subpath but OSV matches on owner/repo
	got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
		{QueryKey: QueryKey{Name: "org/shared-workflows", Version: "1.5.0", Ecosystem: "GitHub Actions"}},
	})
	if err != nil {
		t.Fatalf("queryOSVGHABucketBatch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got))
	}
}

// TestGitHubActionsCaseInsensitiveMatching verifies that action names are matched
// case-insensitively, as GitHub Action references are case-insensitive.
func TestGitHubActionsCaseInsensitiveMatching(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vuln := osvschema.Vulnerability{
		ID:      "GHSA-case-test",
		Summary: "Case test vulnerability",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "Owner/Action-Name", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}}}, // All versions
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-case-test.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// Test different case variations
	cases := []string{
		"owner/action-name",
		"OWNER/ACTION-NAME",
		"Owner/Action-Name",
		"oWnEr/AcTiOn-NaMe",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: name, Version: "1.0.0", Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 vulnerability for %q, got %d", name, len(got))
			}
		})
	}
}

// TestGitHubActionsGHSAIDFormats tests that various GHSA and CVE ID formats are
// properly handled for GitHub Actions.
func TestGitHubActionsGHSAIDFormats(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Different ID formats used in OSV
	vulns := map[string]osvschema.Vulnerability{
		"GHSA-test-ghsa.json": {
			ID:      "GHSA-1234-5678-abcd",
			Summary: "GHSA format advisory",
			Aliases: []string{"CVE-2024-12345"},
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{Name: "owner/ghsa-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
					Ranges:  []osvschema.Range{{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}}}}, // All versions
				},
			},
		},
		"MAL-2024-001.json": {
			ID:      "MAL-2024-0001",
			Summary: "MAL format advisory",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{Name: "owner/mal-action", Ecosystem: string(osvschema.EcosystemGitHubActions)},
					Ranges:  []osvschema.Range{{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}}}}, // All versions, malicious
				},
			},
			DatabaseSpecific: map[string]any{"malware": true},
		},
	}

	if err := writeGHATestZip(zipPath, vulns); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	tests := []struct {
		name     string
		action   string
		wantID   string
		wantType string // GHSA, MAL, etc.
	}{
		{"GHSA format", "owner/ghsa-action", "GHSA-1234-5678-abcd", "GHSA"},
		{"MAL format", "owner/mal-action", "MAL-2024-0001", "MAL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: tc.action, Version: "1.0.0", Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 vulnerability, got %d", len(got))
			}
			if got[0].ID != tc.wantID {
				t.Fatalf("expected ID %q, got %q", tc.wantID, got[0].ID)
			}
		})
	}
}

// TestGitHubActionsKnownVulnerableVersions tests detection of known real-world
// vulnerable GitHub Actions. These are documented vulnerabilities.
func TestGitHubActionsKnownVulnerableVersions(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Simulating real-world vulnerable actions (based on actual advisories)
	// GHSA-3jfq-742w-xg8j - actions/download-artifact artifact poisoning
	downloadArtifactVuln := osvschema.Vulnerability{
		ID:      "GHSA-3jfq-742w-xg8j",
		Summary: "Artifact poisoning in actions/download-artifact",
		Details: "Cross-workflow artifact access vulnerability",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "actions/download-artifact", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "4.1.3"}}},
				},
			},
		},
		Severity: []osvschema.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"GHSA-3jfq-742w-xg8j.json": downloadArtifactVuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// Don't do major tag resolution for this test
	origList := ghaListRemoteRefs
	ghaListRemoteRefs = func(_ context.Context, remoteURL string) ([]string, error) {
		return nil, nil
	}
	t.Cleanup(func() { ghaListRemoteRefs = origList })

	tests := []struct {
		version string
		wantHit bool
	}{
		{"4.1.2", true},  // Vulnerable
		{"4.1.3", false}, // Fixed
		{"4.1.4", false}, // After fix
		{"3.0.0", true},  // Old version
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: "actions/download-artifact", Version: tc.version, Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if tc.wantHit && len(got) == 0 {
				t.Fatalf("expected vulnerability for version %s", tc.version)
			}
			if !tc.wantHit && len(got) > 0 {
				t.Fatalf("expected no vulnerability for version %s", tc.version)
			}
		})
	}
}

// TestGitHubActionsEcosystemAliases verifies that ecosystem string aliases are
// handled correctly when routing to the GHA bucket.
func TestGitHubActionsEcosystemAliases(t *testing.T) {
	tests := []struct {
		ecosystem string
		wantGHA   bool
	}{
		{"GitHub Actions", true},
		{"github actions", true},
		{"github-actions", true},
		{"githubactions", true},
		{"gha", true},
		{"npm", false},
		{"go", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.ecosystem, func(t *testing.T) {
			input := PkgInput{QueryKey: QueryKey{Name: "test/action", Version: "1.0.0", Ecosystem: tc.ecosystem}}
			got := isGitHubActionsInput(input)
			if got != tc.wantGHA {
				t.Fatalf("isGitHubActionsInput(%q) = %v, want %v", tc.ecosystem, got, tc.wantGHA)
			}
		})
	}
}

// TestGitHubActionsWithZipRefresh verifies the zip file is refreshed properly
// when the cache TTL expires and new advisories are available.
func TestGitHubActionsWithZipRefresh(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	// Create initial zip with one vulnerability
	vulnV1 := map[string]osvschema.Vulnerability{
		"GHSA-001.json": {
			ID:      "GHSA-001",
			Summary: "First vulnerability",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{Name: "owner/action-v1", Ecosystem: string(osvschema.EcosystemGitHubActions)},
					Ranges:  []osvschema.Range{{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}}}},
				},
			},
		},
	}

	vulnV2 := map[string]osvschema.Vulnerability{
		"GHSA-001.json": vulnV1["GHSA-001.json"],
		"MAL-002.json": {
			ID:      "MAL-002",
			Summary: "New malicious action",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{Name: "owner/action-v2", Ecosystem: string(osvschema.EcosystemGitHubActions)},
					Ranges:  []osvschema.Range{{Type: osvschema.RangeEcosystem, Events: []osvschema.Event{{Introduced: "0"}}}},
				},
			},
		},
	}

	zipV1 := mustGHATestZipBytes(t, vulnV1)
	zipV2 := mustGHATestZipBytes(t, vulnV2)

	var mu sync.Mutex
	currentZip := zipV1
	etag := `W/"v1"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		z := currentZip
		e := etag
		mu.Unlock()

		if inm := r.Header.Get("If-None-Match"); inm == e {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", e)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(z)
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

	// First query should see v1 only
	idx1, err := loadGHAVulnIndex(context.Background())
	if err != nil {
		t.Fatalf("loadGHAVulnIndex v1: %v", err)
	}
	if len(idx1.byPkg["owner/action-v1"]) != 1 {
		t.Fatalf("expected action-v1 in index, got %v", idx1.byPkg)
	}
	if len(idx1.byPkg["owner/action-v2"]) != 0 {
		t.Fatalf("unexpected action-v2 in initial index")
	}

	// Update server to v2
	mu.Lock()
	currentZip = zipV2
	etag = `W/"v2"`
	mu.Unlock()

	// Force index refresh
	ghaIndexTTL = 0
	idx2, err := loadGHAVulnIndex(context.Background())
	if err != nil {
		t.Fatalf("loadGHAVulnIndex v2: %v", err)
	}
	if len(idx2.byPkg["owner/action-v2"]) != 1 {
		t.Fatalf("expected action-v2 in refreshed index, got %v", idx2.byPkg)
	}
}

// TestGitHubActionsIntroducedZeroOpenEnded tests the edge case where a vulnerability
// uses "Introduced: 0" with no Fixed version (open-ended range). This is common for
// malicious packages that should never be used. Previously this was a bug.
func TestGitHubActionsIntroducedZeroOpenEnded(t *testing.T) {
	resetGHATestState()
	tmp := t.TempDir()
	restore := disk.SetBaseDirForTest(tmp)
	t.Cleanup(restore)

	zipPath := filepath.Join(tmp, ghaCacheSubdir, ghaZipFilename)
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Malicious package with Introduced: "0" and no Fixed (all versions affected)
	vuln := osvschema.Vulnerability{
		ID:      "MAL-OPEN-ENDED",
		Summary: "Malicious package - never use any version",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "malicious/package", Ecosystem: string(osvschema.EcosystemGitHubActions)},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"}, // All versions from beginning
							// No Fixed event - all versions are affected forever
						},
					},
				},
			},
		},
	}

	if err := writeGHATestZip(zipPath, map[string]osvschema.Vulnerability{
		"MAL-OPEN-ENDED.json": vuln,
	}); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	now := time.Now()
	_ = os.Chtimes(zipPath, now, now)

	// All versions should be detected as vulnerable
	versions := []string{"0.0.1", "1.0.0", "2.5.3", "10.0.0", "v1", "v2", "v99"}
	for _, ver := range versions {
		t.Run(ver, func(t *testing.T) {
			got, err := queryOSVGHABucketBatch(context.Background(), nil, []PkgInput{
				{QueryKey: QueryKey{Name: "malicious/package", Version: ver, Ecosystem: "GitHub Actions"}},
			})
			if err != nil {
				t.Fatalf("queryOSVGHABucketBatch: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("expected 1 vulnerability for version %s (open-ended range), got %d", ver, len(got))
			}
		})
	}
}
