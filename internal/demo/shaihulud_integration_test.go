package demo

import (
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
)

// Integration test that hits Wiz's live IOC CSV and the real GitHub API.
// Run with: SHAIHULUD_ORG=your-org [SHAIHULUD_REPOS=repo1,repo2] GITHUB_TOKEN=xxx go test -tags=integration ./internal/demo -count=1
func TestScanShaiHuludIntegration(t *testing.T) {
	owner := strings.TrimSpace(os.Getenv("SHAIHULUD_ORG"))
	if owner == "" {
		t.Skip("set SHAIHULUD_ORG to run integration test")
	}

	reposEnv := strings.TrimSpace(os.Getenv("SHAIHULUD_REPOS"))
	var repos []string
	if reposEnv != "" {
		for r := range strings.SplitSeq(reposEnv, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				repos = append(repos, r)
			}
		}
	}

	testScanShaiHuludIntegration(t, owner, os.Getenv("GITHUB_TOKEN"), repos...)
}

func TestScanShaiHuludIntegration_temporalio(t *testing.T) {
	testScanShaiHuludIntegration(
		t, "temporalio",
		os.Getenv("GITHUB_TOKEN"),
		// "temporal",
		// "sdk-go",
		// "sdk-java",
		// "sdk-typescript",
		// "sdk-python",
		// "sdk-dotnet",
		// "sdk-ruby",
		// "sdk-php",
		// "ui-server",
	)
}

func TestScanShaiHuludIntegration_hashicorp(t *testing.T) {
	testScanShaiHuludIntegration(
		t, "hashicorp",
		os.Getenv("GITHUB_TOKEN"),
		"vault",
	)
}

func TestScanShaiHuludIntegration_fetchWizIOCs(t *testing.T) {
	t.Helper()
	ctx := t.Context()

	set, err := fetchIOCSet(ctx, http.DefaultClient, WizShaiHuludIOCURL)
	if err != nil {
		t.Fatalf("fetchIOCSet: %v", err)
	}
	if len(set.packages) == 0 {
		t.Fatalf("expected IOC set to be non-empty")
	}
	t.Logf("fetched %d IOC packages from Wiz ShaiHulud CSV", len(set.packages))

	// Print packages and versions, in sorted order.
	pkgNames := slices.Collect(maps.Keys(set.packages))
	slices.Sort(pkgNames)
	for _, pkg := range pkgNames {
		versions := slices.Collect(maps.Keys(set.packages[pkg]))
		slices.Sort(versions)
		t.Logf(" - package %s: %d versions: %v", pkg, len(versions), versions)
	}
}

func testScanShaiHuludIntegration(t *testing.T, owner, token string, repos ...string) {
	t.Helper()
	ctx := t.Context()
	client := newGitHubClient(ctx, token)

	// Ensure we can reach Wiz IOC CSV.
	set, err := fetchIOCSet(ctx, http.DefaultClient, WizShaiHuludIOCURL)
	if err != nil {
		t.Fatalf("fetchIOCSet: %v", err)
	}
	if len(set.packages) == 0 {
		t.Fatalf("expected IOC set to be non-empty")
	}

	results, err := ScanShaiHulud(ctx, Options{
		Owner:        owner,
		Repos:        repos,
		GitHubClient: client,
	})
	if err != nil {
		t.Fatalf("ScanShaiHulud: %v", err)
	}

	t.Logf("scanned %d repositories", len(results))

	if len(results) == 0 {
		t.Fatalf("expected at least one repo scanned")
	}
	if len(repos) > 0 && len(results) != len(repos) {
		t.Fatalf("expected %d findings for provided repos, got %d", len(repos), len(results))
	}
	for _, f := range results {
		if f.Owner == "" || f.Name == "" {
			t.Fatalf("missing owner/name in finding: %+v", f)
		}
		if f.CloneURL == "" {
			t.Fatalf("missing clone URL for repo %s", f.Name)
		}
		if f.Error != nil {
			t.Logf("repo %s error: %v", f.Name, f.Error)
			continue
		}
		t.Logf("repo %s: %d matches", f.Name, len(f.Matches))
		for _, m := range f.Matches {
			if m.Package == "" || m.Version == "" {
				t.Fatalf("invalid match in repo %s: %+v", f.Name, m)
			}
			t.Logf("  - package %s version %s", m.Package, m.Version)
		}
	}
}
