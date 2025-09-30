package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	cmp "github.com/picatz/deputy/internal/compare"
)

func requireNetwork(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("short")
	}
	if os.Getenv("DEPUTY_ONLINE_TESTS") == "" {
		t.Skip("network access required (set DEPUTY_ONLINE_TESTS=1)")
	}
}

func Test_Integration_CompareTags(t *testing.T) {
	requireNetwork(t)
	tests := []struct {
		name            string
		repoURL         string
		baseTag         string
		targetTag       string
		expectPackages  bool
		expectedChanges int
		skipReason      string
	}{
		{"hashicorp/go-getter v1.6.0 to v1.7.0", "https://github.com/hashicorp/go-getter", "v1.6.0", "v1.7.0", true, 38, "go-getter should have Go modules"},
		{"gin-gonic/gin v1.8.0 to v1.9.0", "https://github.com/gin-gonic/gin", "v1.8.0", "v1.9.0", true, 20, "gin should have Go modules"},
		{"spf13/cobra v1.6.0 to v1.7.0", "https://github.com/spf13/cobra", "v1.6.0", "v1.7.0", true, 1, "cobra should have Go modules"},
		{"same version comparison", "https://github.com/hashicorp/go-getter", "v1.7.0", "v1.7.0", true, 0, "go-getter should have Go modules"},
		{"kubernetes/client-go major version jump", "https://github.com/kubernetes/client-go", "v0.26.0", "v0.28.0", true, 27, "kubernetes client-go should have many dependencies"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			tmp := t.TempDir()
			repoDir := filepath.Join(tmp, "repo")
			repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{URL: tt.repoURL, Tags: git.AllTags, Depth: 0})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			baseRev, err := repo.ResolveRevision(plumbing.Revision(tt.baseTag))
			if err != nil {
				t.Fatalf("resolve base: %v", err)
			}
			targetRev, err := repo.ResolveRevision(plumbing.Revision(tt.targetTag))
			if err != nil {
				t.Fatalf("resolve target: %v", err)
			}
			basePkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, *baseRev, ScanOptions{})
			if err != nil {
				t.Fatalf("scan base: %v", err)
			}
			targetPkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, *targetRev, ScanOptions{})
			if err != nil {
				t.Fatalf("scan target: %v", err)
			}
			changes := cmp.ComparePackages(basePkgs, targetPkgs, nil, nil)
			if len(basePkgs) == 0 && len(targetPkgs) == 0 {
				if changes != nil {
					t.Fatalf("changes should be nil for empty inputs")
				}
				if tt.expectPackages {
					t.Fatalf("Expected packages: %s", tt.skipReason)
				}
				t.Skipf("No packages found: %s", tt.skipReason)
				return
			}
			if tt.baseTag == tt.targetTag && len(changes) == 0 {
				return
			}
			if changes == nil {
				t.Fatalf("nil changes slice with non-empty inputs")
			}
			if tt.expectedChanges >= 0 && len(changes) != tt.expectedChanges {
				t.Errorf("expected %d changes, got %d", tt.expectedChanges, len(changes))
			}
			// sanity check package objects
			check := func(ps []*extractor.Package) {
				if len(ps) > 0 && ps[0].Name == "" {
					t.Error("package missing name")
				}
			}
			check(basePkgs)
			check(targetPkgs)
		})
	}
}

func Test_Integration_ScanTemporalSDKs(t *testing.T) {
	requireNetwork(t)
	tests := []struct {
		name           string
		repoURL        string
		expectedNames  []string
		expectPURLType string
		skipIfEmpty    string
	}{
		{"Temporal TypeScript SDK", "https://github.com/temporalio/sdk-typescript", []string{"temporalio"}, purl.TypeNPM, ""},
		{"Temporal Python SDK", "https://github.com/temporalio/sdk-python", []string{"nexus-rpc"}, purl.TypePyPi, ""},
		{"Temporal Ruby SDK", "https://github.com/temporalio/sdk-ruby", []string{"temporalio_bridge"}, purl.TypeCargo, ""},
		{"Temporal .NET SDK", "https://github.com/temporalio/sdk-dotnet", []string{"temporal-sdk-bridge"}, purl.TypeCargo, ""},
		{"Temporal Java SDK", "https://github.com/temporalio/sdk-java", []string{"gradle-wrapper"}, purl.TypeMaven, ""},
		{"Temporal PHP SDK", "https://github.com/temporalio/sdk-php", nil, purl.TypeComposer, "composer repository does not include composer.lock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			tmp := t.TempDir()
			repoDir := filepath.Join(tmp, "repo")
			repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{
				URL:          tt.repoURL,
				Depth:        1,
				SingleBranch: true,
			})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			head, err := repo.Head()
			if err != nil {
				t.Fatalf("head: %v", err)
			}
			pkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, head.Hash(), ScanOptions{})
			if err != nil {
				if len(pkgs) == 0 {
					if tt.skipIfEmpty != "" {
						t.Skipf("scan failed for %s: %v", tt.repoURL, err)
						return
					}
					t.Fatalf("scan: %v", err)
				}
				t.Logf("scan warning: %v", err)
			}
			if len(pkgs) == 0 {
				if tt.skipIfEmpty != "" {
					t.Skipf("no packages discovered in %s: %s", tt.repoURL, tt.skipIfEmpty)
					return
				}
				t.Fatalf("expected packages for %s", tt.repoURL)
			}
			var (
				needles []string
				found   map[string]bool
			)
			if len(tt.expectedNames) > 0 {
				needles = make([]string, len(tt.expectedNames))
				found = make(map[string]bool, len(tt.expectedNames))
				for i, name := range tt.expectedNames {
					lower := strings.ToLower(name)
					needles[i] = lower
					found[lower] = false
				}
			}
			matches := make([]string, 0, len(pkgs))
			filtered := make([]*extractor.Package, 0, len(pkgs))
			for _, pkg := range pkgs {
				p := pkg.PURL()
				if p == nil || p.Type != tt.expectPURLType {
					continue
				}
				filtered = append(filtered, pkg)
				matches = append(matches, fmt.Sprintf("%s (pkg=%s)", p.Name, pkg.Name))
				if len(tt.expectedNames) == 0 {
					continue
				}
				pkgLower := strings.ToLower(pkg.Name)
				pLower := strings.ToLower(p.Name)
				for _, needle := range needles {
					if strings.Contains(pkgLower, needle) || strings.Contains(pLower, needle) {
						found[needle] = true
						continue
					}
					for _, loc := range pkg.Locations {
						if strings.Contains(strings.ToLower(loc), needle) {
							found[needle] = true
							break
						}
					}
				}
			}
			if len(filtered) == 0 {
				if tt.skipIfEmpty != "" {
					t.Skipf("no %s packages found in %s: %s", tt.expectPURLType, tt.repoURL, tt.skipIfEmpty)
					return
				}
				t.Fatalf("expected at least one %s package in %s inventory", tt.expectPURLType, tt.repoURL)
			}
			if testing.Verbose() && len(matches) > 0 {
				t.Logf("inventory for %s: %s", tt.repoURL, strings.Join(matches, ", "))
			}
			if len(tt.expectedNames) > 0 {
				missing := make([]string, 0)
				for i, needle := range needles {
					if !found[needle] {
						missing = append(missing, tt.expectedNames[i])
					}
				}
				if len(missing) > 0 {
					msg := "none"
					if len(matches) > 0 {
						msg = strings.Join(matches, ", ")
					}
					t.Fatalf("expected packages %v in %s inventory; missing %v; saw %s", tt.expectedNames, tt.repoURL, missing, msg)
				}
			} else if len(filtered) == 0 {
				if tt.skipIfEmpty != "" {
					t.Skipf("no %s packages found in %s: %s", tt.expectPURLType, tt.repoURL, tt.skipIfEmpty)
					return
				}
				t.Fatalf("expected at least one %s package in %s inventory", tt.expectPURLType, tt.repoURL)
			}
		})
	}
}

// Test_Integration_ScanTemporalSDKJavaStandalone performs a focused scan to aid debugging of Deputy
// Java-specific inventory behaviour (e.g., gradle wrapper handling).
func Test_Integration_ScanTemporalSDKJavaStandalone(t *testing.T) {
	requireNetwork(t)
	ctx := t.Context()
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "repo")
	repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{
		URL:          "https://github.com/temporalio/sdk-java",
		Depth:        1,
		SingleBranch: true,
	})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	pkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, head.Hash(), ScanOptions{})
	if err != nil && len(pkgs) == 0 {
		t.Fatalf("scan: %v", err)
	}
	if err != nil {
		t.Logf("scan warning: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("expected packages from sdk-java scan")
	}
	maven := make([]*extractor.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		p := pkg.PURL()
		if p == nil || p.Type != purl.TypeMaven {
			continue
		}
		maven = append(maven, pkg)
		name := pkg.Name
		pName := p.Name
		ver := p.Version
		locs := strings.Join(pkg.Locations, ", ")
		t.Logf("maven package: pkg=%s purl=%s@%s locs=%s", name, pName, ver, locs)
	}
	if len(maven) == 0 {
		t.Fatalf("no maven packages found in sdk-java inventory (total %d)", len(pkgs))
	}
}
