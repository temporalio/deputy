package inventory

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
)

const envRunMultiEcosystemTests = "DEPUTY_TEST_REMOTE"

// To run: DEPUTY_TEST_REMOTE=1 go test ./internal/inventory -run TestScanPackagesAcrossEcosystems -count=1
func TestScanPackagesAcrossEcosystems(t *testing.T) {
	if os.Getenv(envRunMultiEcosystemTests) == "" {
		t.Skipf("set %s=1 to run remote multi-ecosystem integration tests", envRunMultiEcosystemTests)
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	repos := []struct {
		name              string
		repoURL           string
		expectedPURLTypes []string
	}{
		{
			name:              "temporalio/sdk-go",
			repoURL:           "https://github.com/temporalio/sdk-go",
			expectedPURLTypes: []string{"golang"},
		},
		{
			name:              "temporalio/sdk-python",
			repoURL:           "https://github.com/temporalio/sdk-python",
			expectedPURLTypes: []string{"pypi"},
		},
		{
			name:              "temporalio/sdk-typescript",
			repoURL:           "https://github.com/temporalio/sdk-typescript",
			expectedPURLTypes: []string{"npm"},
		},
		{
			name:              "hashicorp/vault",
			repoURL:           "https://github.com/hashicorp/vault",
			expectedPURLTypes: []string{"golang"},
		},
		{
			name:              "hashicorp/terraform",
			repoURL:           "https://github.com/hashicorp/terraform",
			expectedPURLTypes: []string{"golang"},
		},
		{
			name:              "charmbracelet/ultraviolet",
			repoURL:           "https://github.com/charmbracelet/ultraviolet",
			expectedPURLTypes: []string{"golang"},
		},
	}

	for _, tc := range repos {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			repoDir := filepath.Join(t.TempDir(), "repo")
			repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{
				URL:           tc.repoURL,
				Depth:         1,
				SingleBranch:  true,
				Tags:          git.NoTags,
				ReferenceName: "",
			})
			if err != nil {
				t.Fatalf("clone %s: %v", tc.repoURL, err)
			}
			head, err := repo.Head()
			if err != nil {
				t.Fatalf("head: %v", err)
			}
			pkgs, err := ScanPackagesAtCommitSnapshot(ctx, repo, head.Hash(), ScanOptions{})
			if err != nil {
				t.Fatalf("scan packages: %v", err)
			}
			if len(pkgs) == 0 {
				t.Fatalf("no packages discovered for %s", tc.repoURL)
			}
			found := collectPURLTypes(pkgs)
			for _, want := range tc.expectedPURLTypes {
				if found[want] == 0 {
					t.Fatalf("expected ecosystem %s to be discovered, got %v", want, mapKeys(found))
				}
			}
		})
	}
}

func collectPURLTypes(pkgs []*extractor.Package) map[string]int {
	out := make(map[string]int)
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(pkg.PURLType))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(pkg.Ecosystem()))
		}
		if key == "" {
			continue
		}
		out[key]++
	}
	return out
}

func mapKeys(m map[string]int) []string {
	keys := slices.Collect(maps.Keys(m))
	slices.Sort(keys)
	return keys
}
