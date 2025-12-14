package inventory

import (
	"path/filepath"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/compare"
)

func Test_Integration_CompareTags(t *testing.T) {
	t.Skip("network access required")
	if testing.Short() {
		t.Skip("short")
	}
	tests := []struct {
		name            string
		repoURL         string
		baseTag         string
		targetTag       string
		expectPackages  bool
		expectedChanges int
		skipReason      string
	}{
		{
			name:            "hashicorp/go-getter v1.6.0 to v1.7.0",
			repoURL:         "https://github.com/hashicorp/go-getter",
			baseTag:         "v1.6.0",
			targetTag:       "v1.7.0",
			expectPackages:  true,
			expectedChanges: 38,
			skipReason:      "go-getter should have Go modules",
		},
		{
			name:            "gin-gonic/gin v1.8.0 to v1.9.0",
			repoURL:         "https://github.com/gin-gonic/gin",
			baseTag:         "v1.8.0",
			targetTag:       "v1.9.0",
			expectPackages:  true,
			expectedChanges: 20,
			skipReason:      "gin should have Go modules",
		},
		{
			name:            "spf13/cobra v1.6.0 to v1.7.0",
			repoURL:         "https://github.com/spf13/cobra",
			baseTag:         "v1.6.0",
			targetTag:       "v1.7.0",
			expectPackages:  true,
			expectedChanges: 1,
			skipReason:      "cobra should have Go modules",
		},
		{
			name:            "same version comparison",
			repoURL:         "https://github.com/hashicorp/go-getter",
			baseTag:         "v1.7.0",
			targetTag:       "v1.7.0",
			expectPackages:  true,
			expectedChanges: 0,
			skipReason:      "go-getter should have Go modules",
		},
		{
			name:            "kubernetes/client-go major version jump",
			repoURL:         "https://github.com/kubernetes/client-go",
			baseTag:         "v0.26.0",
			targetTag:       "v0.28.0",
			expectPackages:  true,
			expectedChanges: 27,
			skipReason:      "kubernetes client-go should have many dependencies",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			tmp := t.TempDir()
			repoDir := filepath.Join(tmp, "repo")
			repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{URL: test.repoURL, Tags: git.AllTags, Depth: 0})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			baseRev, err := repo.ResolveRevision(plumbing.Revision(test.baseTag))
			if err != nil {
				t.Fatalf("resolve base: %v", err)
			}
			targetRev, err := repo.ResolveRevision(plumbing.Revision(test.targetTag))
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
			changes := compare.ComparePackages(basePkgs, targetPkgs, nil, nil, nil)
			if len(basePkgs) == 0 && len(targetPkgs) == 0 {
				if changes != nil {
					t.Fatalf("changes should be nil for empty inputs")
				}
				if test.expectPackages {
					t.Fatalf("Expected packages: %s", test.skipReason)
				}
				t.Skipf("No packages found: %s", test.skipReason)
				return
			}
			if test.baseTag == test.targetTag && len(changes) == 0 {
				return
			}
			if changes == nil {
				t.Fatalf("nil changes slice with non-empty inputs")
			}
			if test.expectedChanges >= 0 && len(changes) != test.expectedChanges {
				t.Errorf("expected %d changes, got %d", test.expectedChanges, len(changes))
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
