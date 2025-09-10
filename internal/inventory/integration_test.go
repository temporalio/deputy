package inventory

import (
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	cmp "github.com/picatz/deputy/internal/compare"
	"path/filepath"
	"testing"
)

func Test_Integration_CompareTags(t *testing.T) {
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
			basePkgs, err := ScanPackagesAtCommitSnapshot(ctx, repoDir, *baseRev)
			if err != nil {
				t.Fatalf("scan base: %v", err)
			}
			targetPkgs, err := ScanPackagesAtCommitSnapshot(ctx, repoDir, *targetRev)
			if err != nil {
				t.Fatalf("scan target: %v", err)
			}
			changes := cmp.ComparePackages(basePkgs, targetPkgs, nil)
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
