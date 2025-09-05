package main

import (
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
)

func Test_Integration_CompareTags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	tests := []struct {
		name            string
		repoURL         string
		baseTag         string
		targetTag       string
		expectPackages  bool   // Whether we expect to find packages
		expectedChanges int    // Exact number of changes expected (-1 for any non-zero)
		skipReason      string // Reason to skip if packages not found
	}{
		{
			name:            "hashicorp/go-getter v1.6.0 to v1.7.0",
			repoURL:         "https://github.com/hashicorp/go-getter",
			baseTag:         "v1.6.0",
			targetTag:       "v1.7.0",
			expectPackages:  true,
			expectedChanges: 38, // Exact count we observed
			skipReason:      "go-getter should have Go modules",
		},
		{
			name:            "gin-gonic/gin v1.8.0 to v1.9.0",
			repoURL:         "https://github.com/gin-gonic/gin",
			baseTag:         "v1.8.0",
			targetTag:       "v1.9.0",
			expectPackages:  true,
			expectedChanges: 20, // Exact count we observed
			skipReason:      "gin should have Go modules",
		},
		{
			name:            "spf13/cobra v1.6.0 to v1.7.0",
			repoURL:         "https://github.com/spf13/cobra",
			baseTag:         "v1.6.0",
			targetTag:       "v1.7.0",
			expectPackages:  true,
			expectedChanges: 1, // Exact count we observed
			skipReason:      "cobra should have Go modules",
		},
		{
			name:            "same version comparison",
			repoURL:         "https://github.com/hashicorp/go-getter",
			baseTag:         "v1.7.0",
			targetTag:       "v1.7.0",
			expectPackages:  true,
			expectedChanges: 0, // Should be exactly 0 changes for same version
			skipReason:      "go-getter should have Go modules",
		},
		{
			name:            "kubernetes/client-go major version jump",
			repoURL:         "https://github.com/kubernetes/client-go",
			baseTag:         "v0.26.0",
			targetTag:       "v0.28.0",
			expectPackages:  true,
			expectedChanges: 27, // Exact count we observed
			skipReason:      "kubernetes client-go should have many dependencies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			tmp := t.TempDir()
			repoDir := filepath.Join(tmp, "repo")

			// Clone the repository
			repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{
				URL:  tt.repoURL,
				Tags: git.AllTags,
				// Full clone to ensure tags/references are available for ResolveRevision
				Depth: 0,
			})
			if err != nil {
				t.Fatalf("go-git clone failed: %v", err)
			}

			// Resolve tags to hashes
			baseRev, err := repo.ResolveRevision(plumbing.Revision(tt.baseTag))
			if err != nil {
				t.Fatalf("resolve base tag %s: %v", tt.baseTag, err)
			}
			targetRev, err := repo.ResolveRevision(plumbing.Revision(tt.targetTag))
			if err != nil {
				t.Fatalf("resolve target tag %s: %v", tt.targetTag, err)
			}

			// Scan packages at both revisions
			basePkgs, err := scanPackages(ctx, repoDir, *baseRev)
			if err != nil {
				t.Fatalf("scan base: %v", err)
			}
			targetPkgs, err := scanPackages(ctx, repoDir, *targetRev)
			if err != nil {
				t.Fatalf("scan target: %v", err)
			}

			t.Logf("Base packages: %d, Target packages: %d", len(basePkgs), len(targetPkgs))

			changes := comparePackages(basePkgs, targetPkgs)

			// When both package lists are empty, comparePackages should return nil
			if len(basePkgs) == 0 && len(targetPkgs) == 0 {
				if changes != nil {
					t.Fatalf("comparePackages should return nil when both package lists are empty, got %v", changes)
				}
				if tt.expectPackages {
					t.Fatalf("Expected to find packages but found none: %s", tt.skipReason)
				}
				t.Skipf("No packages found in either version: %s", tt.skipReason)
				return
			}

			// Special case: when comparing same versions, comparePackages may return nil if no changes
			if tt.baseTag == tt.targetTag && changes == nil {
				t.Logf("Same version comparison returned nil (no changes) as expected")
				return
			}

			// For non-empty inputs with different versions, comparePackages should return a valid slice (can be empty)
			if changes == nil {
				t.Fatalf("comparePackages returned nil slice when at least one package list was non-empty")
			}

			changeCount := len(changes)
			t.Logf("Found %d changes between %s and %s", changeCount, tt.baseTag, tt.targetTag)

			// Validate exact change count expectation
			if tt.expectedChanges >= 0 && changeCount != tt.expectedChanges {
				t.Errorf("Expected exactly %d changes, got %d", tt.expectedChanges, changeCount)
			}

			// Ensure returned PackageChange elements have valid Ecosystem
			for i, c := range changes {
				if c.Ecosystem == "" {
					t.Errorf("change %d missing ecosystem: %+v", i, c)
				}
				if c.Name == "" {
					t.Errorf("change %d missing name: %+v", i, c)
				}
				// At least one of BaseVersion or TargetVersion should be non-empty
				if c.BaseVersion == "" && c.TargetVersion == "" {
					t.Errorf("change %d missing both base and target version: %+v", i, c)
				}
			}

			// Also sanity-check scanPackages returns valid extractor.Package objects
			if len(basePkgs) > 0 {
				pkg := basePkgs[0]
				if pkg.Name == "" {
					t.Error("base package missing name")
				}
				// Version can be empty for some packages, so we don't check it
			}
			if len(targetPkgs) > 0 {
				pkg := targetPkgs[0]
				if pkg.Name == "" {
					t.Error("target package missing name")
				}
			}

			// Test synthetic changes: add a fake package to target to ensure detection works
			if len(basePkgs) > 0 || len(targetPkgs) > 0 {
				fake := &extractor.Package{Name: "example.com/fake-test-package", Version: "1.0.0"}
				syntheticChanges := comparePackages(basePkgs, append(targetPkgs, fake))
				if syntheticChanges == nil {
					t.Error("comparePackages with synthetic package returned nil")
				} else if len(syntheticChanges) <= len(changes) {
					t.Errorf("synthetic package addition should increase change count from %d to >%d, got %d",
						len(changes), len(changes), len(syntheticChanges))
				}
			}
		})
	}
}
