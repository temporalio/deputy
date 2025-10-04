package index

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/picatz/deputy/internal/inventory"
)

func setupProductionTestIndex(t *testing.T) (*Index, func()) {
	t.Helper()

	// Create a temporary directory for the index
	tempDir, err := os.MkdirTemp(t.TempDir(), "deputy-index-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Initialize the index
	index, err := Open(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create index: %v", err)
	}

	// Return cleanup function to remove the temporary directory
	cleanup := func() {
		index.Close()
	}

	return index, cleanup
}

// TestTemporalSDKSecurityIntelligence performs comprehensive supply chain security analysis
// of the Temporal SDK Go repository across its release history, implementing time-aware
// vulnerability tracking, trend analysis, and actionable security intelligence for
// application security engineers.
func TestTemporalSDKSecurityIntelligence(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping comprehensive integration test in short mode")
	}

	ctx := context.Background()

	// Create test index for temporal analysis
	testIndex, cleanup := setupProductionTestIndex(t)
	defer cleanup()

	// Clone Temporal SDK Go repository
	t.Logf("Cloning Temporal SDK Go repository...")
	tempDir, err := os.MkdirTemp(t.TempDir(), "deputy-temporal-sdk-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	repoPath := filepath.Join(tempDir, "temporal-sdk-go")
	repo, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL: "https://github.com/temporalio/sdk-go.git",
	})
	if err != nil {
		t.Skipf("Failed to clone Temporal SDK Go repository: %v", err)
	}

	tagsIter, err := repo.Tags()
	if err != nil {
		t.Fatalf("Failed to retrieve tags: %v", err)
	}
	defer tagsIter.Close()

	// Iterate over tags and perform analysis
	err = tagsIter.ForEach(func(ref *plumbing.Reference) error {
		if !strings.HasPrefix(ref.Name().Short(), "v") || strings.Contains(ref.Name().Short(), "-") {
			return nil
		}

		tagName := ref.Name().Short()

		commit, err := repo.CommitObject(ref.Hash())
		if err != nil && err != plumbing.ErrObjectNotFound {
			log.Fatal(err)
		} else if err == plumbing.ErrObjectNotFound {
			t.Logf("Warning: Commit object not found for tag %s", tagName)
			return nil
		}

		// if commit.Author.When.Year() <= 2023 {
		// if commit.Author.When.Year() < 2025 {

		// If the commit is older than 360 days, skip it.
		if commit.Author.When.Before(time.Now().AddDate(0, 0, -360)) {
			t.Logf("Skipping tag %s as it is older", tagName)
			return nil
		}

		t.Logf("Analyzing tag: %s", tagName)

		pkgs, err := inventory.ScanPackagesAtCommitSnapshot(ctx, repo, ref.Hash(), inventory.ScanOptions{
			Ecosystems: []string{"go"},
		})
		if err != nil {
			t.Fatalf("Failed to scan packages at tag %s: %v", tagName, err)
		}

		for _, pkg := range pkgs {
			if pkg == nil {
				continue
			}

			if strings.HasPrefix(pkg.Name, "../") || strings.HasPrefix(pkg.Name, "./") {
				// t.Logf("Skipping package name %q at tag %s", pkg.Name, tagName)
				continue
			}

			purl := pkg.PURL()
			entityID := purl.String()

			ecosystem := pkg.Ecosystem()

			artifactID := fmt.Sprintf("%s:%s", commit.Hash.String(), entityID)

			entityMetadata := map[string]any{
				"repository": "github.com/temporalio/sdk-go",
				"ecosystem":  pkg.Ecosystem(),
				"purl":       purl.String(),
			}
			if pkg.Name != "" {
				entityMetadata["name"] = pkg.Name
			}
			if pkg.Version != "" {
				entityMetadata["version"] = pkg.Version
			}
			if ecosystem != "" {
				entityMetadata["ecosystem"] = ecosystem
			}
			if pkg.SourceCode != nil {
				entityMetadata["source_code"] = map[string]any{
					"repo":   pkg.SourceCode.Repo,
					"commit": pkg.SourceCode.Commit,
				}
			}

			data := map[string]any{
				"tag":           tagName,
				"commit":        commit.Hash.String(),
				"commit_time":   commit.Author.When.UTC(),
				"detected_by":   pkg.Plugins,
				"locations":     pkg.Locations,
				"licenses":      pkg.Licenses,
				"metadata":      pkg.Metadata,
				"annotations":   pkg.AnnotationsDeprecated,
				"layer_details": pkg.LayerDetails,
			}
			if len(pkg.ExploitabilitySignals) > 0 {
				data["exploitability_signals"] = pkg.ExploitabilitySignals
			}

			dimensions := map[string]string{
				"tag": tagName,
			}
			if ecosystem != "" {
				dimensions["ecosystem"] = ecosystem
			}
			if pkg.Name != "" {
				dimensions["package"] = pkg.Name
			}
			if pkg.Version != "" {
				dimensions["version"] = pkg.Version
			}

			artifact := Artifact{
				Namespace: "security",
				Type:      "sca_package",
				ID:        artifactID,
				Entity: Entity{
					Type:     "package",
					ID:       entityID,
					Metadata: entityMetadata,
				},
				Timestamp: commit.Author.When.UTC(),
				Data:      data,
				Relationships: []Relationship{
					{
						Type:   "derived_from",
						Target: "repo:github.com/temporalio/sdk-go",
					},
				},
				Context: map[string]any{
					"repository": "github.com/temporalio/sdk-go",
					"tag":        tagName,
				},
				Dimensions: dimensions,
			}

			if err := testIndex.PutArtifact(ctx, artifact); err != nil {
				t.Fatalf("Failed to store artifact for package %q: %v", entityID, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Error iterating over tags: %v", err)
	}

	// Now we can perform trend analysis and generate reports
	t.Logf("Generating security trend analysis report...")

	// Example query: List all unique packages detected across all tags
	t.Run("ListUniquePackages", func(t *testing.T) {
		compliedExpr, err := testIndex.Compile("artifact_namespace == 'security' && artifact_type == 'sca_package'", nil)
		if err != nil {
			t.Fatalf("Failed to list packages: %v", err)
		}
		artifacts, err := testIndex.Query(ctx, compliedExpr)
		if err != nil {
			t.Fatalf("Failed to query artifacts: %v", err)
		}

		packageSet := make(map[string]struct{})
		for art, err := range artifacts {
			t.Logf("%#+v\n", art)
			if err != nil {
				t.Fatalf("Error retrieving artifact: %v", err)
				continue
			}
			if pkgName, ok := art.Dimensions["package"]; ok {
				packageSet[pkgName] = struct{}{}
			}
		}

		t.Logf("Total unique packages detected across all tags: %d", len(packageSet))
	})

	t.Run("PrintIndex", func(t *testing.T) {
		printIndex(t, testIndex)
	})
}

func printIndex(t *testing.T, idx *Index) {
	t.Helper()

	ctx := context.Background()

	compliedExpr, err := idx.Compile("artifact_namespace == 'security' && artifact_type == 'sca_package'", nil)
	if err != nil {
		t.Fatalf("Failed to list packages: %v", err)
	}
	artifacts, err := idx.Query(ctx, compliedExpr)
	if err != nil {
		t.Fatalf("Failed to query artifacts: %v", err)
	}

	for art, err := range artifacts {
		if err != nil {
			t.Fatalf("Error retrieving artifact: %v", err)
			continue
		}
		t.Logf("%s from %s@%s\n", art.ID, art.Context["repository"], art.Context["tag"])
	}
}
