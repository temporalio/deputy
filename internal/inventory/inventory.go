package inventory

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	pl "github.com/google/osv-scalibr/plugin/list"
)

// ScanPackagesWorking scans the current working directory (including
// uncommitted changes) and returns the discovered package inventory.
func ScanPackagesWorking(ctx context.Context, repoPath string) ([]*extractor.Package, error) {
	plugins, err := pl.FromNames([]string{"go"})
	if err != nil {
		return nil, fmt.Errorf("error creating plugins: %w", err)
	}
	cfg := &scalibr.ScanConfig{ScanRoots: scalibrfs.RealFSScanRoots(repoPath), Plugins: plugins}
	results := scalibr.New().Scan(ctx, cfg)
	return results.Inventory.Packages, nil
}

// ScanPackagesAtCommitSnapshot scans the package inventory for a historical
// commit by materializing its tree into a temporary directory (non-destructive
// to the repository) and invoking the scanner on that snapshot.
func ScanPackagesAtCommitSnapshot(ctx context.Context, repoPath string, commitHash plumbing.Hash) ([]*extractor.Package, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("error opening repository: %w", err)
	}
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return nil, fmt.Errorf("error getting commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("error getting tree: %w", err)
	}
	dir, err := os.MkdirTemp("", "deputy-scan-commit-*")
	if err != nil {
		return nil, err
	}
	// Materialize files
	err = tree.Files().ForEach(func(f *object.File) error {
		// Skip .git directory entries
		if f.Name == ".git" || strings.HasPrefix(f.Name, ".git/") {
			return nil
		}
		target := filepath.Join(dir, f.Name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		r, err := f.Blob.Reader()
		if err != nil {
			return err
		}
		defer r.Close()
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	// Scan temp dir
	plugins, err := pl.FromNames([]string{"go"})
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("error creating plugins: %w", err)
	}
	cfg := &scalibr.ScanConfig{ScanRoots: scalibrfs.RealFSScanRoots(dir), Plugins: plugins}
	results := scalibr.New().Scan(ctx, cfg)
	_ = os.RemoveAll(dir)
	return results.Inventory.Packages, nil
}
