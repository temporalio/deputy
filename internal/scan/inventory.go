package scan

import (
	"context"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	gitx "github.com/picatz/deputy/internal/gitutil"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// collectInventory determines whether to scan the working directory or a specific commit
// based on the provided git reference, and delegates to the appropriate scanning function.
func collectInventory(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error) {
	ref := refOrHEAD(gitRef)

	if strings.EqualFold(ref, gitx.RefHEAD) {
		return scanPackagesWorkingAtPath(ctx, repoPath, opts)
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	h, err := gitx.ResolveRevisionEnhanced(repo, ref)
	if err != nil {
		return nil, err
	}

	return scanPackagesAtCommit(ctx, repoPath, *h, opts)
}

// scanPackagesWorkingAtPath scans the filesystem at the given path for packages.
func scanPackagesWorkingAtPath(ctx context.Context, path string, opts inv.ScanOptions) ([]*extractor.Package, error) {
	ws, err := workspace.NewDir(path)
	if err != nil {
		return nil, err
	}
	defer ws.Close()
	return inv.ScanPackagesWorking(ctx, ws, opts)
}

// scanPackagesAtCommit scans the repository at the given commit hash for packages.
func scanPackagesAtCommit(ctx context.Context, path string, hash plumbing.Hash, opts inv.ScanOptions) ([]*extractor.Package, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, err
	}
	return inv.ScanPackagesAtCommitSnapshot(ctx, repo, hash, opts)
}
