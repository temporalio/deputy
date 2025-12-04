package gitutil

import (
	"fmt"

	git "github.com/go-git/go-git/v5"
)

// CheckFilesChanged returns the list of changed file paths between two refs by
// generating a patch diff. It is used to short‑circuit expensive dependency
// analysis when go.mod and go.sum are unchanged.
func CheckFilesChanged(repoPath string, baseRef string, prRef string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("error opening repository: %w", err)
	}

	baseHash, err := ResolveRevisionEnhanced(repo, baseRef)
	if err != nil {
		return nil, fmt.Errorf("error resolving base reference '%s': %w", baseRef, err)
	}

	prHash, err := ResolveRevisionEnhanced(repo, prRef)
	if err != nil {
		return nil, fmt.Errorf("error resolving PR reference '%s': %w", prRef, err)
	}

	baseCommit, err := repo.CommitObject(*baseHash)
	if err != nil {
		return nil, fmt.Errorf("error getting base commit: %w", err)
	}

	prCommit, err := repo.CommitObject(*prHash)
	if err != nil {
		return nil, fmt.Errorf("error getting PR commit: %w", err)
	}

	changes, err := baseCommit.Patch(prCommit)
	if err != nil {
		return nil, fmt.Errorf("error getting patch: %w", err)
	}

	patches := changes.FilePatches()
	fileNames := make([]string, 0, len(patches))
	for _, change := range patches {
		from, to := change.Files()
		if from != nil {
			fileNames = append(fileNames, from.Path())
		} else if to != nil {
			fileNames = append(fileNames, to.Path())
		}
	}

	return fileNames, nil
}
