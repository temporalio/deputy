package githubactions

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/go-github/v63/github"
	"github.com/picatz/deputy/internal/pin"
)

// Verifier checks commit provenance using the GitHub API to detect
// fork/imposter commits and unsigned commits.
type Verifier struct {
	client *github.Client
}

// NewVerifier creates a Verifier using the provided GitHub API client.
func NewVerifier(client *github.Client) *Verifier {
	return &Verifier{client: client}
}

// Verify checks whether a commit SHA is trustworthy in the given repository.
// It checks:
//  1. Whether the commit is signed (GPG/SSH signature verified by GitHub).
//  2. Whether the commit is reachable from the repository's default branch.
//  3. Whether the commit might be a fork/imposter commit (fetchable from
//     the shared object store but not belonging to any branch).
func (v *Verifier) Verify(ctx context.Context, owner, repo, sha string) (*pin.Verification, error) {
	result := &pin.Verification{}

	// Fetch commit details including signature verification
	commit, resp, err := v.client.Git.GetCommit(ctx, owner, repo, sha)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			result.IsForkCommit = true
			result.Warnings = append(result.Warnings, "commit not found in repository (possible imposter commit)")
			return result, nil
		}
		return nil, fmt.Errorf("fetching commit %s: %w", truncSHA(sha), err)
	}

	// Check signature
	if ver := commit.GetVerification(); ver != nil {
		result.Signed = ver.GetSignature() != ""
		result.SignatureValid = ver.GetVerified()
		result.SignatureReason = ver.GetReason()
	}

	// Record author
	if author := commit.GetAuthor(); author != nil {
		result.CommitAuthor = author.GetName()
	}

	// Check if commit is reachable from the default branch
	repoInfo, _, err := v.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("fetching repo info for %s/%s: %w", owner, repo, err)
	}
	defaultBranch := repoInfo.GetDefaultBranch()
	if defaultBranch == "" {
		return nil, fmt.Errorf("could not determine default branch for %s/%s", owner, repo)
	}

	comparison, resp, err := v.client.Repositories.CompareCommits(ctx, owner, repo, defaultBranch, sha, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			result.IsForkCommit = true
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("commit not reachable from %s (possible imposter commit from fork)", defaultBranch))
		} else {
			// Non-404 errors (rate limit, auth, server): log and report as warning,
			// but don't silently mark as verified.
			slog.Warn("branch comparison failed",
				"owner", owner, "repo", repo, "sha", truncSHA(sha), "error", err)
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("could not verify branch reachability: %v", err))
		}
	} else {
		status := comparison.GetStatus()
		switch status {
		case "behind", "identical":
			result.OnBranch = true
			result.BranchName = defaultBranch
		case "ahead":
			// Commit is ahead of default branch — likely on a feature branch
			// or a recently merged PR. Not suspicious on its own.
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("commit is ahead of %s (may be on a different branch)", defaultBranch))
		case "diverged":
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("commit has diverged from %s", defaultBranch))
		default:
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("unexpected comparison status %q with %s", status, defaultBranch))
		}
	}

	// Signature warnings
	if !result.Signed {
		result.Warnings = append(result.Warnings, "commit is unsigned")
	} else if !result.SignatureValid {
		result.Warnings = append(result.Warnings, "commit signature is not verified")
	}

	// Fork/imposter heuristic: flag as suspicious when the commit is both
	// unsigned AND not reachable from the default branch. This matches the
	// exact pattern of the TeamPCP imposter commits (70379aad, 1885610c)
	// which were unsigned and existed only in the shared fork object store.
	//
	// Legitimate unsigned commits on feature branches will also trigger
	// this — the warning text says "possible" to reflect that uncertainty.
	if !result.SignatureValid && !result.OnBranch && !result.IsForkCommit {
		result.IsForkCommit = true
		result.Warnings = append(result.Warnings,
			"possible imposter commit from fork (unsigned and not reachable from default branch)")
	}

	return result, nil
}
