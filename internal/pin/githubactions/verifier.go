package githubactions

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/go-github/v63/github"
	"github.com/temporalio/deputy/internal/pin"
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

	// Fetch commit details including signature verification.
	commit, resp, err := v.client.Git.GetCommit(ctx, owner, repo, sha)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			// The SHA might be an annotated tag object rather than a commit.
			// This happens when ls-remote returns the tag object SHA instead
			// of the peeled commit SHA (e.g., git protocol v2 without peel).
			// Try to dereference it as a tag object before flagging suspicious.
			commitSHA, derefErr := v.dereferenceTagObject(ctx, owner, repo, sha)
			if derefErr != nil {
				result.IsForkCommit = true
				result.Warnings = append(result.Warnings, "commit not found in repository (possible imposter commit)")
				return result, nil
			}
			slog.Debug("dereferenced tag object to commit",
				"owner", owner, "repo", repo,
				"tag_object", truncSHA(sha), "commit", truncSHA(commitSHA))
			sha = commitSHA
			commit, _, err = v.client.Git.GetCommit(ctx, owner, repo, sha)
			if err != nil {
				result.IsForkCommit = true
				result.Warnings = append(result.Warnings, "commit not found in repository (possible imposter commit)")
				return result, nil
			}
		} else {
			return nil, fmt.Errorf("fetching commit %s: %w", truncSHA(sha), err)
		}
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

	// Check if commit is reachable from the default branch.
	// This may fail for renamed or inaccessible repositories — degrade
	// gracefully for 404 (renamed repo) but treat 403 (rate limit) as
	// unverifiable to avoid silently passing imposter commits.
	repoInfo, repoResp, err := v.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		status := 0
		if repoResp != nil {
			status = repoResp.StatusCode
		}
		if status == http.StatusNotFound {
			// Repo renamed or deleted — reachability is unknown, not an imposter.
			slog.Warn("cannot fetch repo info, skipping branch reachability check",
				"owner", owner, "repo", repo, "status", status, "error", err)
			result.Unverifiable = true
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("could not verify branch reachability: repo %s/%s not found (renamed or deleted?)", owner, repo))
			return result, nil
		}
		if status == http.StatusForbidden {
			// Rate limited or auth required — reachability is unknown. This is
			// NOT evidence of an imposter, so mark it unverifiable rather than
			// suspicious; the caller decides how to treat unverifiable refs.
			slog.Warn("rate limited or forbidden fetching repo info",
				"owner", owner, "repo", repo, "status", status, "error", err)
			result.Unverifiable = true
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("could not verify branch reachability: %s/%s returned %d (rate limited or token required?)", owner, repo, status))
			return result, nil
		}
		return nil, fmt.Errorf("fetching repo info for %s/%s: %w", owner, repo, err)
	}
	defaultBranch := repoInfo.GetDefaultBranch()
	if defaultBranch == "" {
		result.Unverifiable = true
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not determine default branch for %s/%s", owner, repo))
		return result, nil
	}

	comparison, resp, err := v.client.Repositories.CompareCommits(ctx, owner, repo, defaultBranch, sha, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			result.IsForkCommit = true
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("commit not reachable from %s (possible imposter commit from fork)", defaultBranch))
		} else {
			// Non-404 errors (rate limit, auth, server): reachability is unknown,
			// not evidence of an imposter. Mark unverifiable and report.
			slog.Warn("branch comparison failed",
				"owner", owner, "repo", repo, "sha", truncSHA(sha), "error", err)
			result.Unverifiable = true
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
	// Skip it when reachability was unverifiable: "unknown" is not "imposter".
	if !result.SignatureValid && !result.OnBranch && !result.IsForkCommit && !result.Unverifiable {
		result.IsForkCommit = true
		result.Warnings = append(result.Warnings,
			"possible imposter commit from fork (unsigned and not reachable from default branch)")
	}

	return result, nil
}

// dereferenceTagObject attempts to resolve a SHA as a git tag object and
// return the underlying commit SHA. This handles the case where ls-remote
// returns an annotated tag object SHA instead of the peeled commit SHA.
// Follows up to 5 levels of nested tags (tag → tag → ... → commit).
// Returns an error if the SHA is not a tag object or cannot be dereferenced.
func (v *Verifier) dereferenceTagObject(ctx context.Context, owner, repo, sha string) (string, error) {
	const maxDepth = 5
	current := sha
	for range maxDepth {
		tag, resp, err := v.client.Git.GetTag(ctx, owner, repo, current)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			return "", fmt.Errorf("not a tag object (status %d): %w", status, err)
		}
		obj := tag.GetObject()
		if obj == nil {
			return "", fmt.Errorf("tag has no target object")
		}
		if obj.GetType() == "commit" {
			return obj.GetSHA(), nil
		}
		if obj.GetType() == "tag" {
			current = obj.GetSHA()
			continue
		}
		return "", fmt.Errorf("tag points to %s, not a commit or tag", obj.GetType())
	}
	return "", fmt.Errorf("exceeded %d levels of nested tag objects", maxDepth)
}
