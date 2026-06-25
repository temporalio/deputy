package gitutil

import (
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// NormalizeGitRefForGoGit converts common time shorthands within Git revision expressions
// into ISO-8601 timestamps accepted by go-git. If no recognizable shorthand is present,
// the input is returned unchanged.
func NormalizeGitRefForGoGit(ref string) string {
	r := strings.TrimSpace(ref)
	before, after, found := strings.Cut(r, "@{")
	if !found {
		return r
	}
	inner, rest, found := strings.Cut(after, "}")
	if !found {
		return r
	}
	inner = strings.TrimSpace(inner)
	if iso := ParseTimeShorthandToISO(inner); iso != "" {
		return before + "@{" + iso + "}" + rest
	}
	return r
}

// ParseTimeShorthandToISO parses simple time shorthands and returns an RFC3339 UTC timestamp.
// Supported forms:
//   - "now"
//   - "yesterday"
//   - "<n>.<unit>.ago" where unit in {second(s), minute(s), hour(s), day(s), week(s), month(s), year(s)}
func ParseTimeShorthandToISO(expr string) string {
	s := strings.ToLower(strings.TrimSpace(expr))
	now := time.Now().UTC()
	switch s {
	case "now":
		return now.Format(time.RFC3339)
	case "yesterday":
		return now.Add(-24 * time.Hour).Format(time.RFC3339)
	}
	if core, found := strings.CutSuffix(s, ".ago"); found {
		core = strings.TrimSuffix(core, ".") // tolerate trailing dot
		nStr, unit, found := strings.Cut(core, ".")
		if found {
			nStr = strings.TrimSpace(nStr)
			unit = strings.TrimSpace(unit)
			if n, err := strconv.Atoi(nStr); err == nil && n > 0 {
				switch unit {
				case "s", "sec", "secs", "second", "seconds":
					return now.Add(-time.Duration(n) * time.Second).Format(time.RFC3339)
				case "m", "min", "mins", "minute", "minutes":
					return now.Add(-time.Duration(n) * time.Minute).Format(time.RFC3339)
				case "h", "hr", "hrs", "hour", "hours":
					return now.Add(-time.Duration(n) * time.Hour).Format(time.RFC3339)
				case "d", "day", "days":
					return now.Add(-time.Duration(n) * 24 * time.Hour).Format(time.RFC3339)
				case "w", "wk", "wks", "week", "weeks":
					return now.Add(-time.Duration(n) * 7 * 24 * time.Hour).Format(time.RFC3339)
				case "mo", "mon", "month", "months":
					return now.AddDate(0, -n, 0).Format(time.RFC3339)
				case "y", "yr", "yrs", "year", "years":
					return now.AddDate(-n, 0, 0).Format(time.RFC3339)
				}
			}
		}
	}
	return ""
}

// ResolveRevisionEnhanced resolves Git revisions with support for time-based selectors
// of the form "<ref>@{<timestamp>}" where <timestamp> is either RFC3339 or one of
// the supported shorthands handled by ParseTimeShorthandToISO. If a time selector
// is present, the function walks the commit history from <ref> backwards to find
// the newest commit whose commit time is <= the timestamp, and returns its hash.
// If no time selector is present, this defers to go-git's ResolveRevision.
// For CI environments (GitHub Actions, etc.), if a simple branch name fails to resolve,
// it will also try origin/<branch> as a fallback.
func ResolveRevisionEnhanced(repo *git.Repository, ref string) (*plumbing.Hash, error) {
	r := strings.TrimSpace(ref)
	before, after, found := strings.Cut(r, "@{")
	if !found {
		rn := NormalizeGitRefForGoGit(r)
		hash, err := repo.ResolveRevision(plumbing.Revision(rn))
		if err != nil && shouldTryOriginFallback(rn) {
			// Try with origin/ prefix for CI environments where the local branch
			// ref is absent. Runs for slashed branch names (fix/x) too, skipping
			// only already-remote-qualified refs.
			if remoteHash, remoteErr := repo.ResolveRevision(plumbing.Revision("origin/" + rn)); remoteErr == nil {
				return remoteHash, nil
			}
		}
		return hash, err
	}

	inner, _, found := strings.Cut(after, "}")
	if !found {
		rn := NormalizeGitRefForGoGit(r)
		return repo.ResolveRevision(plumbing.Revision(rn))
	}
	base := strings.TrimSpace(before)
	inner = strings.TrimSpace(inner)

	// Parse timestamp
	var ts time.Time
	if iso := ParseTimeShorthandToISO(inner); iso != "" {
		if t, err := time.Parse(time.RFC3339, iso); err == nil {
			ts = t
		}
	}
	if ts.IsZero() {
		if t, err := time.Parse(time.RFC3339, inner); err == nil {
			ts = t
		}
	}
	if ts.IsZero() {
		rn := NormalizeGitRefForGoGit(r)
		return repo.ResolveRevision(plumbing.Revision(rn))
	}

	// Resolve base ref without time selector
	baseRef := strings.TrimSpace(base)
	if baseRef == "" {
		baseRef = RefHEAD
	}
	bh, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		return nil, err
	}
	start, err := repo.CommitObject(*bh)
	if err != nil {
		return nil, err
	}

	// Walk commits; choose the newest commit with Committer.When <= ts
	var best *object.Commit
	seen := map[string]struct{}{}
	iter := object.NewCommitPreorderIter(start, nil, nil)
	_ = iter.ForEach(func(c *object.Commit) error {
		if _, ok := seen[c.Hash.String()]; ok {
			return nil
		}
		seen[c.Hash.String()] = struct{}{}
		if !c.Committer.When.After(ts) {
			if best == nil || c.Committer.When.After(best.Committer.When) {
				best = c
			}
		}
		return nil
	})
	if best != nil {
		h := best.Hash
		return &h, nil
	}
	// If ts is before entire history, pick the oldest reachable commit
	var last *object.Commit
	iter2 := object.NewCommitPreorderIter(start, nil, nil)
	_ = iter2.ForEach(func(c *object.Commit) error {
		last = c
		return nil
	})
	if last != nil {
		h := last.Hash
		return &h, nil
	}
	// Fallback to base
	return bh, nil
}
