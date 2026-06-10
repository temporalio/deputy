package pin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/gobwas/glob"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Ref is a discovered dependency reference that may be pinnable.
type Ref struct {
	// Ecosystem identifies the pinning ecosystem (e.g., "github-actions").
	Ecosystem string `json:"ecosystem"`

	// Name is the dependency identifier (e.g., "actions/checkout").
	Name string `json:"name"`

	// Subpath is an optional sub-path within the dependency (e.g., for
	// owner/repo/subpath@ref in GitHub Actions).
	Subpath string `json:"subpath,omitempty"`

	// Version is the current version reference (tag, branch, SHA, etc.).
	Version string `json:"version"`

	// FilePath is the root-relative path to the file containing this reference.
	FilePath string `json:"filePath"`

	// Raw is the original reference string as it appears in the file.
	Raw string `json:"raw"`

	// LockedVersion is an optional exact version from a lockfile associated with
	// the source reference. Strategies may prefer it when pinning would otherwise
	// resolve a fuzzy request to a newer upstream version.
	LockedVersion string `json:"-"`
}

// DisplayName returns the full dependency name including subpath.
func (r Ref) DisplayName() string {
	if r.Subpath != "" {
		return r.Name + "/" + r.Subpath
	}
	return r.Name
}

// commitSHARe matches a full 40-character hexadecimal Git commit SHA.
// Used to distinguish SHA-pinned refs from mutable tags/branches.
var commitSHARe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// IsSHAPinned reports whether Version is a 40-character hex commit SHA.
func (r Ref) IsSHAPinned() bool {
	return commitSHARe.MatchString(r.Version)
}

// PinStatus indicates the outcome of pinning a dependency.
type PinStatus string

const (
	StatusPinned        PinStatus = "pinned"
	StatusAlreadyPinned PinStatus = "already-pinned"
	StatusUpdated       PinStatus = "updated"
	StatusUnpinned      PinStatus = "unpinned"
	StatusSkipped       PinStatus = "skipped"
	StatusError         PinStatus = "error"
	StatusVerified      PinStatus = "verified"
	StatusSuspicious    PinStatus = "suspicious"
)

// Result captures the outcome for a single dependency.
type Result struct {
	Ref          Ref           `json:"ref"`
	Status       PinStatus     `json:"status"`
	PinnedValue  string        `json:"pinnedValue,omitempty"`  // e.g., the commit SHA
	VersionTag   string        `json:"versionTag,omitempty"`   // e.g., the semver tag for comment
	PreviousRef  string        `json:"previousRef,omitempty"`  // the original version
	Verification *Verification `json:"verification,omitempty"` // fork/imposter check result
	Reason       string        `json:"reason,omitempty"`       // human-readable status detail
	Error        string        `json:"error,omitempty"`
}

// Report aggregates all pin results.
type Report struct {
	Results []Result `json:"results"`
	Stats   Stats    `json:"stats"`
}

// Stats summarizes the pin operation outcomes.
type Stats struct {
	Total         int `json:"total"`
	Pinned        int `json:"pinned"`
	AlreadyPinned int `json:"alreadyPinned"`
	Updated       int `json:"updated,omitempty"`
	Unpinned      int `json:"unpinned,omitempty"`
	Skipped       int `json:"skipped"`
	Errors        int `json:"errors"`
	Verified      int `json:"verified"`
	Suspicious    int `json:"suspicious"`
}

// Options configures the pin operation.
type Options struct {
	DryRun           bool
	SkipVerification bool     // skip provenance checks during pinning
	Concurrency      int      // parallel API requests (default: 4)
	Exclude          []string // glob patterns for action names to skip
}

// concurrency returns the configured concurrency level, defaulting to 4.
func (o *Options) concurrency() int {
	if o.Concurrency <= 0 {
		return 4
	}
	return o.Concurrency
}

// Strategy defines how a specific ecosystem handles pinning. Each supported
// ecosystem implements this interface to provide discovery, resolution,
// verification, and rewriting for its dependency format.
//
// Implemented by:
//   - [GitHubActionsStrategy]: commit SHA pins for workflow action uses
//   - [ContainerStrategy]: sha256 digest pins for Dockerfiles and workflow containers
//
// The interface is designed so new ecosystems can be added by implementing
// these methods without modifying the orchestrator. See doc.go for the
// roadmap of future ecosystems.
type Strategy interface {
	// Ecosystem returns the ecosystem identifier (e.g., "github-actions",
	// "container-image").
	Ecosystem() string

	// IsPinned reports whether the ref is already pinned to an immutable
	// reference for this ecosystem (e.g., 40-char commit SHA for GitHub
	// Actions, sha256 digest for container images).
	IsPinned(ref Ref) bool

	// ShouldSkip reports whether the ref cannot or should not be pinned
	// (e.g., expression refs, scratch images, dynamic references).
	// Returns true and a reason string if the ref should be skipped.
	ShouldSkip(ref Ref) (skip bool, reason string)

	// Discover finds all pinnable references in the filesystem.
	Discover(ctx context.Context, fsys scalibrfs.FS) ([]Ref, error)

	// Resolve converts a mutable version reference to an immutable pin.
	// Returns the pinned value (e.g., commit SHA, sha256 digest) and a
	// human-readable version tag to preserve alongside the pin.
	Resolve(ctx context.Context, ref Ref) (pinnedValue, versionTag string, err error)

	// Verify checks whether an existing pin is trustworthy (e.g., not a
	// fork/imposter commit, valid signature). Returns nil Verification
	// when provenance checking is not available for this ecosystem.
	Verify(ctx context.Context, ref Ref) (*Verification, error)

	// Rewrite applies pin updates to files within the given root directory.
	// Path is root-relative. Implementations must preserve file formatting,
	// comments, and unrelated content.
	Rewrite(root *os.Root, path string, updates []Update) error

	// ResolveUpdate re-resolves an already-pinned ref to check for newer
	// versions. Returns the new pinned value, new version tag, and current
	// version tag. If already at latest, returns pinnedValue equal to
	// ref.Version (caller detects no-op).
	ResolveUpdate(ctx context.Context, ref Ref) (pinnedValue, newVersionTag, currentVersionTag string, err error)
}

// Update describes a single reference to rewrite in a file.
type Update struct {
	// Name is the dependency name (e.g., "actions/checkout" or
	// "actions/checkout/subpath").
	Name string

	// PinnedValue is the immutable pin (e.g., 40-char commit SHA).
	PinnedValue string

	// VersionTag is the human-readable version for the comment (e.g., "v4.2.2").
	VersionTag string
}

// Verification captures the result of provenance checks on a pinned reference.
type Verification struct {
	Signed          bool     `json:"signed"`
	SignatureValid  bool     `json:"signatureValid"`
	SignatureReason string   `json:"signatureReason,omitempty"`
	OnBranch        bool     `json:"onBranch"`
	BranchName      string   `json:"branchName,omitempty"`
	IsForkCommit    bool     `json:"isForkCommit"`
	CommitAuthor    string   `json:"commitAuthor,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

// closeStrategy releases any resources a strategy lazily acquired during the
// operation (e.g. a pooled API connection). Strategies that hold no resources
// need not implement io.Closer; for them this is a no-op.
func closeStrategy(ctx context.Context, s Strategy) {
	c, ok := s.(io.Closer)
	if !ok {
		return
	}
	if err := c.Close(); err != nil {
		slog.DebugContext(ctx, "pin: closing strategy", "ecosystem", s.Ecosystem(), "error", err)
	}
}

// Pin discovers pinnable references, resolves them to immutable pins,
// optionally verifies them, and rewrites the files.
func Pin(ctx context.Context, root *os.Root, opts Options, strategies ...Strategy) (*Report, error) {
	if err := validateExcludePatterns(opts.Exclude); err != nil {
		return nil, err
	}
	fsys, err := rootFS(root)
	if err != nil {
		return nil, err
	}

	report := &Report{}

	for _, strategy := range strategies {
		defer closeStrategy(ctx, strategy)
		refs, err := strategy.Discover(ctx, fsys)
		if err != nil {
			return nil, fmt.Errorf("discovering %s dependencies: %w", strategy.Ecosystem(), err)
		}

		results := processRefs(ctx, refs, strategy, &opts)
		report.Results = append(report.Results, results...)

		// Write updates unless dry-run.
		if !opts.DryRun {
			if err := writeStrategyUpdates(strategy, root, results); err != nil {
				return report, fmt.Errorf("writing %s updates: %w", strategy.Ecosystem(), err)
			}
		}
	}

	computeStats(report)
	return report, nil
}

// processRefs handles resolution and verification for a set of refs using
// bounded concurrency. Respects context cancellation.
func processRefs(ctx context.Context, refs []Ref, strategy Strategy, opts *Options) []Result {
	results := make([]Result, len(refs))
	sem := make(chan struct{}, opts.concurrency())
	var wg sync.WaitGroup

	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			results[i] = Result{
				Ref:    ref,
				Status: StatusError,
				Error:  err.Error(),
			}
			continue
		}
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = Result{
				Ref:    ref,
				Status: StatusError,
				Error:  ctx.Err().Error(),
			}
			wg.Done()
			continue
		}
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			results[i] = processOneRef(ctx, ref, strategy, opts)
		}()
	}

	wg.Wait()
	return results
}

// processOneRef handles a single ref.
func processOneRef(ctx context.Context, ref Ref, strategy Strategy, opts *Options) Result {
	result := Result{
		Ref:         ref,
		PreviousRef: ref.Version,
	}

	// Skip excluded refs.
	if shouldExclude(ref, opts.Exclude) {
		result.Status = StatusSkipped
		result.Reason = "excluded"
		return result
	}

	// Skip unpinnable refs (ecosystem-specific check).
	if skip, reason := strategy.ShouldSkip(ref); skip {
		result.Status = StatusSkipped
		result.Reason = reason
		return result
	}

	return pinRef(ctx, ref, strategy, opts, result)
}

// pinRef resolves a ref and prepares the update.
func pinRef(ctx context.Context, ref Ref, strategy Strategy, opts *Options, result Result) Result {
	// Already pinned to an immutable ref for this ecosystem.
	if strategy.IsPinned(ref) {
		result.Status = StatusAlreadyPinned
		result.PinnedValue = ref.Version
		result.Reason = "already pinned"

		// Still verify if not skipped
		if !opts.SkipVerification {
			v, err := strategy.Verify(ctx, ref)
			if err != nil {
				result.Reason = fmt.Sprintf("already pinned (verification failed: %v)", err)
			} else if v != nil {
				result.Verification = v
				if v.IsForkCommit {
					result.Status = StatusSuspicious
					result.Reason = strings.Join(v.Warnings, "; ")
				}
			}
		}
		return result
	}

	// Resolve to immutable pin
	pinnedValue, versionTag, err := strategy.Resolve(ctx, ref)
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Sprintf("resolving: %v", err)
		return result
	}
	result.PinnedValue = pinnedValue
	result.VersionTag = versionTag

	// Verify unless skipped
	if !opts.SkipVerification {
		pinnedRef := ref
		pinnedRef.Version = pinnedValue
		v, err := strategy.Verify(ctx, pinnedRef)
		if err == nil && v != nil {
			result.Verification = v
			if v.IsForkCommit {
				result.Status = StatusSuspicious
				result.Reason = strings.Join(v.Warnings, "; ")
				return result
			}
		}
	}

	result.Status = StatusPinned
	return result
}

// writeStrategyUpdates groups pinned results by file and calls the strategy's
// Rewrite method.
func writeStrategyUpdates(strategy Strategy, root *os.Root, results []Result) error {
	fileUpdates := map[string][]Update{}
	for _, r := range results {
		if r.Status != StatusPinned && r.Status != StatusUpdated {
			continue
		}
		fileUpdates[r.Ref.FilePath] = append(fileUpdates[r.Ref.FilePath], Update{
			Name:        r.Ref.DisplayName(),
			PinnedValue: r.PinnedValue,
			VersionTag:  r.VersionTag,
		})
	}

	for file, updates := range fileUpdates {
		if err := strategy.Rewrite(root, file, updates); err != nil {
			return fmt.Errorf("rewriting %s: %w", file, err)
		}
	}
	return nil
}

// Check discovers pinnable refs and reports which are pinned and which are not.
// It makes no API calls and writes no files — purely local file scanning.
func Check(ctx context.Context, root *os.Root, opts Options, strategies ...Strategy) (*Report, error) {
	if err := validateExcludePatterns(opts.Exclude); err != nil {
		return nil, err
	}
	fsys, err := rootFS(root)
	if err != nil {
		return nil, err
	}

	report := &Report{}

	for _, strategy := range strategies {
		defer closeStrategy(ctx, strategy)
		refs, err := strategy.Discover(ctx, fsys)
		if err != nil {
			return nil, fmt.Errorf("discovering %s dependencies: %w", strategy.Ecosystem(), err)
		}

		for _, ref := range refs {
			result := Result{Ref: ref, PreviousRef: ref.Version}

			if shouldExclude(ref, opts.Exclude) {
				result.Status = StatusSkipped
				result.Reason = "excluded"
				report.Results = append(report.Results, result)
				continue
			}
			if skip, reason := strategy.ShouldSkip(ref); skip {
				result.Status = StatusSkipped
				result.Reason = reason
				report.Results = append(report.Results, result)
				continue
			}
			if strategy.IsPinned(ref) {
				result.Status = StatusAlreadyPinned
				result.PinnedValue = ref.Version
			} else {
				result.Status = StatusUnpinned
				result.Reason = "not pinned to immutable ref"
			}
			report.Results = append(report.Results, result)
		}
	}

	computeStats(report)
	return report, nil
}

// Verify checks existing SHA-pinned refs for provenance (fork/imposter
// commits, signature status). It makes API calls but writes no files.
// Unpinned refs are skipped.
func Verify(ctx context.Context, root *os.Root, opts Options, strategies ...Strategy) (*Report, error) {
	if err := validateExcludePatterns(opts.Exclude); err != nil {
		return nil, err
	}
	fsys, err := rootFS(root)
	if err != nil {
		return nil, err
	}

	report := &Report{}

	for _, strategy := range strategies {
		defer closeStrategy(ctx, strategy)
		refs, err := strategy.Discover(ctx, fsys)
		if err != nil {
			return nil, fmt.Errorf("discovering %s dependencies: %w", strategy.Ecosystem(), err)
		}

		results := processVerifyRefs(ctx, refs, strategy, &opts)
		report.Results = append(report.Results, results...)
	}

	computeStats(report)
	return report, nil
}

// processVerifyRefs handles verification for a set of refs using bounded
// concurrency.
func processVerifyRefs(ctx context.Context, refs []Ref, strategy Strategy, opts *Options) []Result {
	results := make([]Result, len(refs))
	sem := make(chan struct{}, opts.concurrency())
	var wg sync.WaitGroup

	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			results[i] = Result{
				Ref:    ref,
				Status: StatusError,
				Error:  err.Error(),
			}
			continue
		}
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = Result{
				Ref:    ref,
				Status: StatusError,
				Error:  ctx.Err().Error(),
			}
			wg.Done()
			continue
		}
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			results[i] = processOneVerifyRef(ctx, ref, strategy, opts)
		}()
	}

	wg.Wait()
	return results
}

// processOneVerifyRef handles a single ref for verify mode.
func processOneVerifyRef(ctx context.Context, ref Ref, strategy Strategy, opts *Options) Result {
	result := Result{
		Ref:         ref,
		PreviousRef: ref.Version,
	}

	if shouldExclude(ref, opts.Exclude) {
		result.Status = StatusSkipped
		result.Reason = "excluded"
		return result
	}
	if skip, reason := strategy.ShouldSkip(ref); skip {
		result.Status = StatusSkipped
		result.Reason = reason
		return result
	}

	if !strategy.IsPinned(ref) {
		result.Status = StatusSkipped
		result.Reason = "not pinned"
		return result
	}

	result.PinnedValue = ref.Version

	v, err := strategy.Verify(ctx, ref)
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Sprintf("verification failed: %v", err)
		return result
	}
	if v == nil {
		// Strategy returned no verification data — there is no pin-time
		// provenance check for this ecosystem (e.g. mise verifies tool
		// provenance at install time via cosign/SLSA/attestations; container
		// digest signature checking is not yet supported). Report as
		// already-pinned rather than verified so the output never implies
		// provenance was actually checked, while still surfacing the reason.
		result.Status = StatusAlreadyPinned
		result.Reason = "no pin-time provenance check"
		return result
	}

	result.Verification = v
	if v.IsForkCommit {
		result.Status = StatusSuspicious
		result.Reason = strings.Join(v.Warnings, "; ")
		return result
	}

	result.Status = StatusVerified
	return result
}

// PinUpdate re-pins already-pinned refs to the latest version in their major
// version channel. Unpinned refs are skipped.
func PinUpdate(ctx context.Context, root *os.Root, opts Options, strategies ...Strategy) (*Report, error) {
	if err := validateExcludePatterns(opts.Exclude); err != nil {
		return nil, err
	}
	fsys, err := rootFS(root)
	if err != nil {
		return nil, err
	}

	report := &Report{}

	for _, strategy := range strategies {
		defer closeStrategy(ctx, strategy)
		refs, err := strategy.Discover(ctx, fsys)
		if err != nil {
			return nil, fmt.Errorf("discovering %s dependencies: %w", strategy.Ecosystem(), err)
		}

		results := processUpdateRefs(ctx, refs, strategy, &opts)
		report.Results = append(report.Results, results...)

		if !opts.DryRun {
			if err := writeStrategyUpdates(strategy, root, results); err != nil {
				return report, fmt.Errorf("writing %s updates: %w", strategy.Ecosystem(), err)
			}
		}
	}

	computeStats(report)
	return report, nil
}

// processUpdateRefs handles update resolution for a set of refs using
// bounded concurrency.
func processUpdateRefs(ctx context.Context, refs []Ref, strategy Strategy, opts *Options) []Result {
	results := make([]Result, len(refs))
	sem := make(chan struct{}, opts.concurrency())
	var wg sync.WaitGroup

	for i, ref := range refs {
		if err := ctx.Err(); err != nil {
			results[i] = Result{
				Ref:    ref,
				Status: StatusError,
				Error:  err.Error(),
			}
			continue
		}
		wg.Add(1)
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = Result{
				Ref:    ref,
				Status: StatusError,
				Error:  ctx.Err().Error(),
			}
			wg.Done()
			continue
		}
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()
			results[i] = processOneUpdateRef(ctx, ref, strategy, opts)
		}()
	}

	wg.Wait()
	return results
}

// processOneUpdateRef handles a single ref for update mode.
func processOneUpdateRef(ctx context.Context, ref Ref, strategy Strategy, opts *Options) Result {
	result := Result{
		Ref:         ref,
		PreviousRef: ref.Version,
	}

	if shouldExclude(ref, opts.Exclude) {
		result.Status = StatusSkipped
		result.Reason = "excluded"
		return result
	}
	if skip, reason := strategy.ShouldSkip(ref); skip {
		result.Status = StatusSkipped
		result.Reason = reason
		return result
	}

	// Only update already-pinned refs.
	if !strategy.IsPinned(ref) {
		result.Status = StatusSkipped
		result.Reason = "not pinned (use 'deputy pin' first)"
		return result
	}

	pinnedValue, newTag, currentTag, err := strategy.ResolveUpdate(ctx, ref)
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Sprintf("resolving update: %v", err)
		return result
	}

	// No change needed.
	if pinnedValue == ref.Version {
		result.Status = StatusAlreadyPinned
		result.PinnedValue = ref.Version
		result.VersionTag = currentTag
		result.Reason = "already at latest"
		return result
	}

	result.PinnedValue = pinnedValue
	result.VersionTag = newTag

	// Verify unless skipped.
	if !opts.SkipVerification {
		pinnedRef := ref
		pinnedRef.Version = pinnedValue
		v, err := strategy.Verify(ctx, pinnedRef)
		if err == nil && v != nil {
			result.Verification = v
			if v.IsForkCommit {
				result.Status = StatusSuspicious
				result.Reason = strings.Join(v.Warnings, "; ")
				return result
			}
		}
	}

	result.Status = StatusUpdated
	return result
}

// shouldExclude reports whether a ref matches any exclude pattern.
//
// Patterns are globs matched with '/' as the path separator: '*' matches
// within a single path segment while '**' matches across segments
// (recursive). Each pattern is tested against both the ref's full
// DisplayName() (owner/repo/subpath) and its repo identity Name (owner/repo).
// Matching the repo identity as well means an org- or repo-level pattern such
// as "temporalio/*" or "temporalio/private-actions" excludes monorepo subpath
// actions like "temporalio/private-actions/golang/setup" — not just top-level
// ones — and "temporalio/**" excludes the whole org at any depth.
func shouldExclude(ref Ref, excludes []string) bool {
	if len(excludes) == 0 {
		return false
	}
	display := ref.DisplayName()
	for _, pattern := range excludes {
		g, err := glob.Compile(pattern, '/')
		if err != nil {
			continue
		}
		if g.Match(display) || (ref.Name != display && g.Match(ref.Name)) {
			return true
		}
	}
	return false
}

// validateExcludePatterns checks that all exclude patterns are valid globs.
// Returns an error for malformed patterns rather than silently ignoring them.
func validateExcludePatterns(patterns []string) error {
	for _, p := range patterns {
		if _, err := glob.Compile(p, '/'); err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", p, err)
		}
	}
	return nil
}

// rootFS extracts a scalibrfs.FS from an os.Root.
func rootFS(root *os.Root) (scalibrfs.FS, error) {
	fsys, ok := root.FS().(scalibrfs.FS)
	if !ok {
		return nil, fmt.Errorf("root filesystem does not implement required interfaces")
	}
	return fsys, nil
}

// computeStats tallies result statuses into the report's Stats.
func computeStats(report *Report) {
	report.Stats = Stats{}
	for _, r := range report.Results {
		report.Stats.Total++
		switch r.Status {
		case StatusPinned:
			report.Stats.Pinned++
		case StatusAlreadyPinned:
			report.Stats.AlreadyPinned++
		case StatusUpdated:
			report.Stats.Updated++
		case StatusUnpinned:
			report.Stats.Unpinned++
		case StatusSkipped:
			report.Stats.Skipped++
		case StatusError:
			report.Stats.Errors++
		case StatusVerified:
			report.Stats.Verified++
		case StatusSuspicious:
			report.Stats.Suspicious++
		}
	}
}
