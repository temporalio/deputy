package secrets

import (
	"context"
	"time"
)

// HistoryFinding extends Finding with git history context for proto conversion.
// This wraps HistoricalFinding with simpler field names.
type HistoryFinding struct {
	Finding

	// CommitHash where the secret was introduced.
	CommitHash string
	// Author of the commit.
	Author string
	// AuthorEmail of the commit author.
	AuthorEmail string
	// CommitDate when the secret was introduced.
	CommitDate string
	// CommitMessage summary.
	CommitMessage string
	// RemovedIn is the commit where the secret was removed (empty if still present).
	RemovedIn string
	// StillPresent indicates if the secret exists in HEAD.
	StillPresent bool
}

// GitHistoryOptions configures git history scanning.
type GitHistoryOptions struct {
	MaxCommits     int
	Since          string
	Until          string
	Branch         string
	IncludeRemoved bool
}

// ScanGitHistory scans git history for secrets.
func ScanGitHistory(ctx context.Context, repoPath string, opts GitHistoryOptions) ([]HistoryFinding, error) {
	config := HistoryScanConfig{
		MaxCommits:     opts.MaxCommits,
		Branch:         opts.Branch,
		IncludeRemoved: opts.IncludeRemoved,
	}

	// Parse time bounds
	if opts.Since != "" {
		t, err := time.Parse(time.RFC3339, opts.Since)
		if err == nil {
			config.Since = &t
		}
	}
	if opts.Until != "" {
		t, err := time.Parse(time.RFC3339, opts.Until)
		if err == nil {
			config.Until = &t
		}
	}

	scanner, err := NewHistoryScanner(config)
	if err != nil {
		return nil, err
	}

	result, err := scanner.ScanRepository(ctx, repoPath)
	if err != nil {
		return nil, err
	}

	// Convert to simpler HistoryFinding type
	findings := make([]HistoryFinding, 0, len(result.Findings))
	for _, hf := range result.Findings {
		f := HistoryFinding{
			Finding:      hf.Finding,
			StillPresent: hf.StillPresent,
		}

		if hf.IntroducedIn != nil {
			f.CommitHash = hf.IntroducedIn.Hash
			f.Author = hf.IntroducedIn.Author
			f.AuthorEmail = hf.IntroducedIn.Email
			f.CommitDate = hf.IntroducedIn.Date.Format(time.RFC3339)
			f.CommitMessage = hf.IntroducedIn.Message
		}

		if hf.RemovedIn != nil {
			f.RemovedIn = hf.RemovedIn.Hash
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// DiffResult contains the result of a git diff scan.
type DiffResult struct {
	// Added are secrets introduced in the target ref.
	Added []Finding
	// Removed are secrets present in base ref but not target ref.
	Removed []Finding
}

// ScanGitDiff scans changes between two git refs for secrets.
func ScanGitDiff(ctx context.Context, repoPath, baseRef, targetRef string) (*DiffResult, error) {
	scanner, err := NewHistoryScanner(HistoryScanConfig{})
	if err != nil {
		return nil, err
	}

	// Get new secrets in target ref
	newSecrets, err := scanner.ScanDiff(ctx, repoPath, baseRef, targetRef)
	if err != nil {
		return nil, err
	}

	// Get removed secrets (reverse diff)
	removedSecrets, err := scanner.ScanDiff(ctx, repoPath, targetRef, baseRef)
	if err != nil {
		return nil, err
	}

	return &DiffResult{
		Added:   newSecrets,
		Removed: removedSecrets,
	}, nil
}

// ContainerScanOptions configures container secret scanning.
type ContainerScanOptions struct {
	Deep     bool
	Platform string
}

// ScanContainerImage scans a container image for secrets.
func ScanContainerImage(ctx context.Context, ref string, opts ContainerScanOptions) ([]Finding, []string, error) {
	config := DefaultContainerScanConfig()
	config.ScanLayers = opts.Deep

	scanner, err := NewContainerScanner(config)
	if err != nil {
		return nil, nil, err
	}

	// For now, we return a placeholder - full implementation would use
	// go-containerregistry to fetch and scan the image
	// This is a simplified version that can be expanded
	_ = scanner

	// Return empty for now - full implementation requires image fetching
	var warnings []string
	warnings = append(warnings, "container image scanning requires additional implementation")

	return nil, warnings, nil
}

// VerifyOptions configures secret verification.
type VerifyOptions struct {
	RateLimit int
	Timeout   time.Duration
}

// VerifyFindings attempts to validate detected secrets.
func VerifyFindings(ctx context.Context, findings []Finding, opts VerifyOptions) ([]Finding, error) {
	cfg := &VerificationConfig{
		RateLimit: opts.RateLimit,
		Timeout:   opts.Timeout,
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	engine := NewVerificationEngine(cfg)
	results := engine.VerifyBatch(ctx, findings)

	// Update findings with verification results
	verified := make([]Finding, len(findings))
	for i, f := range findings {
		verified[i] = f
		if result, ok := results[i]; ok {
			verified[i].Validated = result.Status == StatusValid
		}
	}

	return verified, nil
}
