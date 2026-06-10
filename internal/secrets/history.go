package secrets

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// HistoricalFinding extends Finding with git history context.
type HistoricalFinding struct {
	Finding

	// IntroducedIn is the commit that first introduced this secret.
	IntroducedIn *CommitInfo `json:"introducedIn,omitempty"`
	// RemovedIn is the commit that removed this secret (nil if still present).
	RemovedIn *CommitInfo `json:"removedIn,omitempty"`
	// StillPresent indicates if the secret exists in the current HEAD.
	StillPresent bool `json:"stillPresent"`
	// CommitCount is how many commits contained this secret.
	CommitCount int `json:"commitCount"`
	// Authors is the list of commit authors who touched this secret.
	Authors []string `json:"authors,omitempty"`
	// Age is how long the secret has existed (from introduction to now or removal).
	Age time.Duration `json:"age,omitempty"`
}

// CommitInfo contains metadata about a git commit.
type CommitInfo struct {
	Hash      string    `json:"hash"`
	ShortHash string    `json:"shortHash"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Message   string    `json:"message"`
	Date      time.Time `json:"date"`
}

// HistoryScanConfig configures historical secret scanning.
type HistoryScanConfig struct {
	// MaxCommits limits how many commits to scan (0 = all).
	MaxCommits int
	// Since only scans commits after this time.
	Since *time.Time
	// Until only scans commits before this time.
	Until *time.Time
	// Branch specifies which branch to scan (default: HEAD).
	Branch string
	// IncludeRemoved includes secrets that were later removed.
	IncludeRemoved bool
	// PathFilter limits scanning to specific paths.
	PathFilter []string
}

// HistoryScanResult contains the results of a historical secret scan.
type HistoryScanResult struct {
	// Repository is the path to the scanned repository.
	Repository string `json:"repository"`
	// Branch is the branch that was scanned.
	Branch string `json:"branch"`
	// CommitsScanned is the total number of commits analyzed.
	CommitsScanned int `json:"commitsScanned"`
	// Findings contains all historical secret findings.
	Findings []HistoricalFinding `json:"findings"`
	// Stats provides aggregate statistics.
	Stats HistoryStats `json:"stats"`
	// ScannedAt is when the scan was performed.
	ScannedAt time.Time `json:"scannedAt"`
}

// HistoryStats provides aggregate statistics for historical findings.
type HistoryStats struct {
	// TotalSecrets is the total unique secrets found across all commits.
	TotalSecrets int `json:"totalSecrets"`
	// ActiveSecrets is secrets still present in HEAD.
	ActiveSecrets int `json:"activeSecrets"`
	// RemovedSecrets is secrets that were later removed.
	RemovedSecrets int `json:"removedSecrets"`
	// ByType breaks down secrets by type.
	ByType map[SecretType]int `json:"byType"`
	// OldestSecret is the age of the oldest secret.
	OldestSecret time.Duration `json:"oldestSecret,omitempty"`
	// AuthorsWithSecrets lists authors who committed secrets.
	AuthorsWithSecrets []string `json:"authorsWithSecrets,omitempty"`
}

// HistoryScanner scans git history for secrets.
type HistoryScanner struct {
	engine *Engine
	config HistoryScanConfig
}

// NewHistoryScanner creates a new git history scanner.
func NewHistoryScanner(config HistoryScanConfig) (*HistoryScanner, error) {
	engine, err := NewEngine()
	if err != nil {
		return nil, err
	}
	return &HistoryScanner{
		engine: engine,
		config: config,
	}, nil
}

// ScanRepository scans a git repository's history for secrets.
func (h *HistoryScanner) ScanRepository(ctx context.Context, repoPath string) (*HistoryScanResult, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	// Determine starting point
	var startRef plumbing.Hash
	if h.config.Branch != "" {
		ref, err := repo.Reference(plumbing.NewBranchReferenceName(h.config.Branch), true)
		if err != nil {
			return nil, err
		}
		startRef = ref.Hash()
	} else {
		head, err := repo.Head()
		if err != nil {
			return nil, err
		}
		startRef = head.Hash()
	}

	// Track secrets across commits: value -> finding info
	secretTracker := make(map[string]*secretHistory)

	// Walk commit history
	commitIter, err := repo.Log(&git.LogOptions{
		From:  startRef,
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, err
	}

	commitsScanned := 0
	err = commitIter.ForEach(func(commit *object.Commit) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check commit limits
		if h.config.MaxCommits > 0 && commitsScanned >= h.config.MaxCommits {
			return nil // Stop iteration (not an error)
		}

		// Check time bounds
		if h.config.Since != nil && commit.Committer.When.Before(*h.config.Since) {
			return nil // Skip old commits
		}
		if h.config.Until != nil && commit.Committer.When.After(*h.config.Until) {
			return nil // Skip future commits
		}

		commitInfo := &CommitInfo{
			Hash:      commit.Hash.String(),
			ShortHash: commit.Hash.String()[:7],
			Author:    commit.Author.Name,
			Email:     commit.Author.Email,
			Message:   firstLine(commit.Message),
			Date:      commit.Committer.When,
		}

		// Scan files in this commit
		tree, err := commit.Tree()
		if err != nil {
			return nil // Skip problematic commits
		}

		err = tree.Files().ForEach(func(f *object.File) error {
			// Apply path filter
			if len(h.config.PathFilter) > 0 && !matchesPathFilter(f.Name, h.config.PathFilter) {
				return nil
			}

			// Skip binary files
			if isBinaryFile(f.Name) {
				return nil
			}

			// Read file content
			content, err := f.Contents()
			if err != nil {
				return nil
			}

			// Scan for secrets
			findings, err := h.engine.ScanFile(ctx, f.Name, []byte(content))
			if err != nil {
				return nil
			}

			// Track each finding
			for _, finding := range findings {
				key := secretKey(finding)
				if existing, ok := secretTracker[key]; ok {
					// Secret seen before, update history
					existing.lastSeen = commitInfo
					existing.commitCount++
					existing.addAuthor(commitInfo.Author)
				} else {
					// New secret found
					secretTracker[key] = &secretHistory{
						finding:     finding,
						firstSeen:   commitInfo,
						lastSeen:    commitInfo,
						commitCount: 1,
						authors:     []string{commitInfo.Author},
					}
				}
			}

			return nil
		})

		commitsScanned++
		return err
	})

	if err != nil && err != io.EOF {
		return nil, err
	}

	// Check which secrets are still present in HEAD
	headFindings, _ := h.scanHead(ctx, repo, startRef)
	headSecrets := make(map[string]bool)
	for _, f := range headFindings {
		headSecrets[secretKey(f)] = true
	}

	// Build results
	result := &HistoryScanResult{
		Repository:     repoPath,
		Branch:         h.config.Branch,
		CommitsScanned: commitsScanned,
		ScannedAt:      time.Now().UTC(),
		Stats: HistoryStats{
			ByType: make(map[SecretType]int),
		},
	}

	authorSet := make(map[string]bool)
	for key, history := range secretTracker {
		stillPresent := headSecrets[key]

		// Skip removed secrets if not requested
		if !stillPresent && !h.config.IncludeRemoved {
			continue
		}

		var removedIn *CommitInfo
		if !stillPresent {
			removedIn = history.lastSeen // Approximate: last commit where it was seen
		}

		age := time.Since(history.firstSeen.Date)
		if removedIn != nil {
			age = removedIn.Date.Sub(history.firstSeen.Date)
		}

		hf := HistoricalFinding{
			Finding:      history.finding,
			IntroducedIn: history.firstSeen,
			RemovedIn:    removedIn,
			StillPresent: stillPresent,
			CommitCount:  history.commitCount,
			Authors:      history.authors,
			Age:          age,
		}
		result.Findings = append(result.Findings, hf)

		// Update stats
		result.Stats.TotalSecrets++
		result.Stats.ByType[history.finding.Type]++
		if stillPresent {
			result.Stats.ActiveSecrets++
		} else {
			result.Stats.RemovedSecrets++
		}
		if age > result.Stats.OldestSecret {
			result.Stats.OldestSecret = age
		}
		for _, author := range history.authors {
			authorSet[author] = true
		}
	}

	for author := range authorSet {
		result.Stats.AuthorsWithSecrets = append(result.Stats.AuthorsWithSecrets, author)
	}

	return result, nil
}

// scanHead scans the HEAD commit for secrets.
func (h *HistoryScanner) scanHead(ctx context.Context, repo *git.Repository, head plumbing.Hash) ([]Finding, error) {
	commit, err := repo.CommitObject(head)
	if err != nil {
		return nil, err
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	var findings []Finding
	err = tree.Files().ForEach(func(f *object.File) error {
		if isBinaryFile(f.Name) {
			return nil
		}
		content, err := f.Contents()
		if err != nil {
			return nil
		}
		fileFindings, err := h.engine.ScanFile(ctx, f.Name, []byte(content))
		if err != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

// secretHistory tracks a secret across commits.
type secretHistory struct {
	finding     Finding
	firstSeen   *CommitInfo
	lastSeen    *CommitInfo
	commitCount int
	authors     []string
}

func (s *secretHistory) addAuthor(author string) {
	if slices.Contains(s.authors, author) {
		return
	}
	s.authors = append(s.authors, author)
}

// secretKey generates a unique key for a secret finding.
func secretKey(f Finding) string {
	// Use value hash + file + type as key
	return string(f.Type) + ":" + f.File + ":" + f.Redacted
}

// firstLine returns the first line of a string.
func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

// matchesPathFilter checks if a path matches any filter pattern.
func matchesPathFilter(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

// isBinaryFile checks if a file is likely binary based on extension.
func isBinaryFile(name string) bool {
	binaryExts := []string{
		".exe", ".dll", ".so", ".dylib", ".bin",
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
		".mp3", ".mp4", ".avi", ".mov", ".wav",
		".wasm", ".pyc", ".class", ".o", ".a",
	}
	ext := strings.ToLower(filepath.Ext(name))
	return slices.Contains(binaryExts, ext)
}

// ScanDiff scans the diff between two git refs for new secrets.
func (h *HistoryScanner) ScanDiff(ctx context.Context, repoPath, baseRef, headRef string) ([]Finding, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	// Get base commit
	baseHash, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		return nil, err
	}
	baseCommit, err := repo.CommitObject(*baseHash)
	if err != nil {
		return nil, err
	}
	baseTree, err := baseCommit.Tree()
	if err != nil {
		return nil, err
	}

	// Get head commit
	headHash, err := repo.ResolveRevision(plumbing.Revision(headRef))
	if err != nil {
		return nil, err
	}
	headCommit, err := repo.CommitObject(*headHash)
	if err != nil {
		return nil, err
	}
	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, err
	}

	// Get diff
	changes, err := baseTree.Diff(headTree)
	if err != nil {
		return nil, err
	}

	var newFindings []Finding
	for _, change := range changes {
		// Only check added or modified files
		if change.To.Name == "" {
			continue // Deleted file
		}

		// Get new file content
		file, err := headTree.File(change.To.Name)
		if err != nil {
			continue
		}

		if isBinaryFile(file.Name) {
			continue
		}

		newContent, err := file.Contents()
		if err != nil {
			continue
		}

		// Scan new content
		newSecrets, err := h.engine.ScanFile(ctx, file.Name, []byte(newContent))
		if err != nil {
			continue
		}

		// If file existed before, check which secrets are new
		if change.From.Name != "" {
			oldFile, err := baseTree.File(change.From.Name)
			if err == nil {
				oldContent, err := oldFile.Contents()
				if err == nil {
					oldSecrets, _ := h.engine.ScanFile(ctx, oldFile.Name, []byte(oldContent))
					oldSet := make(map[string]bool)
					for _, s := range oldSecrets {
						oldSet[secretKey(s)] = true
					}
					// Only keep truly new secrets
					for _, s := range newSecrets {
						if !oldSet[secretKey(s)] {
							newFindings = append(newFindings, s)
						}
					}
					continue
				}
			}
		}

		// New file, all secrets are new
		newFindings = append(newFindings, newSecrets...)
	}

	return newFindings, nil
}

// DetectLeakedSecretInContent checks if content contains a leaked secret from repo history.
func DetectLeakedSecretInContent(content []byte, historicalFindings []HistoricalFinding) []HistoricalFinding {
	var leaked []HistoricalFinding
	for _, hf := range historicalFindings {
		if hf.Finding.Value != "" && bytes.Contains(content, []byte(hf.Finding.Value)) {
			leaked = append(leaked, hf)
		}
	}
	return leaked
}
