// Package workspace provides post-execution review workflows for sandbox isolation.
package workspace

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// ReviewResult represents the outcome of a user's review decision.
type ReviewResult int

const (
	// ReviewResultPending means no decision has been made yet.
	ReviewResultPending ReviewResult = iota
	// ReviewResultApplyAll applies all changes to the original workspace.
	ReviewResultApplyAll
	// ReviewResultApplySelected applies only selected changes.
	ReviewResultApplySelected
	// ReviewResultDiscard discards all changes.
	ReviewResultDiscard
	// ReviewResultPreserve keeps the isolated workspace for manual review.
	ReviewResultPreserve
)

// ReviewSession manages the post-execution review workflow.
// It allows users to inspect changes, selectively apply them, or discard everything.
type ReviewSession struct {
	isolator       Isolator
	changes        []FileChange
	selectedPaths  map[string]bool
	result         ReviewResult
	preservedPath  string
	diffGenerator  DiffGenerator
}

// DiffGenerator generates diff output for file changes.
type DiffGenerator interface {
	// GenerateDiff creates a unified diff between original and modified files.
	GenerateDiff(originalPath, modifiedPath string) (string, error)
}

// NewReviewSession creates a new review session for an isolator.
func NewReviewSession(isolator Isolator) *ReviewSession {
	return &ReviewSession{
		isolator:      isolator,
		selectedPaths: make(map[string]bool),
		result:        ReviewResultPending,
	}
}

// WithDiffGenerator sets a custom diff generator.
func (r *ReviewSession) WithDiffGenerator(gen DiffGenerator) *ReviewSession {
	r.diffGenerator = gen
	return r
}

// LoadChanges detects all changes in the isolated workspace.
func (r *ReviewSession) LoadChanges(ctx context.Context) error {
	changes, err := r.isolator.Changes(ctx)
	if err != nil {
		return fmt.Errorf("detect changes: %w", err)
	}
	r.changes = changes

	// By default, select all changes
	for _, c := range changes {
		r.selectedPaths[c.Path] = true
	}

	return nil
}

// Changes returns the detected file changes.
func (r *ReviewSession) Changes() []FileChange {
	return r.changes
}

// HasChanges returns true if there are any changes to review.
func (r *ReviewSession) HasChanges() bool {
	return len(r.changes) > 0
}

// Summary returns a summary of changes by type.
func (r *ReviewSession) Summary() ChangeSummary {
	summary := ChangeSummary{}
	for _, c := range r.changes {
		switch c.Type {
		case "added":
			summary.Added++
		case "modified":
			summary.Modified++
		case "deleted":
			summary.Deleted++
		}
	}
	summary.Total = len(r.changes)
	summary.Selected = r.SelectedCount()
	return summary
}

// ChangeSummary provides a summary of changes.
type ChangeSummary struct {
	Added    int
	Modified int
	Deleted  int
	Total    int
	Selected int
}

// SelectPath marks a path as selected for application.
func (r *ReviewSession) SelectPath(path string) {
	r.selectedPaths[path] = true
}

// DeselectPath marks a path as not selected.
func (r *ReviewSession) DeselectPath(path string) {
	r.selectedPaths[path] = false
}

// TogglePath toggles the selection state of a path.
func (r *ReviewSession) TogglePath(path string) {
	r.selectedPaths[path] = !r.selectedPaths[path]
}

// IsSelected returns true if a path is selected.
func (r *ReviewSession) IsSelected(path string) bool {
	return r.selectedPaths[path]
}

// SelectAll selects all changes.
func (r *ReviewSession) SelectAll() {
	for _, c := range r.changes {
		r.selectedPaths[c.Path] = true
	}
}

// DeselectAll deselects all changes.
func (r *ReviewSession) DeselectAll() {
	for _, c := range r.changes {
		r.selectedPaths[c.Path] = false
	}
}

// SelectedCount returns the number of selected changes.
func (r *ReviewSession) SelectedCount() int {
	count := 0
	for _, selected := range r.selectedPaths {
		if selected {
			count++
		}
	}
	return count
}

// SelectedChanges returns only the selected changes.
func (r *ReviewSession) SelectedChanges() []FileChange {
	var selected []FileChange
	for _, c := range r.changes {
		if r.selectedPaths[c.Path] {
			selected = append(selected, c)
		}
	}
	return selected
}

// GetDiff returns the diff for a specific file change.
func (r *ReviewSession) GetDiff(change FileChange) (string, error) {
	originalPath := filepath.Join(r.isolator.OriginalPath(), change.Path)
	isolatedPath := filepath.Join(r.isolator.IsolatedPath(), change.Path)

	switch change.Type {
	case "added":
		// Show full content of new file
		content, err := os.ReadFile(isolatedPath)
		if err != nil {
			return "", err
		}
		return formatNewFileDiff(change.Path, string(content)), nil

	case "deleted":
		// Show full content of deleted file
		content, err := os.ReadFile(originalPath)
		if err != nil {
			return "", err
		}
		return formatDeletedFileDiff(change.Path, string(content)), nil

	case "modified":
		if r.diffGenerator != nil {
			return r.diffGenerator.GenerateDiff(originalPath, isolatedPath)
		}
		return generateSimpleDiff(originalPath, isolatedPath)
	}

	return "", fmt.Errorf("unknown change type: %s", change.Type)
}

// formatNewFileDiff formats a new file as a unified diff.
func formatNewFileDiff(path, content string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- /dev/null\n"))
	sb.WriteString(fmt.Sprintf("+++ b/%s\n", path))
	sb.WriteString("@@ -0,0 +1 @@\n")
	for _, line := range strings.Split(content, "\n") {
		sb.WriteString("+" + line + "\n")
	}
	return sb.String()
}

// formatDeletedFileDiff formats a deleted file as a unified diff.
func formatDeletedFileDiff(path, content string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- a/%s\n", path))
	sb.WriteString(fmt.Sprintf("+++ /dev/null\n"))
	sb.WriteString("@@ -1 +0,0 @@\n")
	for _, line := range strings.Split(content, "\n") {
		sb.WriteString("-" + line + "\n")
	}
	return sb.String()
}

// generateSimpleDiff creates a simple diff between two files.
func generateSimpleDiff(originalPath, modifiedPath string) (string, error) {
	original, err := os.ReadFile(originalPath)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	modified, err := os.ReadFile(modifiedPath)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	// For now, just show before/after content
	// A proper implementation would use a diff algorithm
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- a/%s\n", filepath.Base(originalPath)))
	sb.WriteString(fmt.Sprintf("+++ b/%s\n", filepath.Base(modifiedPath)))
	sb.WriteString("@@ modified @@\n")

	origLines := strings.Split(string(original), "\n")
	modLines := strings.Split(string(modified), "\n")

	// Simple line-by-line comparison
	maxLines := len(origLines)
	if len(modLines) > maxLines {
		maxLines = len(modLines)
	}

	for i := 0; i < maxLines; i++ {
		origLine := ""
		modLine := ""
		if i < len(origLines) {
			origLine = origLines[i]
		}
		if i < len(modLines) {
			modLine = modLines[i]
		}

		if origLine != modLine {
			if origLine != "" {
				sb.WriteString("-" + origLine + "\n")
			}
			if modLine != "" {
				sb.WriteString("+" + modLine + "\n")
			}
		} else {
			sb.WriteString(" " + origLine + "\n")
		}
	}

	return sb.String(), nil
}

// ApplySelected applies only selected changes to the original workspace.
func (r *ReviewSession) ApplySelected(ctx context.Context) error {
	var selectedPatterns []string
	for path, selected := range r.selectedPaths {
		if selected {
			selectedPatterns = append(selectedPatterns, path)
		}
	}

	if len(selectedPatterns) == 0 {
		r.result = ReviewResultDiscard
		return nil
	}

	if err := r.isolator.Sync(ctx, selectedPatterns, nil); err != nil {
		return fmt.Errorf("apply changes: %w", err)
	}

	r.result = ReviewResultApplySelected
	return nil
}

// ApplyAll applies all changes to the original workspace.
func (r *ReviewSession) ApplyAll(ctx context.Context) error {
	if err := r.isolator.Sync(ctx, nil, nil); err != nil {
		return fmt.Errorf("apply all changes: %w", err)
	}
	r.result = ReviewResultApplyAll
	return nil
}

// Discard discards all changes and cleans up.
func (r *ReviewSession) Discard(ctx context.Context) error {
	r.result = ReviewResultDiscard
	return r.isolator.Teardown(ctx, false)
}

// Preserve keeps the isolated workspace for manual review.
func (r *ReviewSession) Preserve() string {
	r.result = ReviewResultPreserve
	r.preservedPath = r.isolator.IsolatedPath()
	return r.preservedPath
}

// Result returns the review result.
func (r *ReviewSession) Result() ReviewResult {
	return r.result
}

// PreservedPath returns the path to the preserved workspace (if preserved).
func (r *ReviewSession) PreservedPath() string {
	return r.preservedPath
}

// PrintChanges prints the list of changes to a writer.
func (r *ReviewSession) PrintChanges(w io.Writer) {
	if !r.HasChanges() {
		fmt.Fprintln(w, "No changes detected.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tTYPE\tPATH")
	fmt.Fprintln(tw, "------\t----\t----")

	for _, c := range r.changes {
		status := "[ ]"
		if r.selectedPaths[c.Path] {
			status = "[x]"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", status, c.Type, c.Path)
	}
	tw.Flush()

	summary := r.Summary()
	fmt.Fprintf(w, "\nTotal: %d changes (%d added, %d modified, %d deleted)\n",
		summary.Total, summary.Added, summary.Modified, summary.Deleted)
	fmt.Fprintf(w, "Selected: %d/%d\n", summary.Selected, summary.Total)
}

// ReviewOptions configures the review workflow.
type ReviewOptions struct {
	// AutoApply automatically applies changes without prompting.
	AutoApply bool

	// AutoDiscard automatically discards changes without prompting.
	AutoDiscard bool

	// PreserveOnError keeps the workspace if an error occurs.
	PreserveOnError bool

	// ShowDiffs shows diffs for each changed file.
	ShowDiffs bool

	// MaxDiffLines limits the number of diff lines shown per file.
	MaxDiffLines int

	// FilterPatterns only shows changes matching these patterns.
	FilterPatterns []string
}

// DefaultReviewOptions returns sensible defaults for review.
func DefaultReviewOptions() ReviewOptions {
	return ReviewOptions{
		ShowDiffs:    true,
		MaxDiffLines: 50,
	}
}

// AgentReviewOptions returns options suitable for AI agent workflows.
// These preserve the workspace by default for human review.
func AgentReviewOptions() ReviewOptions {
	return ReviewOptions{
		ShowDiffs:       true,
		MaxDiffLines:    100,
		PreserveOnError: true,
	}
}
