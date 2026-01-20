package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/sandbox/workspace"
	"github.com/picatz/deputy/internal/ui"
	"golang.org/x/term"
)

// WorkspaceReviewResult indicates what the user decided to do with workspace changes.
type WorkspaceReviewResult int

const (
	// ReviewAccept syncs all changes to the original workspace
	ReviewAccept WorkspaceReviewResult = iota
	// ReviewReject discards all changes
	ReviewReject
	// ReviewSelective allows user to pick which changes to keep
	ReviewSelective
	// ReviewAbort cancels the review without taking action
	ReviewAbort
)

// ReviewWorkspaceChanges displays changes and prompts the user for action.
// Returns the user's decision and any error.
func ReviewWorkspaceChanges(
	ctx context.Context,
	isolator workspace.Isolator,
	stdin io.Reader,
	stdout, stderr io.Writer,
) (WorkspaceReviewResult, error) {
	// Get the list of changes
	changes, err := isolator.Changes(ctx)
	if err != nil {
		return ReviewAbort, fmt.Errorf("failed to get workspace changes: %w", err)
	}

	if len(changes) == 0 {
		fmt.Fprintln(stdout, ui.StyleDim.Render("No workspace changes to review."))
		return ReviewAccept, nil
	}

	// Display header
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, ui.StyleHeader.Render("Workspace Changes"))
	fmt.Fprintln(stdout, ui.StyleDim.Render(strings.Repeat("─", 50)))
	fmt.Fprintln(stdout)

	// Count changes by type
	var added, modified, deleted, renamed int
	for _, change := range changes {
		switch change.Type {
		case "added":
			added++
		case "modified":
			modified++
		case "deleted":
			deleted++
		case "renamed":
			renamed++
		}
	}

	// Display summary
	var summary []string
	if added > 0 {
		summary = append(summary, ui.StyleAdded.Render(fmt.Sprintf("+%d added", added)))
	}
	if modified > 0 {
		summary = append(summary, ui.StyleDowngraded.Render(fmt.Sprintf("~%d modified", modified)))
	}
	if deleted > 0 {
		summary = append(summary, ui.StyleRemoved.Render(fmt.Sprintf("-%d deleted", deleted)))
	}
	if renamed > 0 {
		summary = append(summary, ui.StyleUpgraded.Render(fmt.Sprintf(">%d renamed", renamed)))
	}
	fmt.Fprintln(stdout, strings.Join(summary, "  "))
	fmt.Fprintln(stdout)

	// Display individual changes
	for _, change := range changes {
		displayChange(stdout, change)
	}
	fmt.Fprintln(stdout)

	// Check if stdin is a terminal for interactive prompts
	if f, ok := stdin.(*os.File); ok && !term.IsTerminal(int(f.Fd())) {
		// Non-interactive mode: reject changes by default (safe default)
		fmt.Fprintln(stderr, "Non-interactive mode: discarding workspace changes")
		fmt.Fprintln(stderr, "Use --dangerously-skip-prompt to auto-accept changes")
		return ReviewReject, nil
	}

	// Interactive prompt
	return promptReviewAction(stdin, stdout, stderr, isolator, changes)
}

// ReviewWorkspaceChangesFromEvent handles the review workflow using data from a WorkspaceChangesEvent.
// This is used when receiving changes via streaming (proto-based) rather than direct isolator access.
func ReviewWorkspaceChangesFromEvent(
	ctx context.Context,
	event *sandboxv1.WorkspaceChangesEvent,
	stdin io.Reader,
	stdout, stderr io.Writer,
) (WorkspaceReviewResult, error) {
	if event == nil || len(event.GetChanges()) == 0 {
		fmt.Fprintln(stdout, ui.StyleDim.Render("No workspace changes to review."))
		return ReviewAccept, nil
	}

	// Convert proto changes to workspace.FileChange
	changes := make([]workspace.FileChange, 0, len(event.GetChanges()))
	for _, pc := range event.GetChanges() {
		changes = append(changes, workspace.FileChange{
			Path:    pc.GetPath(),
			Type:    pc.GetChangeType(),
			Size:    pc.GetSize(),
			OldPath: pc.GetOldPath(),
		})
	}

	// Display header
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, ui.StyleHeader.Render("Workspace Changes"))
	fmt.Fprintln(stdout, ui.StyleDim.Render(strings.Repeat("─", 50)))
	fmt.Fprintln(stdout)

	// Count changes by type
	var added, modified, deleted, renamed int
	for _, change := range changes {
		switch change.Type {
		case "added":
			added++
		case "modified":
			modified++
		case "deleted":
			deleted++
		case "renamed":
			renamed++
		}
	}

	// Display summary
	var summary []string
	if added > 0 {
		summary = append(summary, ui.StyleAdded.Render(fmt.Sprintf("+%d added", added)))
	}
	if modified > 0 {
		summary = append(summary, ui.StyleDowngraded.Render(fmt.Sprintf("~%d modified", modified)))
	}
	if deleted > 0 {
		summary = append(summary, ui.StyleRemoved.Render(fmt.Sprintf("-%d deleted", deleted)))
	}
	if renamed > 0 {
		summary = append(summary, ui.StyleUpgraded.Render(fmt.Sprintf(">%d renamed", renamed)))
	}
	fmt.Fprintln(stdout, strings.Join(summary, "  "))
	fmt.Fprintln(stdout)

	// Display individual changes
	for _, change := range changes {
		displayChange(stdout, change)
	}
	fmt.Fprintln(stdout)

	// Check if stdin is a terminal for interactive prompts
	if f, ok := stdin.(*os.File); ok && !term.IsTerminal(int(f.Fd())) {
		// Non-interactive mode: reject changes by default (safe default)
		fmt.Fprintln(stderr, "Non-interactive mode: discarding workspace changes")
		fmt.Fprintln(stderr, "Use --dangerously-skip-prompt to auto-accept changes")
		return ReviewReject, nil
	}

	// Create a path-based adapter for the review prompts
	adapter := &pathBasedReviewer{
		isolatedPath: event.GetIsolatedPath(),
		originalPath: event.GetOriginalPath(),
	}

	// Interactive prompt
	return promptReviewActionFromPaths(stdin, stdout, stderr, adapter, changes)
}

// pathBasedReviewer provides path-based access for review operations.
type pathBasedReviewer struct {
	isolatedPath string
	originalPath string
}

func (p *pathBasedReviewer) IsolatedPath() string { return p.isolatedPath }
func (p *pathBasedReviewer) OriginalPath() string { return p.originalPath }

// SyncChanges copies accepted changes from isolated to original workspace.
func (p *pathBasedReviewer) SyncChanges(changes []workspace.FileChange) error {
	for _, change := range changes {
		srcPath := filepath.Join(p.isolatedPath, change.Path)
		dstPath := filepath.Join(p.originalPath, change.Path)

		switch change.Type {
		case "deleted":
			if err := os.Remove(dstPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("delete %s: %w", change.Path, err)
			}
		case "added", "modified":
			srcInfo, err := os.Stat(srcPath)
			if err != nil {
				return fmt.Errorf("stat %s: %w", change.Path, err)
			}

			if srcInfo.IsDir() {
				if err := os.MkdirAll(dstPath, srcInfo.Mode()); err != nil {
					return fmt.Errorf("mkdir %s: %w", change.Path, err)
				}
			} else {
				// Ensure parent directory exists
				if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
					return fmt.Errorf("mkdir parent of %s: %w", change.Path, err)
				}
				// Copy file
				content, err := os.ReadFile(srcPath)
				if err != nil {
					return fmt.Errorf("read %s: %w", change.Path, err)
				}
				if err := os.WriteFile(dstPath, content, srcInfo.Mode()); err != nil {
					return fmt.Errorf("write %s: %w", change.Path, err)
				}
			}
		case "renamed":
			// For renamed files, delete old and copy new
			oldDstPath := filepath.Join(p.originalPath, change.OldPath)
			if err := os.Remove(oldDstPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("delete old path %s: %w", change.OldPath, err)
			}

			srcInfo, err := os.Stat(srcPath)
			if err != nil {
				return fmt.Errorf("stat %s: %w", change.Path, err)
			}
			if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
				return fmt.Errorf("mkdir parent of %s: %w", change.Path, err)
			}
			content, err := os.ReadFile(srcPath)
			if err != nil {
				return fmt.Errorf("read %s: %w", change.Path, err)
			}
			if err := os.WriteFile(dstPath, content, srcInfo.Mode()); err != nil {
				return fmt.Errorf("write %s: %w", change.Path, err)
			}
		}
	}
	return nil
}

// promptReviewActionFromPaths handles the review menu using path-based access.
func promptReviewActionFromPaths(
	stdin io.Reader,
	stdout, stderr io.Writer,
	reviewer *pathBasedReviewer,
	changes []workspace.FileChange,
) (WorkspaceReviewResult, error) {
	reader := bufio.NewReader(stdin)

	for {
		fmt.Fprintln(stdout, ui.StyleDim.Render(strings.Repeat("─", 50)))
		fmt.Fprintln(stdout, ui.StyleDirect.Render("What would you like to do?"))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  [a] Accept all changes (sync to workspace)")
		fmt.Fprintln(stdout, "  [r] Reject all changes (discard)")
		fmt.Fprintln(stdout, "  [d] Show diff for a specific file")
		fmt.Fprintln(stdout, "  [v] View full diff (opens in $PAGER or less)")
		fmt.Fprintln(stdout, "  [q] Quit without action")
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, ui.StyleDirect.Render("Choice [a/r/d/v/q]: "))

		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return ReviewAbort, nil
			}
			return ReviewAbort, err
		}

		choice := strings.TrimSpace(strings.ToLower(input))
		switch choice {
		case "a", "accept", "y", "yes":
			// Sync changes to original workspace
			if err := reviewer.SyncChanges(changes); err != nil {
				fmt.Fprintf(stderr, "Error syncing changes: %v\n", err)
				return ReviewAbort, err
			}
			fmt.Fprintln(stdout, ui.StyleAdded.Render("Changes synced to workspace successfully."))
			return ReviewAccept, nil
		case "r", "reject", "n", "no":
			fmt.Fprintln(stdout, ui.StyleRemoved.Render("Changes discarded."))
			return ReviewReject, nil
		case "d", "diff":
			if err := showFileDiffFromPaths(stdin, stdout, stderr, reviewer, changes); err != nil {
				fmt.Fprintf(stderr, "Error showing diff: %v\n", err)
			}
		case "v", "view":
			if err := showFullDiffFromPaths(reviewer); err != nil {
				fmt.Fprintf(stderr, "Error showing full diff: %v\n", err)
			}
		case "q", "quit":
			return ReviewAbort, nil
		default:
			fmt.Fprintln(stderr, ui.StyleDim.Render("Invalid choice. Please enter a, r, d, v, or q."))
		}
		fmt.Fprintln(stdout)
	}
}

// showFileDiffFromPaths prompts for a file and shows its diff using path-based access.
func showFileDiffFromPaths(
	stdin io.Reader,
	stdout, stderr io.Writer,
	reviewer *pathBasedReviewer,
	changes []workspace.FileChange,
) error {
	reader := bufio.NewReader(stdin)

	// List files with numbers
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, ui.StyleHeader.Render("Select a file to view diff:"))
	for i, change := range changes {
		displayChange(stdout, change)
		fmt.Fprintf(stdout, "     %s\n", ui.StyleDim.Render(fmt.Sprintf("[%d]", i+1)))
	}
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, ui.StyleDirect.Render("File number (or press Enter to cancel): "))

	input, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var fileNum int
	if _, err := fmt.Sscanf(input, "%d", &fileNum); err != nil || fileNum < 1 || fileNum > len(changes) {
		return fmt.Errorf("invalid file number")
	}

	change := changes[fileNum-1]
	return showDiffForFileFromPaths(stdout, reviewer, change)
}

// showDiffForFileFromPaths displays the diff for a single file using path-based access.
func showDiffForFileFromPaths(out io.Writer, reviewer *pathBasedReviewer, change workspace.FileChange) error {
	originalPath := filepath.Join(reviewer.OriginalPath(), change.Path)
	isolatedPath := filepath.Join(reviewer.IsolatedPath(), change.Path)

	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render(fmt.Sprintf("Diff: %s", change.Path)))
	fmt.Fprintln(out, ui.StyleDim.Render(strings.Repeat("─", 50)))

	switch change.Type {
	case "added":
		// Show the new file content
		content, err := os.ReadFile(isolatedPath)
		if err != nil {
			return fmt.Errorf("read new file: %w", err)
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if i < 50 { // Limit to first 50 lines
				fmt.Fprintln(out, ui.StyleAdded.Render("+ "+line))
			}
		}
		if len(lines) > 50 {
			fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-50)))
		}

	case "deleted":
		// Show the original file content
		content, err := os.ReadFile(originalPath)
		if err != nil {
			return fmt.Errorf("read deleted file: %w", err)
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if i < 50 {
				fmt.Fprintln(out, ui.StyleRemoved.Render("- "+line))
			}
		}
		if len(lines) > 50 {
			fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-50)))
		}

	case "modified":
		// Use diff command if available
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "diff", "-u", originalPath, isolatedPath)
		output, _ := cmd.CombinedOutput()
		if len(output) > 0 {
			lines := strings.Split(string(output), "\n")
			for i, line := range lines {
				if i < 100 {
					if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
						fmt.Fprintln(out, ui.StyleAdded.Render(line))
					} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
						fmt.Fprintln(out, ui.StyleRemoved.Render(line))
					} else if strings.HasPrefix(line, "@@") {
						fmt.Fprintln(out, ui.StyleDowngraded.Render(line))
					} else {
						fmt.Fprintln(out, line)
					}
				}
			}
			if len(lines) > 100 {
				fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-100)))
			}
		}

	case "renamed":
		fmt.Fprintln(out, ui.StyleUpgraded.Render(fmt.Sprintf("Renamed from: %s", change.OldPath)))
		fmt.Fprintln(out, ui.StyleUpgraded.Render(fmt.Sprintf("Renamed to:   %s", change.Path)))
	}

	fmt.Fprintln(out)
	return nil
}

// showFullDiffFromPaths opens the full diff in the user's pager using path-based access.
func showFullDiffFromPaths(reviewer *pathBasedReviewer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate diff
	cmd := exec.CommandContext(ctx, "diff", "-ru", reviewer.OriginalPath(), reviewer.IsolatedPath())
	output, _ := cmd.CombinedOutput()

	if len(output) == 0 {
		return fmt.Errorf("no differences found")
	}

	// Get pager from environment
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less"
	}

	// Create temp file for the diff
	tmpFile, err := os.CreateTemp("", "deputy-diff-*.patch")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(output); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write diff: %w", err)
	}
	tmpFile.Close()

	// Open in pager
	pagerCmd := exec.CommandContext(ctx, pager, tmpFile.Name())
	pagerCmd.Stdin = os.Stdin
	pagerCmd.Stdout = os.Stdout
	pagerCmd.Stderr = os.Stderr

	return pagerCmd.Run()
}

// displayChange formats and displays a single file change.
func displayChange(out io.Writer, change workspace.FileChange) {
	var prefix string
	var style lipgloss.Style

	switch change.Type {
	case "added":
		prefix = "+"
		style = ui.StyleAdded
	case "modified":
		prefix = "~"
		style = ui.StyleDowngraded
	case "deleted":
		prefix = "-"
		style = ui.StyleRemoved
	case "renamed":
		prefix = ">"
		style = ui.StyleUpgraded
	default:
		prefix = "?"
		style = ui.StyleDim
	}

	if change.Type == "renamed" && change.OldPath != "" {
		fmt.Fprintf(out, "  %s %s -> %s\n",
			style.Render(prefix),
			ui.StyleDim.Render(change.OldPath),
			style.Render(change.Path))
	} else {
		sizeInfo := ""
		if change.Size > 0 {
			sizeInfo = ui.StyleDim.Render(fmt.Sprintf(" (%s)", formatFileSize(change.Size)))
		}
		fmt.Fprintf(out, "  %s %s%s\n", style.Render(prefix), style.Render(change.Path), sizeInfo)
	}
}

// promptReviewAction shows the review menu and handles user input.
func promptReviewAction(
	stdin io.Reader,
	stdout, stderr io.Writer,
	isolator workspace.Isolator,
	changes []workspace.FileChange,
) (WorkspaceReviewResult, error) {
	reader := bufio.NewReader(stdin)

	for {
		fmt.Fprintln(stdout, ui.StyleDim.Render(strings.Repeat("─", 50)))
		fmt.Fprintln(stdout, ui.StyleDirect.Render("What would you like to do?"))
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "  [a] Accept all changes (sync to workspace)")
		fmt.Fprintln(stdout, "  [r] Reject all changes (discard)")
		fmt.Fprintln(stdout, "  [d] Show diff for a specific file")
		fmt.Fprintln(stdout, "  [v] View full diff (opens in $PAGER or less)")
		fmt.Fprintln(stdout, "  [q] Quit without action")
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, ui.StyleDirect.Render("Choice [a/r/d/v/q]: "))

		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return ReviewAbort, nil
			}
			return ReviewAbort, err
		}

		choice := strings.TrimSpace(strings.ToLower(input))
		switch choice {
		case "a", "accept", "y", "yes":
			return ReviewAccept, nil
		case "r", "reject", "n", "no":
			return ReviewReject, nil
		case "d", "diff":
			if err := showFileDiff(stdin, stdout, stderr, isolator, changes); err != nil {
				fmt.Fprintf(stderr, "Error showing diff: %v\n", err)
			}
		case "v", "view":
			if err := showFullDiff(isolator); err != nil {
				fmt.Fprintf(stderr, "Error showing full diff: %v\n", err)
			}
		case "q", "quit":
			return ReviewAbort, nil
		default:
			fmt.Fprintln(stderr, ui.StyleDim.Render("Invalid choice. Please enter a, r, d, v, or q."))
		}
		fmt.Fprintln(stdout)
	}
}

// showFileDiff prompts for a file and shows its diff.
func showFileDiff(
	stdin io.Reader,
	stdout, stderr io.Writer,
	isolator workspace.Isolator,
	changes []workspace.FileChange,
) error {
	reader := bufio.NewReader(stdin)

	// List files with numbers
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, ui.StyleHeader.Render("Select a file to view diff:"))
	for i, change := range changes {
		displayChange(stdout, change)
		fmt.Fprintf(stdout, "     %s\n", ui.StyleDim.Render(fmt.Sprintf("[%d]", i+1)))
	}
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, ui.StyleDirect.Render("File number (or press Enter to cancel): "))

	input, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	var fileNum int
	if _, err := fmt.Sscanf(input, "%d", &fileNum); err != nil || fileNum < 1 || fileNum > len(changes) {
		return fmt.Errorf("invalid file number")
	}

	change := changes[fileNum-1]
	return showDiffForFile(stdout, isolator, change)
}

// showDiffForFile displays the diff for a single file.
func showDiffForFile(out io.Writer, isolator workspace.Isolator, change workspace.FileChange) error {
	originalPath := filepath.Join(isolator.OriginalPath(), change.Path)
	isolatedPath := filepath.Join(isolator.IsolatedPath(), change.Path)

	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render(fmt.Sprintf("Diff: %s", change.Path)))
	fmt.Fprintln(out, ui.StyleDim.Render(strings.Repeat("─", 50)))

	switch change.Type {
	case "added":
		// Show the new file content
		content, err := os.ReadFile(isolatedPath)
		if err != nil {
			return fmt.Errorf("read new file: %w", err)
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if i < 50 { // Limit to first 50 lines
				fmt.Fprintln(out, ui.StyleAdded.Render("+ "+line))
			}
		}
		if len(lines) > 50 {
			fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-50)))
		}

	case "deleted":
		// Show the original file content
		content, err := os.ReadFile(originalPath)
		if err != nil {
			return fmt.Errorf("read deleted file: %w", err)
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if i < 50 {
				fmt.Fprintln(out, ui.StyleRemoved.Render("- "+line))
			}
		}
		if len(lines) > 50 {
			fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-50)))
		}

	case "modified":
		// Use diff command if available
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "diff", "-u", originalPath, isolatedPath)
		output, _ := cmd.CombinedOutput()
		if len(output) > 0 {
			lines := strings.Split(string(output), "\n")
			for i, line := range lines {
				if i < 100 {
					if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
						fmt.Fprintln(out, ui.StyleAdded.Render(line))
					} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
						fmt.Fprintln(out, ui.StyleRemoved.Render(line))
					} else if strings.HasPrefix(line, "@@") {
						fmt.Fprintln(out, ui.StyleDowngraded.Render(line))
					} else {
						fmt.Fprintln(out, line)
					}
				}
			}
			if len(lines) > 100 {
				fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-100)))
			}
		}

	case "renamed":
		fmt.Fprintln(out, ui.StyleUpgraded.Render(fmt.Sprintf("Renamed from: %s", change.OldPath)))
		fmt.Fprintln(out, ui.StyleUpgraded.Render(fmt.Sprintf("Renamed to:   %s", change.Path)))
	}

	fmt.Fprintln(out)
	return nil
}

// showFullDiff opens the full diff in the user's pager.
func showFullDiff(isolator workspace.Isolator) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate diff
	cmd := exec.CommandContext(ctx, "diff", "-ru", isolator.OriginalPath(), isolator.IsolatedPath())
	output, _ := cmd.CombinedOutput()

	if len(output) == 0 {
		return fmt.Errorf("no differences found")
	}

	// Get pager from environment
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less"
	}

	// Create temp file for the diff
	tmpFile, err := os.CreateTemp("", "deputy-diff-*.patch")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(output); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write diff: %w", err)
	}
	tmpFile.Close()

	// Open in pager
	pagerCmd := exec.CommandContext(ctx, pager, tmpFile.Name())
	pagerCmd.Stdin = os.Stdin
	pagerCmd.Stdout = os.Stdout
	pagerCmd.Stderr = os.Stderr

	return pagerCmd.Run()
}

// formatFileSize formats a file size in human-readable format.
func formatFileSize(size int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(gb))
	case size >= mb:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
	case size >= kb:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(kb))
	default:
		return fmt.Sprintf("%d B", size)
	}
}
