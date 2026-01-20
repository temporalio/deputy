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
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/sandbox/workspace"
	"github.com/picatz/deputy/internal/ui"
	"golang.org/x/term"
)

// getTerminalWidth returns the current terminal width, or a sensible default.
func getTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil && width > 0 {
		return width
	}
	return 80 // sensible default
}

// minInt returns the smaller of two integers.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// truncatePath shortens a path to fit within maxLen, preserving the filename.
func truncatePath(path string, maxLen int) string {
	if utf8.RuneCountInString(path) <= maxLen {
		return path
	}

	// Keep the filename and as much of the path as possible
	dir, file := filepath.Split(path)
	if utf8.RuneCountInString(file) >= maxLen-4 {
		// Filename alone is too long, truncate it
		runes := []rune(file)
		return "..." + string(runes[len(runes)-maxLen+3:])
	}

	// Truncate directory part
	remaining := maxLen - utf8.RuneCountInString(file) - 4 // ".../"
	if remaining < 1 {
		return file
	}

	dirRunes := []rune(dir)
	if len(dirRunes) > remaining {
		return ".../" + string(dirRunes[len(dirRunes)-remaining:]) + file
	}
	return path
}

// dependencyManifests maps filename patterns to their ecosystem names.
// These are files that, when modified, indicate dependency changes.
var dependencyManifests = map[string]string{
	// Go
	"go.mod": "go",
	"go.sum": "go",
	// Node.js / npm / yarn / pnpm
	"package.json":      "npm",
	"package-lock.json": "npm",
	"yarn.lock":         "npm",
	"pnpm-lock.yaml":    "npm",
	// Python
	"requirements.txt":      "pypi",
	"Pipfile":               "pypi",
	"Pipfile.lock":          "pypi",
	"pyproject.toml":        "pypi",
	"poetry.lock":           "pypi",
	"setup.py":              "pypi",
	"setup.cfg":             "pypi",
	"conda-environment.yml": "conda",
	// Rust
	"Cargo.toml": "cargo",
	"Cargo.lock": "cargo",
	// Ruby
	"Gemfile":      "rubygems",
	"Gemfile.lock": "rubygems",
	// Java / Maven / Gradle
	"pom.xml":           "maven",
	"build.gradle":      "maven",
	"build.gradle.kts":  "maven",
	"gradle.lockfile":   "maven",
	"settings.gradle":   "maven",
	// .NET / NuGet
	"*.csproj":        "nuget",
	"packages.config": "nuget",
	"*.fsproj":        "nuget",
	// PHP
	"composer.json": "packagist",
	"composer.lock": "packagist",
}

// isDependencyManifest checks if a file path is a known dependency manifest.
func isDependencyManifest(path string) (ecosystem string, ok bool) {
	filename := filepath.Base(path)
	if eco, found := dependencyManifests[filename]; found {
		return eco, true
	}
	// Check pattern matches (e.g., *.csproj)
	for pattern, eco := range dependencyManifests {
		if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
			if strings.HasSuffix(filename, suffix) {
				return eco, true
			}
		}
	}
	return "", false
}

// DependencyDiff represents the semantic difference in dependencies.
type DependencyDiff struct {
	Ecosystems map[string]bool    // ecosystems with changes
	Changes    []compare.Change   // semantic dependency changes
	Error      error              // error during diff (non-fatal)
}

// hasDependencyChanges checks if any file changes affect dependency manifests.
func hasDependencyChanges(changes []workspace.FileChange) (ecosystems map[string]bool) {
	ecosystems = make(map[string]bool)
	for _, change := range changes {
		if eco, ok := isDependencyManifest(change.Path); ok {
			ecosystems[eco] = true
		}
	}
	return ecosystems
}

// computeDependencyDiff extracts and compares dependencies between original and isolated workspaces.
// This is best-effort: errors are captured but don't block the review.
// The context should be used for cancellation (e.g., Ctrl+C); no internal timeout is imposed.
func computeDependencyDiff(ctx context.Context, originalPath, isolatedPath string) *DependencyDiff {
	result := &DependencyDiff{
		Ecosystems: make(map[string]bool),
	}

	// Extract packages from original workspace
	oldExec, err := inventory.CollectDirectory(ctx, originalPath, inventory.Options{})
	if err != nil {
		result.Error = fmt.Errorf("original workspace: %w", err)
		return result
	}
	defer oldExec.Close()

	// Check for context cancellation
	if ctx.Err() != nil {
		result.Error = ctx.Err()
		return result
	}

	// Extract packages from isolated (modified) workspace
	newExec, err := inventory.CollectDirectory(ctx, isolatedPath, inventory.Options{})
	if err != nil {
		result.Error = fmt.Errorf("isolated workspace: %w", err)
		return result
	}
	defer newExec.Close()

	// Compare packages
	changes := compare.ComparePackages(
		oldExec.Result.Packages,
		newExec.Result.Packages,
		oldExec.Result.Direct,
		newExec.Result.Direct,
		newExec.Workspace,
	)

	result.Changes = changes

	// Track which ecosystems have changes
	for _, change := range changes {
		if change.Ecosystem != "" {
			result.Ecosystems[change.Ecosystem] = true
		}
	}

	return result
}

// renderDependencyDiff displays the semantic dependency changes.
func renderDependencyDiff(out io.Writer, diff *DependencyDiff, termWidth int) {
	if diff == nil {
		return
	}

	lineWidth := minInt(termWidth-2, 80)

	// If there was an error, show it as a warning but continue
	if diff.Error != nil {
		fmt.Fprintln(out, ui.StyleStatusWarning.Render("●")+" "+
			ui.StyleDim.Render("Dependency analysis: "+diff.Error.Error()))
		fmt.Fprintln(out)
		return
	}

	// If no changes, skip the section entirely
	if len(diff.Changes) == 0 {
		return
	}

	// Count by type
	var added, removed, upgraded, downgraded int
	for _, c := range diff.Changes {
		switch c.ChangeType {
		case compare.Added:
			added++
		case compare.Removed:
			removed++
		case compare.Upgraded:
			upgraded++
		case compare.Downgraded:
			downgraded++
		}
	}

	// Display header
	fmt.Fprintln(out, ui.StyleHeader.Render("Dependency Changes"))
	fmt.Fprintln(out, ui.StyleDim.Render(strings.Repeat("─", lineWidth)))

	// Summary line
	var summaryParts []string
	if added > 0 {
		summaryParts = append(summaryParts, ui.StyleAdded.Render(fmt.Sprintf("+%d", added)))
	}
	if removed > 0 {
		summaryParts = append(summaryParts, ui.StyleRemoved.Render(fmt.Sprintf("-%d", removed)))
	}
	if upgraded > 0 {
		summaryParts = append(summaryParts, ui.StyleUpgraded.Render(fmt.Sprintf("↑%d", upgraded)))
	}
	if downgraded > 0 {
		summaryParts = append(summaryParts, ui.StyleDowngraded.Render(fmt.Sprintf("↓%d", downgraded)))
	}

	// Show ecosystems affected
	var ecosystemList []string
	for eco := range diff.Ecosystems {
		ecosystemList = append(ecosystemList, eco)
	}
	ecosystemInfo := ""
	if len(ecosystemList) > 0 {
		ecosystemInfo = " " + ui.StyleDim.Render("("+strings.Join(ecosystemList, ", ")+")")
	}

	fmt.Fprintf(out, "%s %s%s\n",
		ui.StyleDim.Render(fmt.Sprintf("%d package(s):", len(diff.Changes))),
		strings.Join(summaryParts, " "),
		ecosystemInfo)
	fmt.Fprintln(out)

	// Show individual changes (limit to first 20 for readability in CLI)
	// TODO: Implement TUI interface for interactive browsing of changes/diffs
	// across repos, binaries, container images, SBOMs, etc. This would allow
	// users to expand/collapse sections, search, filter by ecosystem, etc.
	maxShow := 20
	for i, change := range diff.Changes {
		if i >= maxShow {
			remaining := len(diff.Changes) - maxShow
			fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("  ... and %d more (use 'v' to view full diff)", remaining)))
			break
		}
		renderDependencyChange(out, change, termWidth)
	}
	fmt.Fprintln(out)
}

// renderDependencyChange displays a single dependency change.
func renderDependencyChange(out io.Writer, change compare.Change, termWidth int) {
	var prefix string
	var style lipgloss.Style
	var versionInfo string

	switch change.ChangeType {
	case compare.Added:
		prefix = "+"
		style = ui.StyleAdded
		versionInfo = change.TargetVersion
	case compare.Removed:
		prefix = "-"
		style = ui.StyleRemoved
		versionInfo = change.BaseVersion
	case compare.Upgraded:
		prefix = "↑"
		style = ui.StyleUpgraded
		versionInfo = fmt.Sprintf("%s → %s", change.BaseVersion, change.TargetVersion)
	case compare.Downgraded:
		prefix = "↓"
		style = ui.StyleDowngraded
		versionInfo = fmt.Sprintf("%s → %s", change.BaseVersion, change.TargetVersion)
	default:
		prefix = "~"
		style = ui.StyleDim
		versionInfo = fmt.Sprintf("%s → %s", change.BaseVersion, change.TargetVersion)
	}

	// Truncate package name if needed
	name := change.Name
	maxNameWidth := termWidth - 30 // Leave room for version info
	if len(name) > maxNameWidth {
		name = "..." + name[len(name)-maxNameWidth+3:]
	}

	// Direct/indirect indicator
	directIndicator := ""
	if change.IsDirect {
		directIndicator = ui.StyleDirect.Render(" [direct]")
	}

	fmt.Fprintf(out, "  %s %s %s%s\n",
		style.Render(prefix),
		style.Render(name),
		ui.StyleDim.Render(versionInfo),
		directIndicator)
}

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

	// Get terminal width for responsive layout
	termWidth := getTerminalWidth()
	lineWidth := minInt(termWidth-2, 80) // Cap at 80 for readability

	// Display header
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, ui.StyleHeader.Render("Workspace Changes"))
	fmt.Fprintln(stdout, ui.StyleDim.Render(strings.Repeat("─", lineWidth)))

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

	// Display summary in a compact format
	var summaryParts []string
	if added > 0 {
		summaryParts = append(summaryParts, ui.StyleAdded.Render(fmt.Sprintf("+%d", added)))
	}
	if modified > 0 {
		summaryParts = append(summaryParts, ui.StyleDowngraded.Render(fmt.Sprintf("~%d", modified)))
	}
	if deleted > 0 {
		summaryParts = append(summaryParts, ui.StyleRemoved.Render(fmt.Sprintf("-%d", deleted)))
	}
	if renamed > 0 {
		summaryParts = append(summaryParts, ui.StyleUpgraded.Render(fmt.Sprintf(">%d", renamed)))
	}
	totalChanges := added + modified + deleted + renamed
	fmt.Fprintf(stdout, "%s %s\n",
		ui.StyleDim.Render(fmt.Sprintf("%d file(s):", totalChanges)),
		strings.Join(summaryParts, " "))
	fmt.Fprintln(stdout)

	// Display individual changes
	for _, change := range changes {
		displayChangeWithWidth(stdout, change, termWidth)
	}
	fmt.Fprintln(stdout)

	// Check for dependency manifest changes and compute semantic diff
	depEcosystems := hasDependencyChanges(changes)
	if len(depEcosystems) > 0 {
		// Compute and display dependency diff
		depDiff := computeDependencyDiff(ctx, isolator.OriginalPath(), isolator.IsolatedPath())
		renderDependencyDiff(stdout, depDiff, termWidth)
	}

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

	// Get terminal width for responsive layout
	termWidth := getTerminalWidth()
	lineWidth := minInt(termWidth-2, 80) // Cap at 80 for readability

	// Display header
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, ui.StyleHeader.Render("Workspace Changes"))
	fmt.Fprintln(stdout, ui.StyleDim.Render(strings.Repeat("─", lineWidth)))

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

	// Display summary in a compact format
	var summaryParts []string
	if added > 0 {
		summaryParts = append(summaryParts, ui.StyleAdded.Render(fmt.Sprintf("+%d", added)))
	}
	if modified > 0 {
		summaryParts = append(summaryParts, ui.StyleDowngraded.Render(fmt.Sprintf("~%d", modified)))
	}
	if deleted > 0 {
		summaryParts = append(summaryParts, ui.StyleRemoved.Render(fmt.Sprintf("-%d", deleted)))
	}
	if renamed > 0 {
		summaryParts = append(summaryParts, ui.StyleUpgraded.Render(fmt.Sprintf(">%d", renamed)))
	}
	totalChanges := added + modified + deleted + renamed
	fmt.Fprintf(stdout, "%s %s\n",
		ui.StyleDim.Render(fmt.Sprintf("%d file(s):", totalChanges)),
		strings.Join(summaryParts, " "))
	fmt.Fprintln(stdout)

	// Display individual changes
	for _, change := range changes {
		displayChangeWithWidth(stdout, change, termWidth)
	}
	fmt.Fprintln(stdout)

	// Check for dependency manifest changes and compute semantic diff
	depEcosystems := hasDependencyChanges(changes)
	if len(depEcosystems) > 0 && event.GetIsolatedPath() != "" && event.GetOriginalPath() != "" {
		// Compute and display dependency diff
		depDiff := computeDependencyDiff(ctx, event.GetOriginalPath(), event.GetIsolatedPath())
		renderDependencyDiff(stdout, depDiff, termWidth)
	}

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

// renderReviewMenu displays the interactive review menu with styled options.
func renderReviewMenu(out io.Writer) {
	termWidth := getTerminalWidth()
	lineWidth := minInt(termWidth-2, 80)

	fmt.Fprintln(out, ui.StyleDim.Render(strings.Repeat("─", lineWidth)))
	fmt.Fprintln(out, ui.StyleHeader.Render("What would you like to do?"))
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s %s  %s\n",
		ui.StyleAdded.Render("a"),
		ui.StyleDim.Render("│"),
		"Accept all changes (sync to workspace)")
	fmt.Fprintf(out, "  %s %s  %s\n",
		ui.StyleRemoved.Render("r"),
		ui.StyleDim.Render("│"),
		"Reject all changes (discard)")
	fmt.Fprintf(out, "  %s %s  %s\n",
		ui.StyleDirect.Render("d"),
		ui.StyleDim.Render("│"),
		"Show diff for a specific file")
	fmt.Fprintf(out, "  %s %s  %s\n",
		ui.StyleDirect.Render("v"),
		ui.StyleDim.Render("│"),
		"View full diff (opens in $PAGER)")
	fmt.Fprintf(out, "  %s %s  %s\n",
		ui.StyleDim.Render("q"),
		ui.StyleDim.Render("│"),
		ui.StyleDim.Render("Quit without action"))
	fmt.Fprintln(out)
	fmt.Fprint(out, ui.StyleDirect.Render("Choice: "))
}

// suggestValidChoice provides a helpful suggestion for invalid input.
func suggestValidChoice(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return "Please enter a choice (a, r, d, v, or q)"
	}

	// Check for common mistakes and provide helpful suggestions
	suggestions := map[string]string{
		// Accept variations
		"accept": "Did you mean 'a' for accept?",
		"ok":     "Did you mean 'a' for accept?",
		"apply":  "Did you mean 'a' for accept?",
		"sync":   "Did you mean 'a' for accept?",
		"s":      "Did you mean 'a' for accept?",
		// Reject variations
		"reject": "Did you mean 'r' for reject?",
		"discard": "Did you mean 'r' for reject?",
		"cancel": "Did you mean 'r' for reject or 'q' for quit?",
		"c":      "Did you mean 'r' for reject?",
		"x":      "Did you mean 'r' for reject?",
		// Diff variations
		"diff":  "Did you mean 'd' for diff?",
		"show":  "Did you mean 'd' for diff?",
		"f":     "Did you mean 'd' for diff (file)?",
		// View variations
		"view":  "Did you mean 'v' for view?",
		"open":  "Did you mean 'v' for view?",
		"pager": "Did you mean 'v' for view?",
		"p":     "Did you mean 'v' for view?",
		"less":  "Did you mean 'v' for view?",
		// Quit variations
		"quit":   "Did you mean 'q' for quit?",
		"exit":   "Did you mean 'q' for quit?",
		"abort":  "Did you mean 'q' for quit?",
		"e":      "Did you mean 'q' for quit (exit)?",
		// Help
		"help": "Options: a (accept), r (reject), d (diff), v (view), q (quit)",
		"h":    "Options: a (accept), r (reject), d (diff), v (view), q (quit)",
		"?":    "Options: a (accept), r (reject), d (diff), v (view), q (quit)",
	}

	if suggestion, ok := suggestions[input]; ok {
		return suggestion
	}

	// Generic message for unrecognized input
	return fmt.Sprintf("'%s' is not recognized. Valid options: a, r, d, v, q", input)
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
		renderReviewMenu(stdout)

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
			fmt.Fprintln(stdout, ui.StyleStatusSuccess.Render("●")+" "+ui.StyleAdded.Render("Changes synced to workspace successfully."))
			return ReviewAccept, nil
		case "r", "reject", "n", "no":
			fmt.Fprintln(stdout, ui.StyleStatusError.Render("●")+" "+ui.StyleRemoved.Render("Changes discarded."))
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
			fmt.Fprintln(stdout, ui.StyleDim.Render("Review cancelled."))
			return ReviewAbort, nil
		default:
			suggestion := suggestValidChoice(choice)
			fmt.Fprintln(stderr, ui.StyleStatusWarning.Render("●")+" "+ui.StyleDim.Render(suggestion))
		}
		fmt.Fprintln(stdout)
	}
}

// showFileDiffFromPaths prompts for a file and shows its diff using path-based access.
func showFileDiffFromPaths(
	stdin io.Reader,
	stdout, _ io.Writer,
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
		// Show the new file content with security checks
		content, err := os.ReadFile(isolatedPath)
		if err != nil {
			return fmt.Errorf("read new file: %w", err)
		}
		renderFileContent(out, content, ui.StyleAdded, "+ ", 50)

	case "deleted":
		// Show the original file content with security checks
		content, err := os.ReadFile(originalPath)
		if err != nil {
			return fmt.Errorf("read deleted file: %w", err)
		}
		renderFileContent(out, content, ui.StyleRemoved, "- ", 50)

	case "modified":
		// Check both files for security issues first
		oldContent, _ := os.ReadFile(originalPath)
		newContent, _ := os.ReadFile(isolatedPath)

		// Analyze both for security warnings
		oldWarnings := analyzeContentSecurity(oldContent)
		newWarnings := analyzeContentSecurity(newContent)

		// Show warnings if either file has issues
		if len(newWarnings) > 0 {
			renderContentWarnings(out, newWarnings)
		} else if len(oldWarnings) > 0 {
			renderContentWarnings(out, oldWarnings)
		}

		// Render git-style diff
		renderGitStyleDiff(out, originalPath, isolatedPath, change.Path)

	case "renamed":
		fmt.Fprintln(out, ui.StyleUpgraded.Render(fmt.Sprintf("Renamed from: %s", change.OldPath)))
		fmt.Fprintln(out, ui.StyleUpgraded.Render(fmt.Sprintf("Renamed to:   %s", change.Path)))
	}

	fmt.Fprintln(out)
	return nil
}

// renderGitStyleDiff renders a git-style unified diff with proper headers and line numbers.
func renderGitStyleDiff(out io.Writer, originalPath, isolatedPath, displayPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "diff", "-u", originalPath, isolatedPath)
	output, _ := cmd.CombinedOutput()

	if len(output) == 0 {
		fmt.Fprintln(out, ui.StyleDim.Render("(no textual differences)"))
		return
	}

	lines := strings.Split(string(output), "\n")
	termWidth := getTerminalWidth()
	maxLineWidth := termWidth - 10 // Reserve space for line numbers and prefix

	// Track line numbers
	var oldLine, newLine int

	for i, line := range lines {
		if i >= 150 { // Limit lines shown
			remaining := len(lines) - i
			if remaining > 0 {
				fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines (use 'v' to view full diff)", remaining)))
			}
			break
		}

		// Sanitize the line for safe display
		safeLine := sanitizeLineForDisplay(line)

		// Truncate long lines
		if len(safeLine) > maxLineWidth {
			safeLine = safeLine[:maxLineWidth-3] + "..."
		}

		switch {
		case strings.HasPrefix(line, "---"):
			// Old file header (git style)
			fmt.Fprintln(out, ui.StyleRemoved.Render("--- a/"+displayPath))
		case strings.HasPrefix(line, "+++"):
			// New file header (git style)
			fmt.Fprintln(out, ui.StyleAdded.Render("+++ b/"+displayPath))
		case strings.HasPrefix(line, "@@"):
			// Hunk header - parse line numbers
			oldLine, newLine = parseHunkHeader(line)
			fmt.Fprintln(out, ui.StyleDowngraded.Render(safeLine))
		case strings.HasPrefix(line, "+"):
			// Added line with line number
			lineNum := ui.StyleDim.Render(fmt.Sprintf("%4d ", newLine))
			fmt.Fprintln(out, lineNum+ui.StyleAdded.Render(safeLine))
			newLine++
		case strings.HasPrefix(line, "-"):
			// Removed line with line number
			lineNum := ui.StyleDim.Render(fmt.Sprintf("%4d ", oldLine))
			fmt.Fprintln(out, lineNum+ui.StyleRemoved.Render(safeLine))
			oldLine++
		case strings.HasPrefix(line, " "):
			// Context line with line number
			lineNum := ui.StyleDim.Render(fmt.Sprintf("%4d ", newLine))
			fmt.Fprintln(out, lineNum+safeLine)
			oldLine++
			newLine++
		default:
			// Other lines (empty, etc.)
			if line != "" {
				fmt.Fprintln(out, safeLine)
			}
		}
	}
}

// parseHunkHeader extracts starting line numbers from a unified diff hunk header.
// Format: @@ -old_start,old_count +new_start,new_count @@
func parseHunkHeader(header string) (oldLine, newLine int) {
	oldLine, newLine = 1, 1 // defaults

	// Find the @@ markers
	start := strings.Index(header, "@@")
	if start == -1 {
		return
	}
	end := strings.Index(header[start+2:], "@@")
	if end == -1 {
		return
	}

	// Extract the range part: -old_start,old_count +new_start,new_count
	rangePart := strings.TrimSpace(header[start+2 : start+2+end])

	for part := range strings.FieldsSeq(rangePart) {
		if numPart, ok := strings.CutPrefix(part, "-"); ok {
			// Parse old line number
			if commaIdx := strings.Index(numPart, ","); commaIdx != -1 {
				numPart = numPart[:commaIdx]
			}
			fmt.Sscanf(numPart, "%d", &oldLine)
		} else if numPart, ok := strings.CutPrefix(part, "+"); ok {
			// Parse new line number
			if commaIdx := strings.Index(numPart, ","); commaIdx != -1 {
				numPart = numPart[:commaIdx]
			}
			fmt.Sscanf(numPart, "%d", &newLine)
		}
	}

	return
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
	displayChangeWithWidth(out, change, getTerminalWidth())
}

// displayChangeWithWidth formats and displays a single file change with explicit width.
func displayChangeWithWidth(out io.Writer, change workspace.FileChange, termWidth int) {
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

	// Calculate available width for path (accounting for prefix, spaces, and size info)
	// Format: "  + path (size)" -> 4 chars overhead + size info
	sizeInfo := ""
	sizeLen := 0
	if change.Size > 0 {
		sizeInfo = fmt.Sprintf(" (%s)", formatFileSize(change.Size))
		sizeLen = len(sizeInfo)
	}

	availableWidth := max(termWidth-4-sizeLen, 20) // "  + " prefix, minimum 20

	if change.Type == "renamed" && change.OldPath != "" {
		// For renames: "  > oldpath -> newpath"
		arrowLen := 4 // " -> "
		halfWidth := (availableWidth - arrowLen) / 2
		oldPath := truncatePath(change.OldPath, halfWidth)
		newPath := truncatePath(change.Path, halfWidth)
		fmt.Fprintf(out, "  %s %s -> %s\n",
			style.Render(prefix),
			ui.StyleDim.Render(oldPath),
			style.Render(newPath))
	} else {
		displayPath := truncatePath(change.Path, availableWidth)
		fmt.Fprintf(out, "  %s %s%s\n",
			style.Render(prefix),
			style.Render(displayPath),
			ui.StyleDim.Render(sizeInfo))
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
		renderReviewMenu(stdout)

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
			fmt.Fprintln(stdout, ui.StyleStatusSuccess.Render("●")+" "+ui.StyleAdded.Render("Changes accepted."))
			return ReviewAccept, nil
		case "r", "reject", "n", "no":
			fmt.Fprintln(stdout, ui.StyleStatusError.Render("●")+" "+ui.StyleRemoved.Render("Changes discarded."))
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
			fmt.Fprintln(stdout, ui.StyleDim.Render("Review cancelled."))
			return ReviewAbort, nil
		default:
			suggestion := suggestValidChoice(choice)
			fmt.Fprintln(stderr, ui.StyleStatusWarning.Render("●")+" "+ui.StyleDim.Render(suggestion))
		}
		fmt.Fprintln(stdout)
	}
}

// showFileDiff prompts for a file and shows its diff.
func showFileDiff(
	stdin io.Reader,
	stdout, _ io.Writer,
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
		// Show the new file content with security checks
		content, err := os.ReadFile(isolatedPath)
		if err != nil {
			return fmt.Errorf("read new file: %w", err)
		}
		renderFileContent(out, content, ui.StyleAdded, "+ ", 50)

	case "deleted":
		// Show the original file content with security checks
		content, err := os.ReadFile(originalPath)
		if err != nil {
			return fmt.Errorf("read deleted file: %w", err)
		}
		renderFileContent(out, content, ui.StyleRemoved, "- ", 50)

	case "modified":
		// Check both files for security issues first
		oldContent, _ := os.ReadFile(originalPath)
		newContent, _ := os.ReadFile(isolatedPath)

		// Analyze both for security warnings
		oldWarnings := analyzeContentSecurity(oldContent)
		newWarnings := analyzeContentSecurity(newContent)

		// Show warnings if either file has issues
		if len(newWarnings) > 0 {
			renderContentWarnings(out, newWarnings)
		} else if len(oldWarnings) > 0 {
			renderContentWarnings(out, oldWarnings)
		}

		// Render git-style diff
		renderGitStyleDiff(out, originalPath, isolatedPath, change.Path)

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

// ContentWarning represents a security concern found in file content.
type ContentWarning struct {
	Type        string // "bidi", "control", "binary", "homoglyph"
	Description string
	Severity    string // "high", "medium", "low"
}

// bidiChars are Unicode bidirectional override characters that can be used
// in Trojan Source attacks to make code appear different than it executes.
// See: https://trojansource.codes/
var bidiChars = map[rune]string{
	'\u202A': "LRE (Left-to-Right Embedding)",
	'\u202B': "RLE (Right-to-Left Embedding)",
	'\u202C': "PDF (Pop Directional Formatting)",
	'\u202D': "LRO (Left-to-Right Override)",
	'\u202E': "RLO (Right-to-Left Override)",
	'\u2066': "LRI (Left-to-Right Isolate)",
	'\u2067': "RLI (Right-to-Left Isolate)",
	'\u2068': "FSI (First Strong Isolate)",
	'\u2069': "PDI (Pop Directional Isolate)",
}

// dangerousControlChars are control characters that could be used maliciously.
var dangerousControlChars = map[rune]string{
	'\x00': "NULL",
	'\x08': "BACKSPACE",
	'\x7F': "DELETE",
	'\x1B': "ESCAPE",
}

// analyzeContentSecurity checks content for potentially malicious patterns.
func analyzeContentSecurity(content []byte) []ContentWarning {
	var warnings []ContentWarning

	// Check for binary content (non-text)
	if isBinaryContent(content) {
		warnings = append(warnings, ContentWarning{
			Type:        "binary",
			Description: "File appears to contain binary data",
			Severity:    "medium",
		})
		return warnings // Skip further analysis for binary files
	}

	text := string(content)

	// Check for bidirectional override characters (Trojan Source)
	for r, name := range bidiChars {
		if strings.ContainsRune(text, r) {
			warnings = append(warnings, ContentWarning{
				Type:        "bidi",
				Description: fmt.Sprintf("Contains bidirectional text character: %s (U+%04X)", name, r),
				Severity:    "high",
			})
		}
	}

	// Check for dangerous control characters
	for r, name := range dangerousControlChars {
		if strings.ContainsRune(text, r) {
			warnings = append(warnings, ContentWarning{
				Type:        "control",
				Description: fmt.Sprintf("Contains control character: %s (0x%02X)", name, r),
				Severity:    "medium",
			})
		}
	}

	// Check for zero-width characters that could hide content
	zeroWidthChars := map[rune]string{
		'\u200B': "Zero Width Space",
		'\u200C': "Zero Width Non-Joiner",
		'\u200D': "Zero Width Joiner",
		'\uFEFF': "Zero Width No-Break Space (BOM)",
	}
	for r, name := range zeroWidthChars {
		if strings.ContainsRune(text, r) {
			warnings = append(warnings, ContentWarning{
				Type:        "hidden",
				Description: fmt.Sprintf("Contains invisible character: %s (U+%04X)", name, r),
				Severity:    "medium",
			})
		}
	}

	return warnings
}

// Note: isBinaryContent is defined in secrets.go and shared across the cmd package.

// sanitizeLineForDisplay makes a line safe for terminal display by escaping
// dangerous characters while preserving readability.
func sanitizeLineForDisplay(line string) string {
	var result strings.Builder
	result.Grow(len(line))

	for _, r := range line {
		switch {
		// Bidirectional override characters - show as escaped
		case r >= '\u202A' && r <= '\u202E':
			fmt.Fprintf(&result, "\u2590U+%04X\u258C", r)
		case r >= '\u2066' && r <= '\u2069':
			fmt.Fprintf(&result, "\u2590U+%04X\u258C", r)
		// Zero-width characters - show as markers
		case r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF':
			fmt.Fprintf(&result, "\u2590U+%04X\u258C", r)
		// Control characters (except tab/newline)
		case r < 0x20 && r != '\t' && r != '\n' && r != '\r':
			fmt.Fprintf(&result, "\\x%02X", r)
		case r == 0x7F:
			result.WriteString("\\x7F")
		default:
			result.WriteRune(r)
		}
	}

	return result.String()
}

// renderContentWarnings displays security warnings about file content.
func renderContentWarnings(out io.Writer, warnings []ContentWarning) {
	if len(warnings) == 0 {
		return
	}

	// Style for security warnings
	warningStyle := ui.StyleStatusWarning.Bold(true)
	highStyle := ui.StyleRemoved.Bold(true)

	fmt.Fprintln(out)
	fmt.Fprintln(out, warningStyle.Render("! Security warnings detected:"))

	for _, w := range warnings {
		severity := ui.StyleDim.Render(fmt.Sprintf("[%s]", w.Severity))
		if w.Severity == "high" {
			severity = highStyle.Render("[HIGH]")
		}
		fmt.Fprintf(out, "  %s %s\n", severity, w.Description)
	}
	fmt.Fprintln(out)
}

// renderFileContent displays file content with security checks and proper handling.
func renderFileContent(out io.Writer, content []byte, style lipgloss.Style, prefix string, maxLines int) {
	// Handle empty content
	if len(content) == 0 {
		fmt.Fprintln(out, ui.StyleDim.Render(prefix+"(empty file)"))
		return
	}

	// Check for security issues
	warnings := analyzeContentSecurity(content)
	renderContentWarnings(out, warnings)

	// Check for binary content
	if isBinaryContent(content) {
		fmt.Fprintln(out, ui.StyleDim.Render(prefix+fmt.Sprintf("(binary file, %s)", formatFileSize(int64(len(content))))))
		return
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i >= maxLines {
			fmt.Fprintln(out, ui.StyleDim.Render(fmt.Sprintf("... and %d more lines", len(lines)-maxLines)))
			break
		}
		// Sanitize line for safe display
		safeLine := sanitizeLineForDisplay(line)
		fmt.Fprintln(out, style.Render(prefix+safeLine))
	}
}
