package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/deputy/internal/secrets"
	"github.com/spf13/cobra"
)

// AddSecretsBaselineCommand adds the baseline subcommand to the secrets command.
func AddSecretsBaselineCommand(secretsCmd *cobra.Command) {
	baselineCmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage secrets baseline for incremental scanning",
		Long: `Manage a baseline of known/accepted secrets for incremental scanning.

A baseline allows you to track known secrets (test fixtures, false positives, etc.)
and only report new secrets found in subsequent scans. This is useful for:

• Onboarding existing projects with known secrets
• Tracking intentional test credentials
• Managing false positives
• Incremental CI/CD scanning

The baseline file (.deputy-secrets-baseline.json) stores hashes of known findings,
not the actual secret values.

EXAMPLES:

  Create initial baseline:
    deputy secrets baseline create .

  Scan and only show new secrets:
    deputy secrets --baseline .deputy-secrets-baseline.json .

  Update baseline with new findings:
    deputy secrets baseline update .

  Audit baseline for stale entries:
    deputy secrets baseline audit

  View baseline status:
    deputy secrets baseline status
`,
	}

	// Create subcommand
	baselineCreateCmd := &cobra.Command{
		Use:   "create [path]",
		Short: "Create a new baseline from current findings",
		Long: `Create a new baseline file from all secrets found in the target.

This scans the target path and adds all findings to a new baseline.
Use this to establish a known state when onboarding an existing project.

The baseline file stores hashes of findings, not actual secret values.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			output, _ := cmd.Flags().GetString("output")
			reason, _ := cmd.Flags().GetString("reason")
			excludes, _ := cmd.Flags().GetStringSlice("exclude")

			// Check if baseline already exists
			if _, err := os.Stat(output); err == nil {
				return fmt.Errorf("baseline already exists at %s. Use 'baseline update' to add entries or delete the file first", output)
			}

			// Create scanner
			engine, err := secrets.NewEngine()
			if err != nil {
				return fmt.Errorf("creating scanner: %w", err)
			}

			// Generate baseline
			fmt.Printf("Scanning %s for secrets...\n", target)
			baseline, err := generateBaselineWithExcludes(ctx, engine, target, reason, excludes)
			if err != nil {
				return fmt.Errorf("generating baseline: %w", err)
			}

			// Save baseline
			if err := baseline.Save(output); err != nil {
				return fmt.Errorf("saving baseline: %w", err)
			}

			fmt.Printf("\n%s Created baseline with %d entries in %s\n",
				lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("✓"),
				baseline.TotalEntries(),
				output)

			if baseline.TotalEntries() > 0 {
				fmt.Println("\nFiles with baselined secrets:")
				for _, file := range baseline.Files() {
					count := len(baseline.Results[file])
					fmt.Printf("  %s (%d)\n", file, count)
				}
			}

			return nil
		},
	}
	baselineCreateCmd.Flags().StringP("output", "o", secrets.DefaultBaselinePath, "Output path for baseline file")
	baselineCreateCmd.Flags().String("reason", "initial baseline", "Reason for adding findings to baseline")
	baselineCreateCmd.Flags().StringSlice("exclude", nil, "Glob patterns to exclude")

	// Update subcommand
	baselineUpdateCmd := &cobra.Command{
		Use:   "update [path]",
		Short: "Update baseline with new findings",
		Long: `Update an existing baseline with newly detected secrets.

This scans the target, compares against the existing baseline,
and adds any new findings to the baseline.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			baselinePath, _ := cmd.Flags().GetString("baseline")
			reason, _ := cmd.Flags().GetString("reason")

			// Load existing baseline
			baseline, err := secrets.LoadBaseline(baselinePath)
			if err != nil {
				return fmt.Errorf("loading baseline: %w", err)
			}

			// Create scanner
			engine, err := secrets.NewEngine()
			if err != nil {
				return fmt.Errorf("creating scanner: %w", err)
			}

			// Scan for current secrets
			fmt.Printf("Scanning %s for secrets...\n", target)
			findings, err := scanDirectoryForBaseline(ctx, engine, target)
			if err != nil {
				return fmt.Errorf("scanning: %w", err)
			}

			// Find new secrets not in baseline
			var newFindings []secrets.Finding
			for _, f := range findings {
				if !baseline.Contains(f) {
					newFindings = append(newFindings, f)
				}
			}

			if len(newFindings) == 0 {
				fmt.Println("\nNo new secrets found. Baseline is up to date.")
				return nil
			}

			fmt.Printf("\nFound %d new secrets:\n", len(newFindings))
			for _, f := range newFindings {
				fmt.Printf("  %s:%d - %s (%s)\n", f.File, f.Line, f.Type, f.Redacted)
			}

			// Add to baseline
			baseline.AddFindings(newFindings, reason)

			// Save updated baseline
			if err := baseline.Save(baselinePath); err != nil {
				return fmt.Errorf("saving baseline: %w", err)
			}

			fmt.Printf("\n%s Added %d entries to baseline. Total: %d\n",
				lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("✓"),
				len(newFindings),
				baseline.TotalEntries())

			return nil
		},
	}
	baselineUpdateCmd.Flags().StringP("baseline", "b", secrets.DefaultBaselinePath, "Path to baseline file")
	baselineUpdateCmd.Flags().String("reason", "updated baseline", "Reason for new entries")

	// Audit subcommand
	baselineAuditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit baseline for stale entries",
		Long: `Audit the baseline and report stale entries.

Stale entries are findings that no longer match the source files
(file deleted, line changed, etc.).

Use --clean to automatically remove stale entries.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baselinePath, _ := cmd.Flags().GetString("baseline")
			clean, _ := cmd.Flags().GetBool("clean")

			// Load baseline
			baseline, err := secrets.LoadBaseline(baselinePath)
			if err != nil {
				return fmt.Errorf("loading baseline: %w", err)
			}

			// Determine root directory
			rootDir := "."
			if len(args) > 0 {
				rootDir = args[0]
			}

			// Audit
			results, err := baseline.Audit(rootDir)
			if err != nil {
				return fmt.Errorf("auditing baseline: %w", err)
			}

			if len(results) == 0 {
				fmt.Printf("%s Baseline is clean. All %d entries are valid.\n",
					lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("✓"),
					baseline.TotalEntries())
				return nil
			}

			// Report stale entries
			fmt.Printf("Found %d stale entries:\n\n", len(results))

			byStatus := make(map[secrets.AuditStatus][]secrets.AuditResult)
			for _, r := range results {
				byStatus[r.Status] = append(byStatus[r.Status], r)
			}

			statusLabels := map[secrets.AuditStatus]string{
				secrets.AuditStatusFileDeleted:    "File deleted",
				secrets.AuditStatusLineMoved:      "Line moved/removed",
				secrets.AuditStatusContentChanged: "Content changed",
			}

			for status, items := range byStatus {
				fmt.Printf("%s (%d):\n", statusLabels[status], len(items))
				for _, r := range items {
					fmt.Printf("  %s:%d - %s\n", r.File, r.Entry.Line, r.Entry.Type)
				}
				fmt.Println()
			}

			// Clean if requested
			if clean {
				removed, err := baseline.Clean(rootDir)
				if err != nil {
					return fmt.Errorf("cleaning baseline: %w", err)
				}

				if err := baseline.Save(baselinePath); err != nil {
					return fmt.Errorf("saving baseline: %w", err)
				}

				fmt.Printf("%s Removed %d stale entries. Remaining: %d\n",
					lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("✓"),
					removed,
					baseline.TotalEntries())
			} else {
				fmt.Println("Run with --clean to remove stale entries.")
			}

			return nil
		},
	}
	baselineAuditCmd.Flags().StringP("baseline", "b", secrets.DefaultBaselinePath, "Path to baseline file")
	baselineAuditCmd.Flags().Bool("clean", false, "Remove stale entries")

	// Status subcommand
	baselineStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show baseline status",
		Long:  `Display information about the current baseline file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baselinePath, _ := cmd.Flags().GetString("baseline")

			// Load baseline
			baseline, err := secrets.LoadBaseline(baselinePath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Printf("No baseline found at %s\n", baselinePath)
					fmt.Println("\nCreate one with: deputy secrets baseline create")
					return nil
				}
				return fmt.Errorf("loading baseline: %w", err)
			}

			// Display status
			fmt.Printf("Baseline: %s\n", baselinePath)
			fmt.Printf("Version:  %s\n", baseline.Version)
			fmt.Printf("Updated:  %s\n", baseline.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("Entries:  %d\n", baseline.TotalEntries())
			fmt.Printf("Files:    %d\n", len(baseline.Files()))

			if baseline.TotalEntries() > 0 {
				fmt.Println("\nBy file:")
				for _, file := range baseline.Files() {
					entries := baseline.Results[file]
					fmt.Printf("  %s: %d entries\n", file, len(entries))
				}

				// Count by type
				typeCount := make(map[string]int)
				for _, entries := range baseline.Results {
					for _, e := range entries {
						typeCount[e.Type]++
					}
				}

				fmt.Println("\nBy type:")
				for t, count := range typeCount {
					fmt.Printf("  %s: %d\n", t, count)
				}
			}

			return nil
		},
	}
	baselineStatusCmd.Flags().StringP("baseline", "b", secrets.DefaultBaselinePath, "Path to baseline file")

	// Wire up subcommands
	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineUpdateCmd)
	baselineCmd.AddCommand(baselineAuditCmd)
	baselineCmd.AddCommand(baselineStatusCmd)

	secretsCmd.AddCommand(baselineCmd)
}

// generateBaselineWithExcludes generates a baseline while respecting exclude patterns.
func generateBaselineWithExcludes(ctx context.Context, scanner secrets.Scanner, dir, reason string, excludes []string) (*secrets.Baseline, error) {
	baseline := secrets.NewBaseline()

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rootFS := root.FS()

	err = fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".venv" {
				return fs.SkipDir
			}
			return nil
		}

		// Get relative path
		relPath := filepath.FromSlash(path)

		// Check excludes
		for _, pattern := range excludes {
			if matched, _ := filepath.Match(pattern, relPath); matched {
				return nil
			}
			if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
				return nil
			}
		}

		// Skip binary files
		if isBinaryFileByExtension(relPath) {
			return nil
		}

		content, err := fs.ReadFile(rootFS, path)
		if err != nil {
			return nil
		}

		findings, err := scanner.ScanFile(ctx, relPath, content)
		if err != nil {
			return nil
		}

		baseline.AddFindings(findings, reason)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return baseline, nil
}

// scanDirectoryForBaseline scans a directory for secrets (for baseline operations).
func scanDirectoryForBaseline(ctx context.Context, scanner secrets.Scanner, dir string) ([]secrets.Finding, error) {
	var allFindings []secrets.Finding

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rootFS := root.FS()

	err = fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".venv" {
				return fs.SkipDir
			}
			return nil
		}

		// Skip binary files
		if isBinaryFileByExtension(path) {
			return nil
		}

		content, err := fs.ReadFile(rootFS, path)
		if err != nil {
			return nil
		}

		relPath := filepath.FromSlash(path)

		findings, err := scanner.ScanFile(ctx, relPath, content)
		if err != nil {
			return nil
		}

		allFindings = append(allFindings, findings...)
		return nil
	})

	return allFindings, err
}

// isBinaryFileByExtension checks if a file is binary by extension.
func isBinaryFileByExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".pdf": true, ".zip": true, ".tar": true,
		".gz": true, ".bz2": true, ".7z": true, ".rar": true,
		".mp3": true, ".mp4": true, ".wav": true, ".avi": true,
		".ttf": true, ".otf": true, ".woff": true, ".woff2": true,
		".pyc": true, ".pyo": true, ".class": true, ".o": true,
	}
	return binaryExts[ext]
}
