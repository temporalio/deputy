package cli

import (
	"context"

	"github.com/charmbracelet/fang"
	"github.com/go-git/go-git/v5"
	"github.com/picatz/deputy/internal/cli/cmd"
	"github.com/spf13/cobra"
)

// Run constructs the root command hierarchy and executes it with all
// subcommands registered. It is the primary entry point used by main.
func Run(ctx context.Context) error {
	return fang.Execute(ctx, newRoot())
}

// newRoot returns the root command with all subcommands attached.
func newRoot() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "deputy",
		Short: "Analyze dependencies, diff refs, and scan for vulns",
		Long: `Deputy is a comprehensive tool for analyzing Go dependencies, comparing changes between 
  Git references, and scanning for security vulnerabilities.

CORE CAPABILITIES:
• Dependency Analysis: Compare dependencies between any Git references
• Vulnerability Scanning: Scan repositories, directories, or SBOM files for security issues  
• SBOM Generation: Create Software Bills of Materials in multiple formats
• License Detection: Identify licenses for dependencies
• CI/CD Integration: JSON outputs and machine-readable formats

COMMAND OVERVIEW:
• diff: Compare dependency changes between Git references (default when run without subcommand)
• scan: Scan for vulnerabilities using OSV database
• sbom: Generate Software Bills of Materials

The tool automatically detects default branches, optimizes scans by checking for actual
dependency changes, and provides detailed vulnerability information with fix recommendations.

DEFAULT EXECUTION:
Running 'deputy' with no subcommand executes the dependency diff analysis (equivalent to 'deputy diff').
Use 'deputy --help' to view global help or 'deputy diff --help' for diff-specific flags.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Invoke diff command programmatically when no subcommand specified,
			// and we're in a Git repository.
			if isInGitRepo() {
				diffCmd, _, err := cmd.Find([]string{"diff"})
				if err != nil || diffCmd == nil {
					return cmd.Help()
				}
				// Ensure diff command uses same context.
				diffCmd.SetContext(cmd.Context())
				return diffCmd.RunE(diffCmd, args)
			}
			return cmd.Help()
		},
		Example: `QUICK START:
  # Compare your current work with main branch
  deputy

  # Compare two branches explicitly  
  deputy diff main feature-branch

  # Scan current repository for vulnerabilities
  deputy scan

  # Generate SBOM for current repository
  deputy sbom

DEPENDENCY ANALYSIS:
  # Compare current work with default branch
  deputy
  deputy diff

  # Compare specific branches
  deputy diff main develop
  deputy diff v1.0.0 v2.0.0

  # Compare with your uncommitted changes
  deputy diff main WORKING

VULNERABILITY SCANNING:
  # Scan repository at HEAD
  deputy scan

  # Scan specific Git reference  
  deputy scan --ref v1.2.3

  # Scan directory without Git context
  deputy scan dir /path/to/project

  # Scan SBOM file
  deputy scan sbom project-sbom.json

SBOM GENERATION:
  # Generate CycloneDX SBOM
  deputy sbom

  # Generate SPDX SBOM with licenses
  deputy sbom --format spdx --enrich-licenses

  # Generate for specific reference
  deputy sbom --ref v1.2.3 --output release-sbom.json

CI/CD INTEGRATION:
  # Dependency change analysis
  deputy diff --format json main HEAD

  # Vulnerability scanning with JSON output
  deputy scan --format json --ignore-unfixed

  # SBOM generation for compliance
  deputy sbom --format spdx --enrich-licenses --output sbom.json

ADVANCED WORKFLOWS:
  # Full security pipeline
  deputy sbom --format protobom | deputy scan sbom -

  # Compare releases for security analysis
  deputy diff v1.0.0 v2.0.0
  deputy scan --ref v2.0.0 --format json

  # Historical vulnerability analysis
  deputy scan --ref "main@{3.month.ago}"`,
	}
	cmd.RegisterCommands(rootCmd)
	return rootCmd
}

func isInGitRepo() bool {
	// Use the internal git package to check if we're in a Git repository.
	_, err := git.PlainOpen(".")
	return err == nil
}
