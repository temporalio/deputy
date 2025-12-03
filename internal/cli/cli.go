package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/charmbracelet/fang"
	"github.com/go-git/go-git/v5"
	"github.com/picatz/deputy/internal/cli/cmd"
	_ "github.com/picatz/deputy/internal/targets/providers"
	"github.com/spf13/cobra"
)

// Run constructs the root command hierarchy and executes it with all
// subcommands registered. It is the primary entry point used by main.
func Run(ctx context.Context) error {
	return fang.Execute(ctx, newRoot(), fang.WithErrorHandler(silentErrorHandler))
}

// silentErrorHandler suppresses fang's default styled error output.
// Commands that need custom error handling (like proxy exec) print their own messages.
func silentErrorHandler(_ io.Writer, _ fang.Styles, _ error) {
	// intentionally empty - let commands handle their own errors
}

// newRoot returns the root command with all subcommands attached.
func newRoot() *cobra.Command {
	var logLevel = defaultLogLevel()
	var logFormat = defaultLogFormat()

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

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", logLevel, "Logging level (debug, info, warn, error). Override with DEPUTY_LOG_LEVEL")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", logFormat, "Logging format (text, json). Override with DEPUTY_LOG_FORMAT")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return configureLogging(logLevel, logFormat)
	}
	cmd.RegisterCommands(rootCmd)
	return rootCmd
}

func isInGitRepo() bool {
	// Use the internal git package to check if we're in a Git repository.
	_, err := git.PlainOpen(".")
	return err == nil
}

func defaultLogLevel() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_LEVEL")); v != "" {
		return v
	}
	return "info"
}

func defaultLogFormat() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_FORMAT")); v != "" {
		return v
	}
	return "text"
}

func configureLogging(levelStr, format string) error {
	level, err := parseLogLevel(levelStr)
	if err != nil {
		return err
	}
	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	default:
		return fmt.Errorf("unknown log format %q", format)
	}
	slog.SetDefault(slog.New(handler))
	return nil
}

func parseLogLevel(value string) (slog.Leveler, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return nil, fmt.Errorf("unknown log level %q", value)
	}
}
