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
		Short: "Secure your dependencies with policy enforcement, vulnerability scanning, and automated remediation",
		Long: `Deputy is a comprehensive security tool for modern development workflows. It integrates 
dependency analysis, vulnerability scanning, policy enforcement, and automated remediation 
into a single CLI.

CORE CAPABILITIES:
• Vulnerability Management: Scan for issues, triage results with AI, and apply automated fixes.
• Policy Enforcement: Define and enforce CEL-based policies for dependencies and licenses.
• Dependency Analysis: Track changes between commits and list dependencies across ecosystems.
• Supply Chain Security: Generate SBOMs and proxy package managers to block risky packages.

COMMAND OVERVIEW:
• scan:    Scan repositories or SBOMs for vulnerabilities
• fix:     Generate and apply remediation plans for vulnerabilities
• triage:  Summarize and prioritize issues (with optional AI assistance)
• policy:  Develop, test, and evaluate security policies
• proxy:   Run a policy-enforcing proxy for Go, npm, PyPI, and RubyGems
• diff:    Compare dependency changes between Git references
• list:    List dependencies in a repository
• sbom:    Generate Software Bills of Materials (SBOMs)

DEFAULT EXECUTION:
Running 'deputy' without arguments defaults to 'deputy diff' if inside a Git repository.`,
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
  # Scan for vulnerabilities
  deputy scan

  # Fix vulnerabilities automatically
  deputy fix

  # Triage issues with AI assistance
  deputy triage --agent codex

POLICY ENFORCEMENT:
  # Run npm through the Deputy proxy to enforce policies
  deputy proxy npm -- npm install

  # Evaluate a policy against a context
  deputy policy eval --policy policy.yaml --input context.json

DEPENDENCY ANALYSIS:
  # Compare current work with main branch
  deputy diff main

  # List all dependencies
  deputy list

SUPPLY CHAIN:
  # Generate an SBOM
  deputy sbom --format spdx`,
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", logLevel, "Logging level (debug, info, warn, error). Override with DEPUTY_LOG_LEVEL")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", logFormat, "Logging format (text, json). Override with DEPUTY_LOG_FORMAT")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return configureLogging(logLevel, logFormat)
	}
	cmd.RegisterCommands(rootCmd)
	return rootCmd
}

// isInGitRepo checks if the current working directory is inside a git repository.
func isInGitRepo() bool {
	// Use the internal git package to check if we're in a Git repository.
	_, err := git.PlainOpen(".")
	return err == nil
}

// defaultLogLevel returns the default log level from the environment or "info".
func defaultLogLevel() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_LEVEL")); v != "" {
		return v
	}
	return "info"
}

// defaultLogFormat returns the default log format from the environment or "text".
func defaultLogFormat() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_FORMAT")); v != "" {
		return v
	}
	return "text"
}

// configureLogging sets up the global slog logger based on the provided level and format.
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

// parseLogLevel converts a string log level to a slog.Leveler.
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
