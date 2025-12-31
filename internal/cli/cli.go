package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/charmbracelet/fang"
	"github.com/go-git/go-git/v5"
	"github.com/picatz/deputy/internal/cli/cmd"
	"github.com/picatz/deputy/internal/config"
	deputyerrors "github.com/picatz/deputy/internal/errors"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/scan"
	_ "github.com/picatz/deputy/internal/targets/providers"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Run constructs the root command hierarchy and executes it with all
// subcommands registered. It is the primary entry point used by main.
func Run(ctx context.Context) error {
	// Load configuration (includes OTel settings)
	cfg := loadOTelConfig()

	// Initialize OpenTelemetry (graceful no-op if disabled)
	provider, err := otel.Init(ctx, cfg)
	if err != nil {
		slog.Warn("failed to initialize OpenTelemetry", "error", err)
	}
	defer func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			slog.Debug("otel shutdown error", "error", err)
		}
	}()

	return fang.Execute(ctx, newRoot(), fang.WithErrorHandler(silentErrorHandler))
}

// loadOTelConfig returns OTel configuration from environment and config file.
func loadOTelConfig() otel.Config {
	// Try to load from config file
	configPath := config.FindConfigFile()
	if configPath != "" {
		loader := config.NewLoader(configPath)
		if cfg, err := loader.Load(); err == nil {
			return cfg.OTel
		}
	}
	// Fall back to defaults (env vars are checked in otel.Init)
	return otel.DefaultConfig()
}

// silentErrorHandler suppresses fang's default styled error output.
// Commands that need custom error handling (like proxy exec) print their own messages.
func silentErrorHandler(w io.Writer, styles fang.Styles, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	if errors.Is(err, pflag.ErrHelp) {
		return
	}
	var silent *deputyerrors.SilentError
	if errors.As(err, &silent) {
		return
	}
	fang.DefaultErrorHandler(w, styles, err)
}

// newRoot returns the root command with all subcommands attached.
func newRoot() *cobra.Command {
	logLevel := defaultLogLevel()
	logFormat := defaultLogFormat()

	rootCmd := &cobra.Command{
		Use:           "deputy",
		Short:         "Secure your dependencies with policy enforcement, vulnerability scanning, and automated remediation",
		SilenceErrors: true,
		SilenceUsage:  true,
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

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", logLevel, "Logging level: debug, info, warn, error (default: warn). Override with DEPUTY_LOG_LEVEL")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", logFormat, "Logging format (text, json). Override with DEPUTY_LOG_FORMAT")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return configureLogging(logLevel, logFormat)
	}
	cmd.RegisterCommands(rootCmd, cmd.Dependencies{ScanService: scan.NewService()})
	return rootCmd
}

// isInGitRepo checks if the current working directory is inside a git repository.
func isInGitRepo() bool {
	// Use the internal git package to check if we're in a Git repository.
	_, err := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	return err == nil
}

// defaultLogLevel returns the default log level from the environment or "warn".
// Default is warn to keep CLI output clean for interactive use. Users who want
// verbose observability logs can set DEPUTY_LOG_LEVEL=info or --log-level=info.
func defaultLogLevel() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_LEVEL")); v != "" {
		return v
	}
	return "warn"
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

	// Enable trace context and OTel log export when OTel is enabled
	otelEnabled := otel.IsEnabled()

	logger := logs.New(logs.Options{
		Level:               level,
		Format:              format,
		Writer:              os.Stderr,
		ColorEnabled:        true,
		IncludeTraceContext: otelEnabled,
		ExportToOTel:        otelEnabled,
	})

	slog.SetDefault(logger)
	logs.SetDefault(logger)

	return nil
}

// parseLogLevel converts a string log level to slog.Level, defaulting to [slog.LevelInfo] if empty.
func parseLogLevel(value string) (slog.Level, error) {
	if strings.TrimSpace(value) == "" {
		return slog.LevelInfo, nil
	}
	return logs.ParseLevel(value)
}
