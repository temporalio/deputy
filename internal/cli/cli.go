package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/charmbracelet/fang"
	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/temporalio/deputy/internal/analysis/advisorysource"
	"github.com/temporalio/deputy/internal/cache"
	"github.com/temporalio/deputy/internal/cli/cmd"
	"github.com/temporalio/deputy/internal/config"
	deputyerrors "github.com/temporalio/deputy/internal/errors"
	"github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/network"
	"github.com/temporalio/deputy/internal/otel"
	_ "github.com/temporalio/deputy/internal/targets/providers"
	"github.com/temporalio/deputy/internal/version"
)

// Run constructs the root command hierarchy and executes it with all
// subcommands registered. It is the primary entry point used by main.
func Run(ctx context.Context) error {
	// Load configuration for runtime defaults (OTel, egress allowlists).
	cfg := loadRuntimeConfig()

	// Apply local egress allowlists before services are initialized.
	applyLocalEgressConfig(cfg)

	// Declare configured advisory sources; they are materialized lazily when a
	// scan builds its source registry, so non-scanning commands pay nothing.
	applyAdvisorySourceConfig(cfg)

	otelCfg := otel.DefaultConfig()
	if cfg != nil {
		otelCfg = cfg.OTel
	}

	// Initialize OpenTelemetry (graceful no-op if disabled)
	provider, err := otel.Init(ctx, otelCfg)
	if err != nil {
		slog.Warn("failed to initialize OpenTelemetry", "error", err)
	}
	defer func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			slog.Debug("otel shutdown error", "error", err)
		}
	}()

	return fang.Execute(ctx, newRoot(), fang.WithErrorHandler(silentErrorHandler), fang.WithVersion(version.Value))
}

// loadRuntimeConfig loads configuration from environment and config file.
func loadRuntimeConfig() *config.Config {
	configPath := config.FindConfigFile()
	loader := config.NewLoader(configPath)
	cfg, err := loader.Load()
	if err != nil {
		return nil
	}
	return cfg
}

// applyAdvisorySourceConfig hands the config file's advisory_sources entries to
// the advisory-source registry as declarative configs. Materialization (and any
// plugin exec or network Info call) happens lazily at scan time.
func applyAdvisorySourceConfig(cfg *config.Config) {
	if cfg == nil || len(cfg.AdvisorySources) == 0 {
		return
	}
	declared := make([]advisorysource.SourceConfig, 0, len(cfg.AdvisorySources))
	for _, s := range cfg.AdvisorySources {
		declared = append(declared, advisorysource.SourceConfig{Program: s.Program, URL: s.URL})
	}
	advisorysource.SetConfiguredSources(declared)
}

func applyLocalEgressConfig(cfg *config.Config) {
	if cfg == nil || cfg.Egress == nil || !cfg.Egress.Configured() {
		return
	}

	allowedHosts := sanitizeHosts(cfg.Egress.AllowedHosts)
	allowedCIDRs, err := cfg.Egress.AllowedCIDRPrefixes()
	if err != nil {
		slog.Warn("invalid egress configuration, skipping local allowlists", "error", err)
		return
	}

	var opts []network.Option
	if len(allowedHosts) > 0 {
		opts = append(opts, network.WithAllowedHosts(allowedHosts...))
	}
	if len(allowedCIDRs) > 0 {
		opts = append(opts, network.WithAllowedCIDRs(allowedCIDRs...))
	}
	if cfg.Egress.AllowLoopback {
		opts = append(opts, network.WithAllowLoopback())
	}
	if cfg.Egress.AllowLinkLocal {
		opts = append(opts, network.WithAllowLinkLocal())
	}

	if len(opts) == 0 {
		return
	}

	network.SetDefaultSafeDialerOptions(opts...)
	gitutil.InstallSafeGitTransport()
}

func sanitizeHosts(values []string) []string {
	out := make([]string, 0, len(values))
	for _, host := range values {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		out = append(out, host)
	}
	return out
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
	if _, ok := errors.AsType[*deputyerrors.SilentError](err); ok {
		return
	}
	fang.DefaultErrorHandler(w, styles, err)

	// Display suggestion if available to help users fix the issue.
	if suggestion := deputyerrors.GetSuggestion(err); suggestion != "" {
		io.WriteString(w, "\n")
		io.WriteString(w, styles.FlagDescription.Render("Suggestion: "+suggestion))
		io.WriteString(w, "\n")
	}
}

// newRoot returns the root command with all subcommands attached.
func newRoot() *cobra.Command {
	logLevel := defaultLogLevel()
	logFormat := defaultLogFormat()
	var serverAddr string
	var daemonSocket string
	var authToken string
	var noCache string

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
• server:  Run the Deputy API server

CONNECTION MODES:
Deputy can operate in two modes:
• In-process (default): Direct execution with zero network overhead
• Remote: Connect to a remote Deputy server via HTTP/2

Remote mode is selected with the --server flag or the DEPUTY_SERVER environment
variable; the flag takes precedence when both are set.

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
  deputy sbom --format spdx

CONNECTION MODES:
  # Use in-process mode (default)
  deputy scan

  # Connect to a remote server
  deputy --server https://deputy.example.com:8090 scan

  # Start a server for others to connect to
  deputy server --addr :8090`,
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", logLevel, "Logging level: debug, info, warn, error (default: warn). Override with DEPUTY_LOG_LEVEL")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", logFormat, "Logging format (text, json). Override with DEPUTY_LOG_FORMAT")
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "Connect to remote Deputy server (e.g., https://deputy.example.com:8090). Takes precedence over DEPUTY_SERVER; --server= (empty) forces in-process mode")
	rootCmd.PersistentFlags().StringVar(&daemonSocket, "daemon", "", "Reserved for future daemon support; has no effect as of August 2026")
	// Hidden while reserved: the flag stays parseable so scripts written against
	// it keep working when daemon mode lands, without adding help-text noise for
	// a mode that does not exist yet.
	_ = rootCmd.PersistentFlags().MarkHidden("daemon")
	rootCmd.PersistentFlags().StringVar(&authToken, "auth-token", "", "Bearer token for authenticating with remote server. Takes precedence over DEPUTY_AUTH_TOKEN; --auth-token= (empty) sends no token")
	rootCmd.PersistentFlags().StringVar(&noCache, "no-cache", "", "Bypass cache and fetch fresh data. Use 'true' for all caches, or comma-separated source names (e.g., 'osv,kev')")

	// Commands are registered before cobra parses the persistent flags, so the
	// connection settings resolve from the environment here and are re-resolved
	// in PersistentPreRunE once the flag values are known.
	deps := &cmd.Dependencies{}
	cmd.RegisterCommands(rootCmd, deps)

	rootCmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		if err := configureLogging(logLevel, logFormat); err != nil {
			return err
		}

		// Apply --no-cache flag to context if set
		if noCache != "" {
			ctx := cache.ApplyNoCacheFlag(c.Context(), noCache)
			c.SetContext(ctx)
		}

		// Re-apply the service connection now that persistent flags are
		// parsed: a flag the user set, even to an empty value, beats its
		// environment variable, and the environment variable beats the
		// in-process default. An explicitly empty --server forces in-process
		// mode and an explicitly empty --auth-token clears any token from
		// the environment, so cobra's Changed state is what distinguishes
		// "omitted" from "set to empty".
		serverSet := c.Flags().Changed("server")
		tokenSet := c.Flags().Changed("auth-token")
		if serverSet || tokenSet {
			if serverSet {
				deps.ServerAddress = serverAddr
			}
			if tokenSet {
				deps.AuthToken = authToken
			}
			if err := deps.ApplyConnection(); err != nil {
				return fmt.Errorf("configure server connection: %w", err)
			}
		}

		return nil
	}

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
