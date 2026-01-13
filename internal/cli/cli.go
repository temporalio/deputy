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
	"github.com/picatz/deputy/internal/cache"
	"github.com/picatz/deputy/internal/cli/cmd"
	"github.com/picatz/deputy/internal/config"
	deputyerrors "github.com/picatz/deputy/internal/errors"
	"github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/network"
	"github.com/picatz/deputy/internal/otel"
	_ "github.com/picatz/deputy/internal/targets/providers"
	"github.com/picatz/deputy/internal/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Run constructs the root command hierarchy and executes it with all
// subcommands registered. It is the primary entry point used by main.
func Run(ctx context.Context) error {
	// Load configuration for runtime defaults (OTel, egress allowlists).
	cfg := loadRuntimeConfig()

	// Apply local egress allowlists before services are initialized.
	applyLocalEgressConfig(cfg)

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
	var silent *deputyerrors.SilentError
	if errors.As(err, &silent) {
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
Deputy can operate in three modes:
• In-process (default): Direct execution with zero network overhead
• Local daemon: Connect to a running 'deputy server' via Unix socket
• Remote: Connect to a remote Deputy server via HTTP/2

Mode is auto-detected (remote if DEPUTY_SERVER is set, daemon if socket exists),
or can be forced with --server or --daemon flags.

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

  # Connect to a local daemon
  deputy --daemon /tmp/deputy.sock scan

  # Start a server for others to connect to
  deputy server --addr :8090`,
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", logLevel, "Logging level: debug, info, warn, error (default: warn). Override with DEPUTY_LOG_LEVEL")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", logFormat, "Logging format (text, json). Override with DEPUTY_LOG_FORMAT")
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "Connect to remote Deputy server (e.g., https://deputy.example.com:8090). Override with DEPUTY_SERVER")
	rootCmd.PersistentFlags().StringVar(&daemonSocket, "daemon", "", "Connect to local daemon via Unix socket path (reserved for future use)")
	rootCmd.PersistentFlags().StringVar(&authToken, "auth-token", "", "Bearer token for authenticating with remote server. Override with DEPUTY_AUTH_TOKEN")
	rootCmd.PersistentFlags().StringVar(&noCache, "no-cache", "", "Bypass cache and fetch fresh data. Use 'true' for all caches, or comma-separated source names (e.g., 'osv,kev')")
	rootCmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		if err := configureLogging(logLevel, logFormat); err != nil {
			return err
		}

		// Apply --no-cache flag to context if set
		if noCache != "" {
			ctx := cache.ApplyNoCacheFlag(c.Context(), noCache)
			c.SetContext(ctx)
		}

		return nil
	}

	// Register commands with server address from flags
	// Clients will be created by RegisterCommands based on environment/flags
	cmd.RegisterCommands(rootCmd, cmd.Dependencies{
		ServerAddress: serverAddr,
		AuthToken:     authToken,
	})
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
