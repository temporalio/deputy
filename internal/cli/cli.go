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
	// Load configuration for runtime defaults (OTel, egress allowlists). A
	// config file that exists but cannot be loaded is fatal, not ignorable:
	// every setting it carries would otherwise revert to its default with
	// nothing said, and a configured advisory mirror quietly becoming the
	// public default sources is a security problem, not a degraded mode.
	//
	// The failure is carried into the root command instead of being returned
	// here, because main only maps a Run error to an exit code; reporting it
	// from PersistentPreRunE routes it through fang so the user sees the same
	// diagnostic 'deputy config show' prints. The merged settings travel with
	// it, so the commands that need configuration read this one rather than
	// loading their own and reaching a different answer.
	rc := loadRuntimeConfig()

	// Apply local egress allowlists before services are initialized.
	//
	// These three consumers run on the merged settings, before validation,
	// which cannot happen until the command line is parsed. So a config file
	// with one bad field now wires up whatever else it carries, where before it
	// would have wired up nothing: the egress relaxations get installed and an
	// OTel exporter gets built, and only then is the command refused. That is
	// deliberate. Each consumer already rejects what it cannot use on its own
	// (egress skips an unparseable CIDR, OTel falls back to its defaults), the
	// refusal follows immediately, and no command body runs in between.
	applyLocalEgressConfig(rc.Config)

	// Declare configured advisory sources; they are materialized lazily when a
	// scan builds its source registry, so non-scanning commands pay nothing.
	applyAdvisorySourceConfig(rc.Config)

	otelCfg := otel.DefaultConfig()
	if rc.Config != nil {
		otelCfg = rc.Config.OTel
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

	return fang.Execute(ctx, newRoot(rc), fang.WithErrorHandler(silentErrorHandler), fang.WithVersion(version.Value))
}

// runtimeConfig is what the CLI knows about configuration before cobra has
// parsed anything: the file and environment settings merged together, the file
// they came from, and any failure to get that far.
//
// Validation is deliberately not part of it. The merged value is not the
// effective one until the command line is parsed, because flags outrank both
// sources, so the gate in newRoot validates instead, once, with the flags
// applied.
type runtimeConfig struct {
	// Config is the merged file and environment settings. It is nil only when
	// Err is non-nil.
	Config *config.Config

	// Path is the config file the settings were read from, empty when no file
	// was found. It is what the diagnostic names.
	Path string

	// Err reports a configuration source that was named but could not be read
	// or parsed. No flag corrects that, so it is fatal on its own.
	Err error
}

// loadRuntimeConfig merges configuration from the environment and the
// auto-discovered config file. A non-nil Err means a configuration source was
// present but unusable (missing when named explicitly, or unreadable or
// malformed), which callers must treat as fatal: continuing would silently
// substitute defaults for whatever the file configured. That means querying the
// public advisory sources in place of a pinned internal mirror, exporting no
// telemetry, and dropping the egress relaxations that let allowlisted internal
// hosts resolve to private addresses. Finding no config file at all is not an
// error, it yields the defaults with a nil Err.
func loadRuntimeConfig() runtimeConfig {
	configPath, err := config.ResolveConfigFile()
	if err != nil {
		// An explicitly requested file that is not there is the same downgrade
		// this function exists to prevent: without this, discovery would fall
		// back to some other file, or to none, and the command would run on
		// settings the operator did not ask for.
		return runtimeConfig{Err: deputyerrors.Suggest(
			fmt.Errorf("failed to load config: %w", err),
			"Point DEPUTY_CONFIG at a readable config file, or unset it to use auto-discovery",
		)}
	}
	cfg, err := config.NewLoader(configPath).LoadMerged()
	if err != nil {
		return runtimeConfig{Path: configPath, Err: configLoadError(configPath, err)}
	}
	return runtimeConfig{Config: cfg, Path: configPath}
}

// configGateError reports the configuration failure that must stop cmd, or nil
// when the invocation is usable. It runs from PersistentPreRunE rather than
// from the load, because that is the first moment the effective configuration
// exists: cobra has parsed the command line by then, so a flag the user set can
// correct a value the environment or the file got wrong, which is the
// precedence the reference documents. Validating earlier rejected values the
// invocation had already replaced, and it did so for every override-capable
// flag, one finding at a time.
//
// The overrides land on the shared configuration rather than on a copy, so the
// commands handed that configuration see the corrected values too.
func configGateError(rc runtimeConfig, cmd *cobra.Command) error {
	if rc.Err != nil {
		return rc.Err
	}
	if rc.Config == nil {
		return nil
	}
	config.ApplyOverrides(rc.Config, flagOverrides(cmd))
	if err := rc.Config.Validate(); err != nil {
		return configLoadError(rc.Path, err)
	}
	return nil
}

// flagOverrides collects the flags the invocation set explicitly, keyed by flag
// name, for config.ApplyOverrides to pick from. It reports every changed flag
// rather than a chosen few: which flags configuration cares about is the
// config package's business, and a list kept here would have to be extended
// for each new override-capable flag, which is how command-specific flags came
// to be missing from the validated merge in the first place.
//
// cmd is the command cobra resolved, so its flag set already carries the
// persistent flags inherited from the root alongside its own. Arguments after
// "--" are not flags to pflag, so a passthrough such as
// 'deputy proxy npm -- npm install --log-level=silly' cannot contribute one.
func flagOverrides(cmd *cobra.Command) config.Overrides {
	flags := cmd.Flags()
	overrides := make(config.Overrides, flags.NFlag())
	flags.Visit(func(f *pflag.Flag) {
		if slice, ok := f.Value.(pflag.SliceValue); ok {
			overrides[f.Name] = slice.GetSlice()
			return
		}
		overrides[f.Name] = []string{f.Value.String()}
	})
	return overrides
}

// configLoadError turns a load failure into a diagnostic that points at a
// source which can actually be at fault. Read and parse failures are the file's
// by construction, since the loader only raises them with a file in hand.
// Validation is different: it runs on the merged result of file, environment,
// and flags, so blaming the file for it sends the operator to
// 'deputy config validate', which passes, and teaches them nothing. Where the
// provenance is genuinely unknown, the message says so rather than guessing.
func configLoadError(configPath string, err error) error {
	if _, ok := errors.AsType[*deputyerrors.ConfigError](err); ok {
		// ConfigError already names the path it failed to read or parse.
		return deputyerrors.Suggest(
			fmt.Errorf("failed to load config: %w", err),
			fmt.Sprintf("Fix the file, or run 'deputy config validate %s' for details", configPath),
		)
	}
	if configPath == "" {
		return deputyerrors.Suggest(
			fmt.Errorf("invalid configuration: %w", err),
			"No config file was loaded, so check the DEPUTY_* environment variables for an invalid value",
		)
	}
	return deputyerrors.Suggest(
		fmt.Errorf("invalid configuration: %w", err),
		fmt.Sprintf("The value can come from %s or from a DEPUTY_* environment variable, which overrides the file; check both", configPath),
	)
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

// newRoot returns the root command with all subcommands attached. rc carries
// the configuration merged before command construction, handed to the commands
// that need it so none of them loads its own and reaches a different answer.
// Whatever cannot be honored in it, either because the file would not load or
// because the merged result fails validation once the flags are in, stops every
// command outside commandsRunnableWithoutConfig, so a config file that cannot
// be honored never masquerades as an absent one.
func newRoot(rc runtimeConfig) *cobra.Command {
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
	deps := &cmd.Dependencies{Config: rc.Config}
	cmd.RegisterCommands(rootCmd, deps)

	rootCmd.PersistentPreRunE = func(c *cobra.Command, args []string) error {
		// Refuse to run on a configuration that cannot be honored. This is
		// checked first: a command that proceeds here would query the default
		// advisory sources instead of the configured ones, export no
		// telemetry, and lose the egress relaxations the file granted, none of
		// which the user asked for. A short allowlist of commands that do not
		// act on configuration stays runnable, so the failure can be diagnosed
		// and reported.
		exempt := runsWithoutConfig(c)
		if configErr := configGateError(rc, c); configErr != nil && !exempt {
			return configErr
		}

		if err := configureLogging(logLevel, logFormat); err != nil {
			if !exempt {
				return err
			}
			// Exempt means exempt for the whole startup, not just for the
			// check above. An invalid DEPUTY_LOG_LEVEL is a configuration
			// fault like any other, and taking 'deputy version' or shell
			// completion down with it defeats the point of the allowlist, so
			// these commands fall back to the built-in logging defaults.
			slog.Debug("ignoring invalid logging configuration for a command that runs without configuration", "error", err)
			if err := configureLogging(fallbackLogLevel, fallbackLogFormat); err != nil {
				return err
			}
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

// commandsRunnableWithoutConfig is the allowlist of top-level commands that
// still run when the discovered config file cannot be loaded. Membership is
// earned by not acting on configuration at all:
//
//   - config, because its subcommands exist to diagnose exactly this failure,
//     and refusing to run them would take away the tools that explain it.
//   - version, because it is the first thing a user runs when filing a bug
//     report, and because 'deputy --version' answers with the version whether
//     or not a config file loads; the subcommand must not disagree with it.
//   - completion and cobra's hidden completion helpers, because their output is
//     sourced at shell startup and requested on every tab press, so gating them
//     would inject errors into an interactive shell rather than into a command
//     the user chose to run.
//   - help, because the help command (unlike the --help flag, which cobra
//     resolves before this check) is dispatched like any other command.
var commandsRunnableWithoutConfig = map[string]bool{
	"config":                        true,
	"version":                       true,
	"completion":                    true,
	"help":                          true,
	cobra.ShellCompRequestCmd:       true,
	cobra.ShellCompNoDescRequestCmd: true,
}

// runsWithoutConfig reports whether cmd belongs to a top-level command that is
// allowed to run when configuration could not be loaded. The allowlist is keyed
// on the top-level command rather than on cmd's own name, so a future
// subcommand that happens to share an exempt name (say 'deputy proxy config')
// cannot inherit the exemption and quietly become runnable on a config file
// that failed to load.
func runsWithoutConfig(cmd *cobra.Command) bool {
	top := topLevelCommand(cmd)
	if top == nil {
		// The root command itself, which runs diff when invoked bare, so it
		// acts on configuration and is not exempt.
		return false
	}
	return commandsRunnableWithoutConfig[top.Name()]
}

// topLevelCommand returns the ancestor of cmd that is a direct child of the
// root command, or nil when cmd is the root itself.
func topLevelCommand(cmd *cobra.Command) *cobra.Command {
	for c := cmd; c != nil; c = c.Parent() {
		parent := c.Parent()
		if parent == nil {
			return nil
		}
		if !parent.HasParent() {
			return c
		}
	}
	return nil
}

// isInGitRepo checks if the current working directory is inside a git repository.
func isInGitRepo() bool {
	// Use the internal git package to check if we're in a Git repository.
	_, err := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	return err == nil
}

const (
	// fallbackLogLevel and fallbackLogFormat are the built-in logging settings.
	// Warn keeps interactive output clean; they are also what a command that
	// runs without configuration falls back to when the requested values do
	// not parse.
	fallbackLogLevel  = "warn"
	fallbackLogFormat = "text"
)

// defaultLogLevel returns the default log level from the environment or "warn".
// Default is warn to keep CLI output clean for interactive use. Users who want
// verbose observability logs can set DEPUTY_LOG_LEVEL=info or --log-level=info.
func defaultLogLevel() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_LEVEL")); v != "" {
		return v
	}
	return fallbackLogLevel
}

// defaultLogFormat returns the default log format from the environment or "text".
func defaultLogFormat() string {
	if v := strings.TrimSpace(os.Getenv("DEPUTY_LOG_FORMAT")); v != "" {
		return v
	}
	return fallbackLogFormat
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
