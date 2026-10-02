package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/spf13/cobra"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	"github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/config"
	"github.com/temporalio/deputy/internal/ignore"
	inv "github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/report/render"
	"github.com/temporalio/deputy/internal/scanning"
)

// Output format constants used across CLI commands.
const (
	// FormatText is the human-readable text output format.
	FormatText = "text"
	// FormatJSON is the JSON output format.
	FormatJSON = "json"
	// FormatTSV is the tab-separated values output format.
	FormatTSV = "tsv"
	// FormatSARIF is the SARIF output format for security tools.
	FormatSARIF = "sarif"
	// FormatCycloneDX is the CycloneDX SBOM format.
	FormatCycloneDX = "cyclonedx"
	// FormatCycloneDXJSON is the CycloneDX JSON SBOM format.
	FormatCycloneDXJSON = "cyclonedx-json"
	// FormatSPDX is the SPDX SBOM format.
	FormatSPDX = "spdx"
	// FormatSPDXJSON is the SPDX JSON SBOM format.
	FormatSPDXJSON = "spdx-json"
)

// scanFlags holds common scan command flags to reduce duplication across
// runScan, runScanDir, and runScanSBOM.
type scanFlags struct {
	// Output configuration
	OutPath string
	Format  string

	// Filtering options
	IgnoreUnfixed      bool
	IgnoreFile         string // Path to ignore rules file
	PublishedBeforeStr string
	PublishedAfterStr  string
	AsOfStr            string
	Filter             string // CEL expression for filtering vulnerabilities

	// Policy configuration
	PolicyPaths []string

	// Display options
	ShowSymbols           bool
	ShowDBInfo            bool
	ShowUnfixableGuidance bool

	// Scan options
	Ecosystems []string
	Ref        string

	// ExcludePaths are directory-path glob patterns to skip during the walk.
	// Populated from the --exclude-path flag unioned with the config file's
	// scan.exclude_paths.
	ExcludePaths []string

	// SBOM-specific
	InputFormat string

	// Enrichment options
	Enrich bool

	// Graph option - enables dependency graph resolution for path analysis
	WithGraph bool

	// Secrets option - scan for leaked secrets in addition to vulnerabilities
	Secrets bool

	// DetectBaseImage enables base image detection for container image scans.
	// When enabled, queries deps.dev to determine if layers belong to known base images.
	DetectBaseImage bool

	// NoVerifyFixes disables fix resolution (Go module proxy installability
	// probes and migration detection). Verification is on by default.
	NoVerifyFixes bool

	// Cached ignore rules (populated by loadIgnoreRules)
	ignoreRules *ignore.Rules
}

// displayOptions returns the VulnerabilityDisplayOptions derived from scan flags.
func (f scanFlags) displayOptions() render.VulnerabilityDisplayOptions {
	return render.VulnerabilityDisplayOptions{
		ShowSymbols:           f.ShowSymbols,
		ShowDatabaseInfo:      f.ShowDBInfo,
		ShowUnfixableGuidance: f.ShowUnfixableGuidance,
	}
}

// displayOptionsWithResult returns VulnerabilityDisplayOptions including the graph from a scan result.
func (f scanFlags) displayOptionsWithResult(result scanning.Result) render.VulnerabilityDisplayOptions {
	opts := f.displayOptions()
	opts.Graph = result.Graph
	return opts
}

// scanOptions returns the inventory scan options derived from scan flags.
func (f scanFlags) scanOptions() inv.ScanOptions {
	return inv.ScanOptions{Ecosystems: f.Ecosystems, ExcludePaths: f.ExcludePaths}
}

// parsePublishedTimes parses the published time filters and returns before/after times.
func (f scanFlags) parsePublishedTimes(errW io.Writer) (beforeT, afterT time.Time) {
	return flags.ParsePublishedFilters(errW, f.AsOfStr, f.PublishedBeforeStr, f.PublishedAfterStr)
}

// extractScanFlags reads all common scan flags from a cobra command.
// This consolidates the repeated flag reading pattern across scan variants.
func extractScanFlags(cmd *cobra.Command) scanFlags {
	f := scanFlags{}

	// Output flags
	f.OutPath, _ = cmd.Flags().GetString("output")
	f.Format, _ = cmd.Flags().GetString("format")

	// Filtering flags
	f.IgnoreUnfixed, _ = cmd.Flags().GetBool("ignore-unfixed")
	f.IgnoreFile, _ = cmd.Flags().GetString("ignore-file")
	f.PublishedBeforeStr, _ = cmd.Flags().GetString("published-before")
	f.PublishedAfterStr, _ = cmd.Flags().GetString("published-after")
	f.AsOfStr, _ = cmd.Flags().GetString("as-of")
	f.Filter, _ = cmd.Flags().GetString("filter")

	// Policy flags
	f.PolicyPaths, _ = cmd.Flags().GetStringArray("policy")

	// Display flags
	f.ShowSymbols, _ = cmd.Flags().GetBool("show-symbols")
	f.ShowDBInfo, _ = cmd.Flags().GetBool("show-db-info")
	f.ShowUnfixableGuidance, _ = cmd.Flags().GetBool("show-unfixable-guidance")

	// Scan options
	f.Ecosystems, _ = cmd.Flags().GetStringSlice("ecosystems")
	f.Ref, _ = cmd.Flags().GetString("ref")

	// Path exclusions: config file's scan.exclude_paths unioned additively with
	// any --exclude-path flags (a flag never silently drops the committed list).
	f.ExcludePaths = excludePathsFromCmd(cmd)

	// SBOM-specific
	f.InputFormat, _ = cmd.Flags().GetString("input-format")

	// Enrichment options
	f.Enrich, _ = cmd.Flags().GetBool("enrich")

	// Graph option
	f.WithGraph, _ = cmd.Flags().GetBool("with-graph")

	// Secrets option
	f.Secrets, _ = cmd.Flags().GetBool("secrets")

	// Base image detection option
	f.DetectBaseImage, _ = cmd.Flags().GetBool("detect-base-image")

	// Fix verification (on by default; --no-verify-fixes disables proxy probes).
	// GetBool returns false when the flag isn't registered on a subcommand,
	// leaving verification enabled.
	f.NoVerifyFixes, _ = cmd.Flags().GetBool("no-verify-fixes")

	return f
}

// addExcludePathFlag registers the shared --exclude-path flag on a command.
// Used by scan-family and the other source-walking commands (diff, list,
// inventory, graph) so the flag is spelled and documented identically everywhere.
func addExcludePathFlag(cmd *cobra.Command) {
	cmd.Flags().StringArray("exclude-path", nil,
		"Glob of directory paths to skip during the walk (repeatable; e.g. '.bin/**'). Unioned with scan.exclude_paths from config")
}

// excludePathsFromCmd returns the effective path exclusions for a command: the
// config file's scan.exclude_paths unioned with any --exclude-path flags.
func excludePathsFromCmd(cmd *cobra.Command) []string {
	flagExcludes, _ := cmd.Flags().GetStringArray("exclude-path")
	return unionStrings(discoverConfigExcludePaths(), flagExcludes)
}

// discoverConfigExcludePaths returns scan.exclude_paths from an auto-discovered
// .deputy.yaml (relative to the current working directory, then home). A missing
// config yields no patterns. An unparseable one also yields none, which is safe
// only because the CLI refuses to run any command whose config file failed to
// load (see internal/cli.loadRuntimeConfig): by the time a scan reaches here the
// config is known to be loadable, so this returns nothing only when the setting
// is genuinely absent.
func discoverConfigExcludePaths() []string {
	path := config.FindConfigFile()
	if path == "" {
		return nil
	}
	cfg, err := config.NewLoader(path).Load()
	if err != nil {
		return nil
	}
	return cfg.Scan.ExcludePaths
}

// unionStrings concatenates string slices, trimming whitespace and dropping
// empties and duplicates while preserving first-seen order. Used to merge
// config-file and CLI-flag exclusion patterns additively.
func unionStrings(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// loadIgnoreRules loads ignore rules from the specified file or auto-discovers them.
// If IgnoreFile is set, loads from that file only.
// Otherwise, auto-discovers from .deputy.yaml, .deputyignore.yaml, and deputy-baseline.yaml.
func (f *scanFlags) loadIgnoreRules(workDir string) error {
	if f.ignoreRules != nil {
		return nil // Already loaded
	}

	var rules *ignore.Rules
	var err error

	if f.IgnoreFile != "" {
		// Load from specified file
		rules, err = ignore.LoadFromPath(f.IgnoreFile)
		if err != nil {
			return fmt.Errorf("loading ignore file %s: %w", f.IgnoreFile, err)
		}
	} else {
		// Auto-discover from working directory
		rules, err = ignore.LoadFromDirectory(workDir)
		if err != nil {
			return fmt.Errorf("loading ignore rules: %w", err)
		}
	}

	f.ignoreRules = rules
	return nil
}

// toScanRequest builds a scanv1.ScanRequest from CLI flags.
// This enables the CLI to use the Client interface consistently across
// in-process, daemon, and remote server modes.
func (f scanFlags) toScanRequest(target string, errW io.Writer) *scanv1.ScanRequest {
	beforeT, afterT := f.parsePublishedTimes(errW)

	opts := &scanv1.ScanOptions{
		Ecosystems:             f.Ecosystems,
		Ref:                    f.Ref,
		PolicyPaths:            f.PolicyPaths,
		IncludeSecrets:         f.Secrets,
		DetectBaseImage:        f.DetectBaseImage,
		DisableFixVerification: f.NoVerifyFixes,
		ExcludePaths:           f.ExcludePaths,
	}

	// Set published time filters
	if !beforeT.IsZero() {
		opts.PublishedBefore = timestamppb.New(beforeT)
	}
	if !afterT.IsZero() {
		opts.PublishedAfter = timestamppb.New(afterT)
	}

	// Set graph options
	if f.WithGraph {
		opts.GraphOptions = &scanv1.GraphOptions{
			Enabled:  true,
			UseProxy: true,
		}
	}

	// Set enrichment options
	if f.Enrich {
		opts.EnrichOptions = &scanv1.EnrichOptions{
			Enabled:     true,
			IncludeEpss: true,
			IncludeKev:  true,
		}
	}

	return &scanv1.ScanRequest{
		Target:  target,
		Options: opts,
	}
}

// toScanRequestWithHint builds a scanv1.ScanRequest with explicit target hint.
func (f scanFlags) toScanRequestWithHint(target string, kind targetv1.TargetKind, transport string, platform string, errW io.Writer) *scanv1.ScanRequest {
	req := f.toScanRequest(target, errW)

	// Set target hint for disambiguation
	req.Options.TargetHint = &scanv1.TargetHint{
		Kind:           kind,
		ImageTransport: transport,
	}

	// Set platform for container images
	if platform != "" {
		req.Options.Platform = platform
	}

	return req
}
