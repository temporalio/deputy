package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"google.golang.org/protobuf/types/known/timestamppb"

	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/ignore"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/scanning"
	"github.com/picatz/deputy/internal/targets"
	"github.com/spf13/cobra"
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

	// Cached ignore rules (populated by loadIgnoreRules)
	ignoreRules *ignore.Rules
}

// displayOptions returns the VulnerabilityDisplayOptions derived from scan flags.
// This is a base method - prefer displayOptionsWithResult when target info is available.
func (f scanFlags) displayOptions() render.VulnerabilityDisplayOptions {
	return render.VulnerabilityDisplayOptions{
		ShowSymbols:           f.ShowSymbols,
		ShowDatabaseInfo:      f.ShowDBInfo,
		ShowUnfixableGuidance: f.ShowUnfixableGuidance,
		ShowDirectIndirect:    true, // Default to true for backwards compatibility
	}
}

// displayOptionsWithResult returns VulnerabilityDisplayOptions including the graph from a scan result.
// It automatically sets ShowDirectIndirect based on the target kind and available info.
func (f scanFlags) displayOptionsWithResult(result scanning.Result) render.VulnerabilityDisplayOptions {
	opts := f.displayOptions()
	opts.Graph = result.Graph
	// Show [direct]/[indirect] labels for:
	// 1. Repository-like targets (always have direct/indirect from manifest parsing)
	// 2. Container images when base image detection was used (LayerDetails populated)
	opts.ShowDirectIndirect = supportsDirectIndirectKind(result.Target.Kind) || hasBaseImageInfoFromPackages(result.Packages)
	return opts
}

// supportsDirectIndirectKind returns true if the target kind supports direct/indirect
// dependency distinction. Only repository-like targets have meaningful direct/indirect
// semantics; container images, binaries, and other artifact types just have packages "present".
func supportsDirectIndirectKind(kind targets.Kind) bool {
	switch kind {
	case targets.KindDir, targets.KindGit, targets.KindFile:
		return true
	default:
		// Container images, binaries, VM images, cloud resources, SBOMs, etc.
		// don't have meaningful direct/indirect distinction by default
		return false
	}
}

// hasBaseImageInfoFromPackages returns true if base image detection was used and
// meaningful direct/indirect info is available. This is indicated by at least one
// package having InBaseImage=true. Without base image detection, InBaseImage defaults
// to false for all packages, making the distinction meaningless.
func hasBaseImageInfoFromPackages(pkgs []*extractor.Package) bool {
	for _, pkg := range pkgs {
		if pkg != nil && pkg.LayerDetails != nil && pkg.LayerDetails.InBaseImage {
			return true
		}
	}
	return false
}

// scanOptions returns the inventory scan options derived from scan flags.
func (f scanFlags) scanOptions() inv.ScanOptions {
	return inv.ScanOptions{Ecosystems: f.Ecosystems}
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

	return f
}

// outputWriter represents a writer that may need to be closed.
type outputWriter struct {
	Writer io.Writer
	closer io.Closer
}

// Close closes the underlying writer if it's a file.
func (ow *outputWriter) Close() error {
	if ow.closer != nil {
		return ow.closer.Close()
	}
	return nil
}

// openOutputWriter creates an output writer based on the output path.
// If outPath is empty or "-", it returns stdout. Otherwise, it creates a file.
// The caller must call Close() on the returned outputWriter.
func openOutputWriter(cmd *cobra.Command, outPath string) (*outputWriter, error) {
	if outPath == "" || outPath == "-" {
		return &outputWriter{Writer: cmd.OutOrStdout()}, nil
	}

	f, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	return &outputWriter{Writer: f, closer: f}, nil
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
		Ecosystems:      f.Ecosystems,
		Ref:             f.Ref,
		PolicyPaths:     f.PolicyPaths,
		IncludeSecrets:  f.Secrets,
		DetectBaseImage: f.DetectBaseImage,
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
