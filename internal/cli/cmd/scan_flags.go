package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/picatz/deputy/internal/cli/flags"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/report/render"
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
	PublishedBeforeStr string
	PublishedAfterStr  string
	AsOfStr            string

	// Policy configuration
	PolicyPaths []string

	// Display options
	ShowSymbols bool
	ShowDBInfo  bool

	// Scan options
	Ecosystems []string
	Ref        string

	// SBOM-specific
	InputFormat string
}

// displayOptions returns the VulnerabilityDisplayOptions derived from scan flags.
func (f scanFlags) displayOptions() render.VulnerabilityDisplayOptions {
	return render.VulnerabilityDisplayOptions{
		ShowSymbols:      f.ShowSymbols,
		ShowDatabaseInfo: f.ShowDBInfo,
	}
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
	f.PublishedBeforeStr, _ = cmd.Flags().GetString("published-before")
	f.PublishedAfterStr, _ = cmd.Flags().GetString("published-after")
	f.AsOfStr, _ = cmd.Flags().GetString("as-of")

	// Policy flags
	f.PolicyPaths, _ = cmd.Flags().GetStringArray("policy")

	// Display flags
	f.ShowSymbols, _ = cmd.Flags().GetBool("show-symbols")
	f.ShowDBInfo, _ = cmd.Flags().GetBool("show-db-info")

	// Scan options
	f.Ecosystems, _ = cmd.Flags().GetStringSlice("ecosystems")
	f.Ref, _ = cmd.Flags().GetString("ref")

	// SBOM-specific
	f.InputFormat, _ = cmd.Flags().GetString("input-format")

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
