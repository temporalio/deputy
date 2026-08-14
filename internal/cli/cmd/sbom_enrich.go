package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	sbomx "github.com/temporalio/deputy/internal/sbom"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// addSBOMEnrichCommand adds the 'sbom enrich' subcommand.
func addSBOMEnrichCommand(sbomCmd *cobra.Command) {
	var (
		outPath           string
		format            string
		enrichConcurrency int
		addCPEs           bool
		addSuppliers      bool
		addExternalRefs   bool
		addPublishedDate  bool
		showScore         bool
	)

	cmd := &cobra.Command{
		Use:   "enrich <sbom-file>",
		Short: "Enrich an existing SBOM with additional metadata",
		Long: `Enrich an existing SBOM document with additional metadata from deps.dev.

This command takes an existing SBOM (in Protobom JSON format) and enriches it
with additional metadata including:
  - CPE identifiers for vulnerability correlation
  - Supplier/maintainer information
  - External references (VCS URLs, homepage, issue tracker)
  - Package publish dates

The enriched SBOM can be output in any supported format.

USAGE:
  # Enrich an SBOM and output to stdout
  deputy sbom enrich my-sbom.json

  # Enrich and save to a new file
  deputy sbom enrich my-sbom.json --output enriched-sbom.json

  # Enrich specific fields only
  deputy sbom enrich my-sbom.json --add-cpes --add-suppliers

  # Show completeness score after enrichment
  deputy sbom enrich my-sbom.json --show-score`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			inputPath := args[0]

			// Read the input SBOM
			doc, err := readProtobomDocument(inputPath)
			if err != nil {
				return fmt.Errorf("failed to read SBOM: %w", err)
			}

			// Determine what to enrich
			// If no specific flags are set, enrich everything
			enrichAll := !addCPEs && !addSuppliers && !addExternalRefs && !addPublishedDate
			if enrichAll {
				addCPEs = true
				addSuppliers = true
				addExternalRefs = true
				addPublishedDate = true
			}

			// Run enrichment
			concurrency := enrichConcurrency
			if concurrency <= 0 {
				concurrency = 10
			}
			enrichOpts := sbomx.EnrichOptions{
				AddCPEs:          addCPEs,
				AddSuppliers:     addSuppliers,
				AddExternalRefs:  addExternalRefs,
				AddPublishedDate: addPublishedDate,
				Concurrency:      concurrency,
			}

			result, err := sbomx.Enrich(ctx, doc, enrichOpts)
			if err != nil {
				return fmt.Errorf("failed to enrich SBOM: %w", err)
			}

			// Show score if requested
			if showScore {
				score := sbomx.CalculateCompleteness(doc)
				fmt.Fprintf(cmd.ErrOrStderr(), "Enrichment complete:\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "  Nodes enriched:    %d/%d\n", result.NodesEnriched, result.NodesProcessed)
				fmt.Fprintf(cmd.ErrOrStderr(), "  CPEs added:        %d\n", result.CPEsAdded)
				fmt.Fprintf(cmd.ErrOrStderr(), "  Suppliers added:   %d\n", result.SuppliersAdded)
				fmt.Fprintf(cmd.ErrOrStderr(), "  Ext. refs added:   %d\n", result.ExternalRefsAdded)
				fmt.Fprintf(cmd.ErrOrStderr(), "\nCompleteness Score: %.1f%%\n", score.Score*100)
				if score.NTIACompliant {
					fmt.Fprintf(cmd.ErrOrStderr(), "NTIA Status: Compliant\n")
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "NTIA Status: Non-compliant\n")
					if len(score.NTIAMissing) > 0 {
						fmt.Fprintf(cmd.ErrOrStderr(), "Missing: %s\n", strings.Join(score.NTIAMissing, ", "))
					}
				}
				fmt.Fprintln(cmd.ErrOrStderr())
			}

			// Write output
			out, err := openOutputWriter(cmd, outPath)
			if err != nil {
				return err
			}
			defer out.Close()
			w := out.Writer

			// Write in requested format
			switch strings.ToLower(format) {
			case "cyclonedx-json", "cyclonedx", "cdx":
				return sbomx.WriteCycloneDXJSON(doc, w)
			case "spdx-json", "spdx":
				return sbomx.WriteSPDXJSON(doc, w)
			case "protobom-json", "protobom", "pb":
				return sbomx.WriteProtobomJSON(doc, w)
			default:
				return fmt.Errorf("unsupported output format: %s (use cyclonedx-json, spdx-json, or protobom-json)", format)
			}
		},
	}

	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().StringVarP(&format, "format", "f", "cyclonedx-json", "Output format: cyclonedx-json | spdx-json | protobom-json")
	cmd.Flags().IntVar(&enrichConcurrency, "concurrency", 10, "Max concurrent deps.dev requests")
	cmd.Flags().BoolVar(&addCPEs, "add-cpes", false, "Add CPE identifiers (if not set, all enrichments are applied)")
	cmd.Flags().BoolVar(&addSuppliers, "add-suppliers", false, "Add supplier/maintainer info")
	cmd.Flags().BoolVar(&addExternalRefs, "add-external-refs", false, "Add external references (VCS, homepage, etc.)")
	cmd.Flags().BoolVar(&addPublishedDate, "add-published-date", false, "Add package publish dates")
	cmd.Flags().BoolVar(&showScore, "show-score", false, "Show completeness score after enrichment")

	sbomCmd.AddCommand(cmd)
}

// readProtobomDocument reads a Protobom JSON document from a file or stdin.
func readProtobomDocument(path string) (*sbom.Document, error) {
	var data []byte
	var err error

	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}

	doc := &sbom.Document{}
	if err := protojson.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM (must be Protobom JSON format): %w", err)
	}

	return doc, nil
}
