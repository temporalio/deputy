package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// SBOMDiff represents the difference between two SBOMs.
type SBOMDiff struct {
	// Added contains packages present in the new SBOM but not in the old.
	Added []PackageSummary `json:"added,omitempty"`
	// Removed contains packages present in the old SBOM but not in the new.
	Removed []PackageSummary `json:"removed,omitempty"`
	// Changed contains packages with version changes between SBOMs.
	Changed []PackageChange `json:"changed,omitempty"`
	// Stats provides summary statistics.
	Stats DiffStats `json:"stats"`
}

// PackageSummary is a simplified view of a package for diff output.
type PackageSummary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// PackageChange represents a version change for a package.
type PackageChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	PURL       string `json:"purl,omitempty"`
}

// DiffStats provides summary statistics for the diff.
type DiffStats struct {
	OldTotal       int `json:"old_total"`
	NewTotal       int `json:"new_total"`
	AddedCount     int `json:"added"`
	RemovedCount   int `json:"removed"`
	ChangedCount   int `json:"changed"`
	UnchangedCount int `json:"unchanged"`
}

// addSBOMDiffCommand adds the 'sbom diff' subcommand.
func addSBOMDiffCommand(sbomCmd *cobra.Command) {
	var (
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "diff <old-sbom> <new-sbom>",
		Short: "Compare two SBOMs and show differences",
		Long: `Compare two SBOM documents and display the differences.

This command analyzes two SBOMs and identifies:
  - Packages added in the new SBOM
  - Packages removed from the old SBOM
  - Packages with version changes

SUPPORTED INPUT FORMATS:
  - Protobom JSON
  - CycloneDX JSON
  - SPDX JSON

USAGE:
  # Compare two SBOMs
  deputy sbom diff old.json new.json

  # Output as JSON for further processing
  deputy sbom diff old.json new.json --format json

  # Compare release versions
  deputy sbom diff v1.0.0-sbom.json v2.0.0-sbom.json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldPath := args[0]
			newPath := args[1]

			// Read both SBOMs
			oldDoc, err := readSBOMForDiff(oldPath)
			if err != nil {
				return fmt.Errorf("failed to read old SBOM %s: %w", oldPath, err)
			}

			newDoc, err := readSBOMForDiff(newPath)
			if err != nil {
				return fmt.Errorf("failed to read new SBOM %s: %w", newPath, err)
			}

			// Calculate diff
			diff := calculateSBOMDiff(oldDoc, newDoc)

			// Output
			switch strings.ToLower(outputFormat) {
			case "json":
				return outputDiffJSON(cmd.OutOrStdout(), diff)
			default:
				return outputDiffText(cmd.OutOrStdout(), diff, oldPath, newPath)
			}
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text | json")

	sbomCmd.AddCommand(cmd)
}

// readSBOMForDiff reads an SBOM file and returns it as a protobom document.
func readSBOMForDiff(path string) (*sbom.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Try protobom format first
	doc := &sbom.Document{}
	if err := protojson.Unmarshal(data, doc); err == nil && doc.NodeList != nil {
		return doc, nil
	}

	// Try CycloneDX format
	var cdx map[string]interface{}
	if err := json.Unmarshal(data, &cdx); err == nil {
		if _, ok := cdx["bomFormat"]; ok {
			return convertCycloneDXToProtobom(cdx)
		}
		// Try SPDX format
		if _, ok := cdx["spdxVersion"]; ok {
			return convertSPDXToProtobom(cdx)
		}
	}

	return nil, fmt.Errorf("unsupported SBOM format (expected protobom-json, cyclonedx-json, or spdx-json)")
}

// convertCycloneDXToProtobom converts a CycloneDX document to protobom.
func convertCycloneDXToProtobom(cdx map[string]interface{}) (*sbom.Document, error) {
	doc := sbom.NewDocument()
	doc.NodeList = &sbom.NodeList{}

	components, ok := cdx["components"].([]interface{})
	if !ok {
		return doc, nil
	}

	for _, comp := range components {
		c, ok := comp.(map[string]interface{})
		if !ok {
			continue
		}

		node := sbom.NewNode()
		if name, ok := c["name"].(string); ok {
			node.Name = name
		}
		if version, ok := c["version"].(string); ok {
			node.Version = version
		}
		if purl, ok := c["purl"].(string); ok {
			if node.Identifiers == nil {
				node.Identifiers = make(map[int32]string)
			}
			node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purl
		}
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
	}

	return doc, nil
}

// convertSPDXToProtobom converts an SPDX document to protobom.
func convertSPDXToProtobom(spdx map[string]interface{}) (*sbom.Document, error) {
	doc := sbom.NewDocument()
	doc.NodeList = &sbom.NodeList{}

	packages, ok := spdx["packages"].([]interface{})
	if !ok {
		return doc, nil
	}

	for _, pkg := range packages {
		p, ok := pkg.(map[string]interface{})
		if !ok {
			continue
		}

		node := sbom.NewNode()
		if name, ok := p["name"].(string); ok {
			node.Name = name
		}
		if version, ok := p["versionInfo"].(string); ok {
			node.Version = version
		}
		// Extract PURL from external refs
		if refs, ok := p["externalRefs"].([]interface{}); ok {
			for _, ref := range refs {
				r, ok := ref.(map[string]interface{})
				if !ok {
					continue
				}
				if refType, ok := r["referenceType"].(string); ok && refType == "purl" {
					if purl, ok := r["referenceLocator"].(string); ok {
						if node.Identifiers == nil {
							node.Identifiers = make(map[int32]string)
						}
						node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = purl
					}
				}
			}
		}
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
	}

	return doc, nil
}

// calculateSBOMDiff computes the difference between two SBOM documents.
func calculateSBOMDiff(oldDoc, newDoc *sbom.Document) SBOMDiff {
	// Build maps of packages by name for comparison
	oldPkgs := buildPackageMap(oldDoc)
	newPkgs := buildPackageMap(newDoc)

	var diff SBOMDiff
	diff.Stats.OldTotal = len(oldPkgs)
	diff.Stats.NewTotal = len(newPkgs)

	// Find added and changed packages
	for name, newPkg := range newPkgs {
		if oldPkg, exists := oldPkgs[name]; exists {
			if oldPkg.Version != newPkg.Version {
				diff.Changed = append(diff.Changed, PackageChange{
					Name:       name,
					OldVersion: oldPkg.Version,
					NewVersion: newPkg.Version,
					PURL:       newPkg.PURL,
				})
			} else {
				diff.Stats.UnchangedCount++
			}
		} else {
			diff.Added = append(diff.Added, newPkg)
		}
	}

	// Find removed packages
	for name, oldPkg := range oldPkgs {
		if _, exists := newPkgs[name]; !exists {
			diff.Removed = append(diff.Removed, oldPkg)
		}
	}

	// Sort results
	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].Name < diff.Added[j].Name })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].Name < diff.Removed[j].Name })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].Name < diff.Changed[j].Name })

	// Update stats
	diff.Stats.AddedCount = len(diff.Added)
	diff.Stats.RemovedCount = len(diff.Removed)
	diff.Stats.ChangedCount = len(diff.Changed)

	return diff
}

// buildPackageMap creates a map of packages from an SBOM document.
func buildPackageMap(doc *sbom.Document) map[string]PackageSummary {
	pkgs := make(map[string]PackageSummary)
	if doc == nil || doc.NodeList == nil {
		return pkgs
	}

	for _, node := range doc.NodeList.Nodes {
		if node == nil || node.Name == "" {
			continue
		}
		// Use PURL as key if available, otherwise use name
		purl := ""
		if node.Identifiers != nil {
			purl = node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
		}
		key := node.Name
		if purl != "" {
			// Extract name from PURL for better grouping
			key = extractNameFromPURL(purl)
		}
		pkgs[key] = PackageSummary{
			Name:    node.Name,
			Version: node.Version,
			PURL:    purl,
		}
	}
	return pkgs
}

// extractNameFromPURL extracts a normalized package name from a PURL.
func extractNameFromPURL(purl string) string {
	// pkg:type/namespace/name@version -> namespace/name or name
	purl = strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(purl, "/", 2)
	if len(parts) < 2 {
		return purl
	}
	// Remove type prefix
	rest := parts[1]
	// Remove version
	if idx := strings.Index(rest, "@"); idx > 0 {
		rest = rest[:idx]
	}
	return rest
}

// outputDiffJSON outputs the diff as JSON.
func outputDiffJSON(w io.Writer, diff SBOMDiff) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(diff)
}

// outputDiffText outputs the diff in human-readable text format.
func outputDiffText(w io.Writer, diff SBOMDiff, oldPath, newPath string) error {
	fmt.Fprintf(w, "SBOM Diff: %s -> %s\n", oldPath, newPath)
	fmt.Fprintf(w, "========================================\n\n")

	fmt.Fprintf(w, "Summary:\n")
	fmt.Fprintf(w, "  Old SBOM: %d packages\n", diff.Stats.OldTotal)
	fmt.Fprintf(w, "  New SBOM: %d packages\n", diff.Stats.NewTotal)
	fmt.Fprintf(w, "  Added:    %d\n", diff.Stats.AddedCount)
	fmt.Fprintf(w, "  Removed:  %d\n", diff.Stats.RemovedCount)
	fmt.Fprintf(w, "  Changed:  %d\n", diff.Stats.ChangedCount)
	fmt.Fprintf(w, "  Unchanged: %d\n\n", diff.Stats.UnchangedCount)

	if len(diff.Added) > 0 {
		fmt.Fprintf(w, "Added (%d):\n", len(diff.Added))
		for _, pkg := range diff.Added {
			fmt.Fprintf(w, "  + %s@%s\n", pkg.Name, pkg.Version)
		}
		fmt.Fprintln(w)
	}

	if len(diff.Removed) > 0 {
		fmt.Fprintf(w, "Removed (%d):\n", len(diff.Removed))
		for _, pkg := range diff.Removed {
			fmt.Fprintf(w, "  - %s@%s\n", pkg.Name, pkg.Version)
		}
		fmt.Fprintln(w)
	}

	if len(diff.Changed) > 0 {
		fmt.Fprintf(w, "Changed (%d):\n", len(diff.Changed))
		for _, pkg := range diff.Changed {
			fmt.Fprintf(w, "  ~ %s: %s -> %s\n", pkg.Name, pkg.OldVersion, pkg.NewVersion)
		}
		fmt.Fprintln(w)
	}

	return nil
}
