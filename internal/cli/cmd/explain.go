package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/analysis/osv"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/spf13/cobra"
)

// AddExplainCommand adds the explain command to the root command.
func AddExplainCommand(root *cobra.Command) {
	var (
		formatFlag string
		verbose    bool
	)

	explainCmd := &cobra.Command{
		Use:   "explain <vuln-id> [vuln-id...]",
		Short: "Explain vulnerabilities by ID",
		Long: `Get detailed information about vulnerabilities by their IDs.

Fetches vulnerability data from OSV and displays a clear, concise summary
including severity, description, affected versions, and remediation guidance.

Accepts CVE, GHSA, GO-, RUSTSEC-, and other OSV-compatible identifiers.`,
		Example: `  # Explain a single vulnerability
  deputy explain CVE-2021-44228

  # Explain multiple vulnerabilities
  deputy explain GHSA-jfh8-c2j2-2hch CVE-2023-45853

  # Show verbose output with full details
  deputy explain --verbose CVE-2021-44228

  # Output as JSON
  deputy explain --format json CVE-2021-44228`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			client := osv.NewClient()

			for i, id := range args {
				if i > 0 {
					fmt.Fprintln(out)
				}

				vuln, err := client.GetVulnByID(ctx, id)
				if err != nil {
					fmt.Fprintf(out, "%s %s: %v\n", ui.StyleRemoved.Render("error"), id, err)
					continue
				}
				if vuln == nil {
					fmt.Fprintf(out, "%s %s: not found\n", ui.StyleRemoved.Render("error"), id)
					continue
				}

				if formatFlag == "json" {
					renderVulnJSON(out, vuln)
				} else {
					renderVulnText(out, vuln, verbose)
				}
			}

			return nil
		},
	}

	explainCmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format: text, json")
	explainCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show full details including description")

	root.AddCommand(explainCmd)
}

// renderVulnText displays vulnerability details in a human-readable format.
func renderVulnText(out io.Writer, vuln *osvschema.Vulnerability, verbose bool) {
	if out == nil || vuln == nil {
		return
	}

	// Extract severity
	severity := extractVulnSeverity(vuln)
	severityStyle := severityStyleFor(severity.Level)

	// Header with ID and severity
	fmt.Fprintf(out, "%s %s\n", ui.StylePackageName.Render(vuln.ID), severityStyle.Render(severity.Level.String()))

	// Aliases
	if len(vuln.Aliases) > 0 {
		fmt.Fprintf(out, "%s %s\n", ui.StyleDim.Render("Aliases:"), strings.Join(vuln.Aliases, ", "))
	}

	// Summary
	if vuln.Summary != "" {
		fmt.Fprintf(out, "\n%s\n", vuln.Summary)
	}

	// Details (verbose only)
	if verbose && vuln.Details != "" {
		fmt.Fprintf(out, "\n%s\n%s\n", ui.StyleDim.Render("Details:"), wrapDetailsText(vuln.Details, 80))
	}

	// Affected packages and fixed versions
	if len(vuln.Affected) > 0 {
		fmt.Fprintf(out, "\n%s\n", ui.StyleDim.Render("Affected:"))
		for _, affected := range vuln.Affected {
			pkgName := affected.Package.Name
			if affected.Package.Ecosystem != "" {
				pkgName = fmt.Sprintf("%s (%s)", pkgName, affected.Package.Ecosystem)
			}
			fmt.Fprintf(out, "  %s\n", ui.StylePath.Render(pkgName))

			// Show version ranges
			for _, r := range affected.Ranges {
				for _, event := range r.Events {
					if event.Introduced != "" {
						fmt.Fprintf(out, "    %s %s\n", ui.StyleDim.Render("introduced:"), event.Introduced)
					}
					if event.Fixed != "" {
						fmt.Fprintf(out, "    %s %s\n", ui.StyleUpgraded.Render("fixed:"), event.Fixed)
					}
				}
			}
		}
	}

	// References
	if len(vuln.References) > 0 && verbose {
		fmt.Fprintf(out, "\n%s\n", ui.StyleDim.Render("References:"))
		for _, ref := range vuln.References {
			fmt.Fprintf(out, "  %s\n", ref.URL)
		}
	} else if len(vuln.References) > 0 {
		// Show just first reference in non-verbose mode
		fmt.Fprintf(out, "\n%s %s\n", ui.StyleDim.Render("More info:"), vuln.References[0].URL)
	}

	// Published/Modified dates
	if !vuln.Published.IsZero() {
		fmt.Fprintf(out, "\n%s %s", ui.StyleDim.Render("Published:"), vuln.Published.Format("2006-01-02"))
		if !vuln.Modified.IsZero() {
			fmt.Fprintf(out, " %s %s", ui.StyleDim.Render("Modified:"), vuln.Modified.Format("2006-01-02"))
		}
		fmt.Fprintln(out)
	}
}

// renderVulnJSON outputs vulnerability data as JSON.
func renderVulnJSON(out io.Writer, vuln *osvschema.Vulnerability) {
	// Build a clean JSON structure
	data := map[string]any{
		"id":      vuln.ID,
		"summary": vuln.Summary,
	}

	if len(vuln.Aliases) > 0 {
		data["aliases"] = vuln.Aliases
	}
	if vuln.Details != "" {
		data["details"] = vuln.Details
	}

	severity := extractVulnSeverity(vuln)
	data["severity"] = severity.Level.String()

	if len(vuln.Affected) > 0 {
		affected := make([]map[string]any, 0, len(vuln.Affected))
		for _, a := range vuln.Affected {
			pkg := map[string]any{
				"name":      a.Package.Name,
				"ecosystem": string(a.Package.Ecosystem),
			}
			var fixed []string
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						fixed = append(fixed, e.Fixed)
					}
				}
			}
			if len(fixed) > 0 {
				pkg["fixed_versions"] = fixed
			}
			affected = append(affected, pkg)
		}
		data["affected"] = affected
	}

	if len(vuln.References) > 0 {
		refs := make([]string, 0, len(vuln.References))
		for _, r := range vuln.References {
			refs = append(refs, r.URL)
		}
		data["references"] = refs
	}

	if !vuln.Published.IsZero() {
		data["published"] = vuln.Published.Format("2006-01-02")
	}
	if !vuln.Modified.IsZero() {
		data["modified"] = vuln.Modified.Format("2006-01-02")
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

// extractVulnSeverity extracts severity from an OSV vulnerability.
func extractVulnSeverity(vuln *osvschema.Vulnerability) vulnerability.Severity {
	if vuln == nil {
		return vulnerability.Severity{}
	}

	// Check severity array first
	for _, sev := range vuln.Severity {
		if sev.Score != "" {
			return vulnerability.NewSeverity(sev.Score, string(sev.Type))
		}
	}

	// Check database_specific for GHSA severity
	if vuln.DatabaseSpecific != nil {
		if sevRaw, ok := vuln.DatabaseSpecific["severity"]; ok {
			if sevStr, ok := sevRaw.(string); ok {
				return vulnerability.NewSeverity(strings.ToUpper(sevStr), "GHSA")
			}
		}
	}

	return vulnerability.Severity{}
}

// severityStyleFor returns the appropriate UI style for a severity level.
func severityStyleFor(level vulnerability.SeverityLevel) lipgloss.Style {
	switch level {
	case vulnerability.SeverityCritical:
		return ui.StyleCritical
	case vulnerability.SeverityHigh:
		return ui.StyleRemoved // High uses the red "removed" style
	case vulnerability.SeverityMedium:
		return ui.StyleDowngraded // Medium uses the yellow "downgraded" style
	case vulnerability.SeverityLow:
		return ui.StyleVersion // Low uses the dim version style
	default:
		return ui.StyleDim
	}
}

// wrapDetailsText wraps text to the specified width for vulnerability details.
func wrapDetailsText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var lines []string
	for _, paragraph := range strings.Split(text, "\n\n") {
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			continue
		}

		var line strings.Builder
		for _, word := range words {
			if line.Len()+len(word)+1 > width {
				lines = append(lines, line.String())
				line.Reset()
			}
			if line.Len() > 0 {
				line.WriteString(" ")
			}
			line.WriteString(word)
		}
		if line.Len() > 0 {
			lines = append(lines, line.String())
		}
		lines = append(lines, "")
	}

	return strings.TrimSuffix(strings.Join(lines, "\n"), "\n")
}
