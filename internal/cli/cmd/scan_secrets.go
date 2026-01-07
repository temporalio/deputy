package cmd

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/picatz/deputy/internal/secrets"
	ui "github.com/picatz/deputy/internal/ui"
)

// runSecretsScanner scans a directory for secrets and returns findings.
// Uses the shared SecretsResult type from secrets.go.
func runSecretsScanner(ctx context.Context, path string, errW io.Writer) (*SecretsResult, error) {
	engine, err := secrets.NewEngine()
	if err != nil {
		return nil, err
	}

	findings, filesScanned, err := scanDirectory(ctx, engine, path, "", "")
	if err != nil {
		return nil, err
	}

	stats := make(map[secrets.SecretType]int)
	highConfCount := 0
	for _, f := range findings {
		stats[f.Type]++
		if f.Confidence >= 0.9 {
			highConfCount++
		}
	}

	return &SecretsResult{
		Target:              path,
		Generated:           time.Now().UTC().Format(time.RFC3339),
		FilesScanned:        filesScanned,
		SecretsFound:        len(findings),
		HighConfidenceCount: highConfCount,
		Findings:            findings,
		Stats:               stats,
	}, nil
}

// renderSecretsFindings outputs secrets findings in text format.
// Used by scan --secrets to append secrets to vulnerability output.
func renderSecretsFindings(out io.Writer, results *SecretsResult) {
	if results == nil || len(results.Findings) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StyleAdded.Render("✓ No secrets detected"))
		return
	}

	// Section header (Deputy style)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s %s\n",
		ui.StyleDowngraded.Render("∴"),
		ui.StyleHeader.Render(fmt.Sprintf("Secrets Detected (%d):", len(results.Findings))))

	// Group by file, maintain order
	byFile := make(map[string][]secrets.Finding)
	var fileOrder []string
	for _, f := range results.Findings {
		file := f.File
		if file == "" {
			file = "(inline)"
		}
		if _, seen := byFile[file]; !seen {
			fileOrder = append(fileOrder, file)
		}
		byFile[file] = append(byFile[file], f)
	}

	for _, file := range fileOrder {
		fileFindings := byFile[file]
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %s\n",
			ui.StylePackageName.Render(file),
			ui.StyleVersion.Render(fmt.Sprintf("[%d]", len(fileFindings))))

		for _, f := range fileFindings {
			// Build location string
			location := ""
			if f.Line > 0 {
				location = fmt.Sprintf(":%d", f.Line)
				if f.Column > 0 {
					location += fmt.Sprintf(":%d", f.Column)
				}
			}

			// Confidence indicator
			confLabel := confidenceLabel(f.Confidence)

			// Secret type display
			typeDisplay := secretTypeDisplay(f.Type)

			fmt.Fprintf(out, "  %s %s %s%s\n",
				ui.StyleVersion.Render("•"),
				typeDisplay,
				confLabel,
				ui.StyleMeta.Render(location))

			fmt.Fprintf(out, "    %s\n", ui.StyleDim.Render(f.Redacted))
		}
	}
}
