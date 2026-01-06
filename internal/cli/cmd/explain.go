package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/ai"
	_ "github.com/picatz/deputy/internal/ai/providers/claude" // Register claude provider
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/explain"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddExplainCommand adds the explain command to the root command.
func AddExplainCommand(root *cobra.Command) {
	var (
		formatFlag string
		enrich     bool
		aiAssist   bool
	)

	explainCmd := &cobra.Command{
		Use:   "explain <vuln-id> [vuln-id...]",
		Short: "Explain vulnerabilities by ID",
		Long: `Get detailed information about vulnerabilities by their IDs.

Fetches vulnerability data from OSV and displays a comprehensive, context-rich
explanation including severity, timeline, threat intelligence, affected packages,
and remediation guidance.

Accepts CVE, GHSA, GO-, RUSTSEC-, and other OSV-compatible identifiers.

The output is designed to help developers, security engineers, and managers
understand the vulnerability's impact and urgency.`,
		Example: `  # Explain a vulnerability (includes threat intelligence by default)
  deputy explain CVE-2021-44228

  # Explain multiple vulnerabilities
  deputy explain GHSA-jfh8-c2jp-5v3q CVE-2023-45853

  # Skip threat intelligence lookup (faster, offline)
  deputy explain --enrich=false CVE-2021-44228

  # Get AI-assisted analysis (requires claude CLI)
  deputy explain --ai CVE-2021-44228

  # Output as JSON
  deputy explain --format json CVE-2021-44228`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			client := osv.NewClient()

			// Create renderer with configuration
			renderer := explain.NewRenderer(explain.Config{
				Enrich:    enrich,
				DiskCache: true,
			})

			for i, id := range args {
				if i > 0 {
					fmt.Fprintln(out)
					fmt.Fprintln(out, strings.Repeat("─", 80))
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
					if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
						fmt.Fprintf(out, "%s rendering %s: %v\n", ui.StyleRemoved.Render("error"), id, err)
					}
				} else {
					if err := renderer.Render(ctx, out, vuln); err != nil {
						fmt.Fprintf(out, "%s rendering %s: %v\n", ui.StyleRemoved.Render("error"), id, err)
					}

					// AI-assisted analysis
					if aiAssist {
						fmt.Fprintln(out)
						if err := renderAIAnalysis(ctx, out, vuln); err != nil {
							fmt.Fprintf(out, "\n%s AI analysis: %v\n", ui.StyleDim.Render("note:"), err)
						}
					}
				}
			}

			return nil
		},
	}

	explainCmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format: text, json")
	explainCmd.Flags().BoolVar(&enrich, "enrich", true, "Enrich with threat intelligence (EPSS scores, KEV catalog)")
	explainCmd.Flags().BoolVar(&aiAssist, "ai", false, "Add AI-assisted analysis (requires claude CLI)")

	root.AddCommand(explainCmd)
}

// renderAIAnalysis uses an AI model to provide additional context and analysis.
func renderAIAnalysis(ctx context.Context, out io.Writer, vuln *osvschema.Vulnerability) error {
	// Get the claude provider from the AI registry
	provider, err := ai.GetProvider("claude")
	if err != nil {
		return fmt.Errorf("AI provider not available: %w", err)
	}

	// Build vulnerability summary for the AI
	vulnJSON, err := json.Marshal(map[string]any{
		"id":       vuln.ID,
		"summary":  vuln.Summary,
		"details":  vuln.Details,
		"aliases":  vuln.Aliases,
		"severity": vuln.Severity,
	})
	if err != nil {
		return fmt.Errorf("encode vulnerability: %w", err)
	}

	// Create prompt - now request markdown output for better rendering
	prompt := buildExplainAIPrompt(string(vulnJSON))

	// Print header
	fmt.Fprintln(out, ui.StyleHeader.Render("AI Analysis"))

	// Start spinner while waiting for AI response
	var progress *ui.Progress
	isTTY := ui.IsTTY(out)
	if isTTY {
		progress = ui.NewProgress(os.Stderr, "Generating analysis")
		progress.Start(ctx)
	}

	// Collect the full response for glamour rendering
	var response strings.Builder
	firstToken := true

	// Stream the response using the ai package
	for event, err := range provider.Stream(ctx, &ai.CompletionRequest{
		Prompt:    prompt,
		MaxTokens: 2048,
	}) {
		if err != nil {
			if progress != nil {
				progress.Fail()
			}
			return fmt.Errorf("AI stream: %w", err)
		}
		switch e := event.(type) {
		case ai.TextEvent:
			// Clear spinner on first token
			if firstToken && progress != nil {
				progress.Clear()
				firstToken = false
			}
			response.WriteString(e.Text)
		case ai.ErrorEvent:
			if progress != nil {
				progress.Fail()
			}
			return fmt.Errorf("AI error: %w", e.Error())
		}
	}

	// Clear spinner if no text was received
	if firstToken && progress != nil {
		progress.Clear()
	}

	// Render the response with glamour for beautiful markdown output
	if response.Len() > 0 {
		rendered, err := renderMarkdown(response.String())
		if err != nil {
			// Fallback to plain text if glamour fails
			fmt.Fprintln(out)
			fmt.Fprintln(out, response.String())
		} else {
			fmt.Fprint(out, rendered)
		}
	}

	return nil
}

// renderMarkdown renders markdown text using glamour with a dark theme.
func renderMarkdown(content string) (string, error) {
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(80),
	)
	if err != nil {
		return "", err
	}
	return renderer.Render(content)
}

// buildExplainAIPrompt creates a prompt for AI vulnerability analysis.
func buildExplainAIPrompt(vulnJSON string) string {
	var sb strings.Builder

	sb.WriteString("You are a security expert helping developers understand vulnerabilities.\n\n")
	sb.WriteString("Analyze this vulnerability and provide:\n")
	sb.WriteString("1. A plain-English explanation of what this vulnerability means\n")
	sb.WriteString("2. The potential impact if exploited\n")
	sb.WriteString("3. Who should be concerned (what types of applications)\n")
	sb.WriteString("4. Key remediation steps\n\n")
	sb.WriteString("Provide clear, actionable analysis suitable for developers and security engineers.\n")
	sb.WriteString("Use markdown formatting with **bold** for emphasis and bullet points for lists.\n")
	sb.WriteString("Keep the response concise but comprehensive.\n\n")

	sb.WriteString("Vulnerability data:\n")
	sb.WriteString(vulnJSON)

	return sb.String()
}
