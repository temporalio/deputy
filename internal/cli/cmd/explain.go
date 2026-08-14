package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/ai"
	_ "github.com/temporalio/deputy/internal/ai/providers/claude" // Register claude provider
	_ "github.com/temporalio/deputy/internal/ai/providers/codex"  // Register codex provider
	"github.com/temporalio/deputy/internal/ai/render"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/explain"
	ui "github.com/temporalio/deputy/internal/ui"
)

// AddExplainCommand adds the explain command to the root command.
func AddExplainCommand(root *cobra.Command) {
	var (
		formatFlag   string
		enrich       bool
		agentName    string
		agentModel   string
		agentSandbox string
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
understand the vulnerability's impact and urgency.

AGENT-ASSISTED ANALYSIS:
When using --agent, Deputy delegates analysis to an AI agent (Claude or Codex).
The agent runs in read-only mode by default (cannot modify files), providing:
• Plain-English explanation of the vulnerability
• Impact assessment and exploitation likelihood
• Who should be concerned (affected application types)
• Prioritized remediation steps`,
		Example: `  # Explain a vulnerability (includes threat intelligence by default)
  deputy explain CVE-2021-44228

  # Explain multiple vulnerabilities
  deputy explain GHSA-jfh8-c2jp-5v3q CVE-2023-45853

  # Skip threat intelligence lookup (faster, offline)
  deputy explain --enrich=false CVE-2021-44228

  # Get agent-assisted analysis (read-only by default)
  deputy explain --agent claude CVE-2021-44228
  deputy explain --agent codex CVE-2021-44228

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
					if osv.IsNotFoundError(err) {
						fmt.Fprintf(out, "%s %s: not found\n", ui.StyleRemoved.Render("error"), id)
						continue
					}
					fmt.Fprintf(out, "%s %s: %v\n", ui.StyleRemoved.Render("error"), id, err)
					continue
				}
				if vuln == nil {
					fmt.Fprintf(out, "%s %s: not found\n", ui.StyleRemoved.Render("error"), id)
					continue
				}
				vuln = osv.HydrateSparseVulnerabilityAliases(ctx, client, vuln)

				if formatFlag == "json" {
					if err := renderer.RenderJSON(ctx, out, vuln); err != nil {
						fmt.Fprintf(out, "%s rendering %s: %v\n", ui.StyleRemoved.Render("error"), id, err)
					}
				} else {
					if err := renderer.Render(ctx, out, vuln); err != nil {
						fmt.Fprintf(out, "%s rendering %s: %v\n", ui.StyleRemoved.Render("error"), id, err)
					}

					// Agent-assisted analysis
					if agentName != "" {
						fmt.Fprintln(out)
						if err := renderAgentAnalysis(ctx, out, vuln, agentName, agentModel, agentSandbox); err != nil {
							fmt.Fprintf(out, "\n%s agent analysis: %v\n", ui.StyleDim.Render("note:"), err)
						}
					}
				}
			}

			return nil
		},
	}

	explainCmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format: text, json")
	explainCmd.Flags().BoolVar(&enrich, "enrich", true, "Enrich with threat intelligence (EPSS scores, KEV catalog)")
	explainCmd.Flags().StringVar(&agentName, "agent", "", "Use an AI agent to analyze the vulnerability (e.g. 'claude', 'codex')")
	explainCmd.Flags().StringVar(&agentModel, "agent-model", "", "Model identifier to use when --agent is set")
	explainCmd.Flags().StringVar(&agentSandbox, "agent-sandbox", "read-only", "Sandbox policy for AI agent (read-only|workspace-write|danger-full-access)")

	root.AddCommand(explainCmd)
}

// renderAgentAnalysis uses an AI agent to provide additional context and analysis.
func renderAgentAnalysis(ctx context.Context, out io.Writer, vuln *osvschema.Vulnerability, providerName, model, sandboxMode string) error {
	provider, err := ai.GetProvider(providerName)
	if err != nil {
		available := ai.ListProviders()
		if len(available) > 0 {
			return fmt.Errorf("agent %q not available (available: %s)", providerName, strings.Join(available, ", "))
		}
		return fmt.Errorf("agent %q not available; install claude or codex CLI", providerName)
	}

	// Build vulnerability summary for the agent
	// Severity entries are flattened by hand: the OSV schema types are protobuf
	// messages, which encoding/json renders with numeric enums instead of the
	// "CVSS_V3" names the agent prompt is written against.
	severities := make([]map[string]string, 0, len(vuln.GetSeverity()))
	for _, sev := range vuln.GetSeverity() {
		severities = append(severities, map[string]string{
			"type":  sev.GetType().String(),
			"score": sev.GetScore(),
		})
	}
	vulnJSON, err := json.Marshal(map[string]any{
		"id":       vuln.GetId(),
		"summary":  vuln.GetSummary(),
		"details":  vuln.GetDetails(),
		"aliases":  vuln.GetAliases(),
		"severity": severities,
	})
	if err != nil {
		return fmt.Errorf("encode vulnerability: %w", err)
	}

	// Create prompt
	prompt := buildExplainAgentPrompt(string(vulnJSON))

	// Map sandbox mode string to ai.Sandbox
	sandbox := parseSandboxMode(sandboxMode)

	// Get working directory (required by some providers like codex)
	workDir, _ := os.Getwd()

	// Print header
	fmt.Fprintln(out, ui.StyleHeader.Render("Agent Analysis"))

	// Use the shared render.StreamResponse for consistent output with glamour markdown
	return render.StreamResponse(ctx, provider, &ai.CompletionRequest{
		Prompt:    prompt,
		Model:     model,
		MaxTokens: 2048,
		Sandbox:   sandbox,
		WorkDir:   workDir,
	}, render.Config{
		Out:            out,
		Err:            os.Stderr,
		SpinnerMessage: providerName,
		ProviderName:   providerName,
		Model:          model,
		RenderMarkdown: true,
		ShowMetadata:   true,
		WordWrap:       80,
	})
}

// parseSandboxMode converts a sandbox mode string to ai.Sandbox.
func parseSandboxMode(mode string) ai.Sandbox {
	switch strings.ToLower(mode) {
	case "read-only", "readonly":
		return ai.SandboxReadOnly
	case "workspace-write", "workspacewrite":
		return ai.SandboxWorkspaceWrite
	case "full-access", "fullaccess", "danger-full-access":
		return ai.SandboxFullAccess
	default:
		return ai.SandboxReadOnly // Default to read-only for explain
	}
}

// buildExplainAgentPrompt creates a prompt for agent vulnerability analysis.
func buildExplainAgentPrompt(vulnJSON string) string {
	var sb strings.Builder

	// Context and constraints
	sb.WriteString("You are Deputy's vulnerability explanation assistant, helping developers understand security issues.\n\n")

	sb.WriteString("IMPORTANT CONSTRAINTS:\n")
	sb.WriteString("- This is a NON-INTERACTIVE CLI output. Your response will be displayed directly in a terminal.\n")
	sb.WriteString("- Do NOT ask follow-up questions or offer to do more analysis.\n")
	sb.WriteString("- Do NOT say things like \"Want me to...\" or \"Let me know if...\" or \"I can help with...\".\n")
	sb.WriteString("- Provide a COMPLETE, SELF-CONTAINED explanation in a single response.\n")
	sb.WriteString("- Use markdown formatting (headers, bold, bullet points) for terminal rendering.\n\n")

	// Task description
	sb.WriteString("TASK:\n")
	sb.WriteString("Analyze this vulnerability and provide a clear, actionable explanation.\n\n")

	sb.WriteString("COVER THESE TOPICS:\n")
	sb.WriteString("1. **What This Vulnerability Means** - Plain-English explanation of the issue\n")
	sb.WriteString("2. **Potential Impact** - What could happen if exploited (data exposure, RCE, DoS, etc.)\n")
	sb.WriteString("3. **Who Should Be Concerned** - What types of applications/configurations are affected\n")
	sb.WriteString("4. **Key Remediation Steps** - Concrete actions to fix or mitigate the issue\n\n")

	sb.WriteString("Keep the response concise but comprehensive. Target audience: developers and security engineers.\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString("Vulnerability data:\n")
	sb.WriteString(vulnJSON)

	return sb.String()
}
