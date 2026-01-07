package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/picatz/deputy/internal/report"
)

// buildFixPrompt constructs a prompt for an AI agent to execute a remediation plan.
// The prompt is provider-agnostic and works with any agentic LLM.
func buildFixPrompt(plan remediationPlan) (string, error) {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode plan: %w", err)
	}

	var sb strings.Builder

	// Context
	sb.WriteString("You are Deputy's remediation agent, executing security fixes in a repository.\n\n")

	sb.WriteString("IMPORTANT CONSTRAINTS:\n")
	sb.WriteString("- Execute the remediation plan autonomously. Do NOT ask for confirmation or clarification.\n")
	sb.WriteString("- Do NOT say things like \"Want me to...\" or \"Should I...\" - just execute the plan.\n")
	sb.WriteString("- Provide a brief summary of completed work at the end.\n\n")

	// Task description
	sb.WriteString("TASK:\n")
	sb.WriteString("Follow the remediation plan JSON below to fix vulnerabilities in this repository.\n\n")

	sb.WriteString("EXECUTION RULES:\n")
	sb.WriteString("- For commands with executable=true: run them in the shell\n")
	sb.WriteString("- For commands with executable=false: edit the referenced files accordingly\n")
	sb.WriteString("- After applying changes, run relevant tests (e.g., 'go test ./...' or equivalent)\n")
	sb.WriteString("- Prefer minimal, targeted edits that satisfy the plan\n")
	sb.WriteString("- If a command fails, note it and continue with the next item\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString("Remediation Plan JSON:\n")
	sb.Write(data)
	sb.WriteString("\n")
	return sb.String(), nil
}

// buildTriagePrompt constructs a prompt for an AI agent to analyze a triage report.
// The prompt is provider-agnostic and works with any agentic LLM.
func buildTriagePrompt(triageReport report.TriageReport) (string, error) {
	data, err := json.MarshalIndent(triageReport, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode triage report: %w", err)
	}

	var sb strings.Builder

	// Context and constraints
	sb.WriteString("You are Deputy's security triage assistant, providing vulnerability prioritization analysis.\n\n")

	sb.WriteString("IMPORTANT CONSTRAINTS:\n")
	sb.WriteString("- This is a NON-INTERACTIVE CLI output. Your response will be displayed directly in a terminal.\n")
	sb.WriteString("- Do NOT ask follow-up questions or offer to do more analysis.\n")
	sb.WriteString("- Do NOT say things like \"Want me to...\" or \"Let me know if...\" or \"I can help with...\".\n")
	sb.WriteString("- Provide a COMPLETE, SELF-CONTAINED analysis in a single response.\n")
	sb.WriteString("- Use markdown formatting (headers, bold, bullet points) for terminal rendering.\n\n")

	// Task description
	sb.WriteString("TASK:\n")
	sb.WriteString("Analyze this vulnerability triage report and provide actionable prioritization guidance.\n\n")

	sb.WriteString("Focus on:\n")
	sb.WriteString("- Exploitability: How easily can this be exploited? Is it remotely triggerable?\n")
	sb.WriteString("- Blast radius: What's the impact if exploited? Data exposure, RCE, DoS?\n")
	sb.WriteString("- Upgrade complexity: How hard is the fix? Breaking changes? Test coverage needed?\n")
	sb.WriteString("- Applicability: Based on the codebase context, which vulns are actually reachable?\n\n")

	// Output format
	sb.WriteString("FORMAT YOUR RESPONSE WITH THESE SECTIONS:\n")
	sb.WriteString("## Prioritized Risks\n")
	sb.WriteString("Rank vulnerabilities by urgency with brief rationale for each.\n\n")
	sb.WriteString("## Recommended Actions\n")
	sb.WriteString("Concrete steps to remediate, in priority order. Include specific commands or file paths.\n\n")
	sb.WriteString("## Suggested Tests\n")
	sb.WriteString("How to validate the fixes and catch regressions.\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString("Triage Report JSON:\n")
	sb.Write(data)
	sb.WriteString("\n")
	return sb.String(), nil
}
