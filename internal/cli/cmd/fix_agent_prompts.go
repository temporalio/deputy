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
	sb.WriteString("You are Deputy's remediation agent.\n")
	sb.WriteString("Follow the remediation plan JSON provided below to fix the repository.\n")
	sb.WriteString("For each command marked executable=true, run it in the shell when appropriate.\n")
	sb.WriteString("For commands marked executable=false, edit the referenced files accordingly.\n")
	sb.WriteString("After applying changes, run relevant tests (e.g., 'go test ./...' or language-specific equivalents) when feasible.\n")
	sb.WriteString("Prefer minimal, targeted edits that satisfy the plan.\n")
	sb.WriteString("Summarize your work at the end.\n\n")
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
	sb.WriteString("You are Deputy's security triage assistant.\n")
	sb.WriteString("Review the vulnerability summary JSON below, identify the issues that pose the highest risk to production systems, and explain why.\n")
	sb.WriteString("Focus on exploitability, blast radius, and upgrade complexity.\n")
	sb.WriteString("Suggest concrete remediation steps (including code areas to inspect) and any validation or regression tests engineers should run.\n")
	sb.WriteString("Format your response with sections: 'Prioritized Risks', 'Recommended Actions', and 'Suggested Tests'.\n\n")
	sb.WriteString("Triage Report JSON:\n")
	sb.Write(data)
	sb.WriteString("\n")
	return sb.String(), nil
}
