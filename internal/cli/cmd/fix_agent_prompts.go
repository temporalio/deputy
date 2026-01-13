package cmd

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	fixv1 "github.com/picatz/deputy/gen/deputy/fix/v1"
)

// buildFixPromptProto constructs a prompt for an AI agent to execute a remediation plan.
// The prompt is provider-agnostic and works with any agentic LLM.
func buildFixPromptProto(resp *fixv1.FixResponse) (string, error) {
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	data, err := opts.Marshal(resp)
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
