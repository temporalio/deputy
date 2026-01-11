package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/picatz/deputy/internal/report"
	ui "github.com/picatz/deputy/internal/ui"
)

// PolicyEvaluationSummary writes a summary of policy evaluation to w.
// It shows that policies were loaded and evaluated, even when there are no findings.
//
// Design:
//   - Happy path (all passed): green checkmark with success styling
//   - Warnings only: amber indicator with warning styling
//   - Denials: red indicator with error styling (this is blocking)
//
// The visual design is intentionally minimal and cohesive with Deputy's
// overall aesthetic: informative without being noisy.
func PolicyEvaluationSummary(w io.Writer, policyCount int, findings []report.PolicyFinding) {
	if policyCount == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Policy Evaluation:"))

	// Count actions by type
	denies, warns := countPolicyActions(findings)

	// Render appropriate status based on results
	switch {
	case denies > 0:
		// Blocking: at least one policy denied
		renderPolicyStatus(w, policyCount, denies, warns, "denied")
	case warns > 0:
		// Non-blocking warnings
		renderPolicyStatus(w, policyCount, denies, warns, "warned")
	default:
		// All passed
		renderPolicyPassed(w, policyCount)
	}
}

// countPolicyActions counts deny and warn actions from findings.
func countPolicyActions(findings []report.PolicyFinding) (denies, warns int) {
	for _, f := range findings {
		switch strings.ToLower(f.Action) {
		case "deny":
			denies++
		case "warn":
			warns++
		}
	}
	return
}

// renderPolicyPassed renders the happy path - all policies passed.
func renderPolicyPassed(w io.Writer, policyCount int) {
	plural := "s"
	if policyCount == 1 {
		plural = ""
	}
	line := fmt.Sprintf("  %s %d policy file%s evaluated",
		ui.StyleStatusSuccess.Render("✓"),
		policyCount,
		plural,
	)
	line += " " + ui.StyleMeta.Render("- all passed")
	fmt.Fprintln(w, line)
}

// renderPolicyStatus renders the status when there are denials or warnings.
func renderPolicyStatus(w io.Writer, policyCount, denies, warns int, outcome string) {
	plural := "s"
	if policyCount == 1 {
		plural = ""
	}

	// Choose indicator based on outcome
	var indicator string
	switch outcome {
	case "denied":
		indicator = ui.StyleStatusError.Render("!")
	case "warned":
		indicator = ui.StyleStatusWarning.Render("!")
	default:
		indicator = ui.StyleStatusPending.Render("•")
	}

	line := fmt.Sprintf("  %s %d policy file%s evaluated",
		indicator,
		policyCount,
		plural,
	)

	// Build result summary
	parts := []string{}
	if denies > 0 {
		parts = append(parts, ui.StyleStatusError.Render(fmt.Sprintf("%d denied", denies)))
	}
	if warns > 0 {
		parts = append(parts, ui.StyleStatusWarning.Render(fmt.Sprintf("%d warned", warns)))
	}
	if len(parts) > 0 {
		line += " - " + strings.Join(parts, ", ")
	}

	fmt.Fprintln(w, line)
}

// PolicyFindings writes policy findings to w in a human-friendly format.
// Each finding is rendered with:
//   - Action indicator (DENY in red, WARN in amber)
//   - Source file reference
//   - Reason/message
//   - Remediation guidance (if provided)
//
// Design principles:
//   - Clear visual hierarchy: action -> source -> details
//   - Actionable: always show what to do about it
//   - Scannable: consistent formatting for quick review
func PolicyFindings(w io.Writer, findings []report.PolicyFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Policy Findings:"))

	for _, f := range findings {
		renderPolicyFinding(w, f)
	}
}

// renderPolicyFinding renders a single policy finding.
func renderPolicyFinding(w io.Writer, f report.PolicyFinding) {
	action := strings.ToUpper(strings.TrimSpace(f.Action))
	if action == "" {
		action = "FINDING"
	}

	// Style action based on severity
	var styledAction string
	switch strings.ToLower(f.Action) {
	case "deny":
		styledAction = ui.StyleStatusError.Render("[" + action + "]")
	case "warn":
		styledAction = ui.StyleStatusWarning.Render("[" + action + "]")
	default:
		styledAction = ui.StyleMeta.Render("[" + action + "]")
	}

	// Build the header line: bullet + action + source
	source := strings.TrimSpace(f.Source)
	line := fmt.Sprintf("  %s %s", ui.StyleVersion.Render("•"), styledAction)
	if source != "" {
		line += " " + ui.StylePolicyFile.Render(source)
	}
	fmt.Fprintln(w, line)

	// Reason or message (the "why")
	msg := strings.TrimSpace(firstNonEmpty(f.Reason, f.Message))
	if msg != "" {
		fmt.Fprintln(w, "    "+ui.StyleSymbol.Render(msg))
	}

	// Remediation (the "what to do")
	if rem := strings.TrimSpace(f.Remediation); rem != "" {
		fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Remediation: ")+rem)
	}
}

// firstNonEmpty returns the first non-empty string from the provided values.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
