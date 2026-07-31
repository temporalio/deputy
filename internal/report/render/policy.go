package render

import (
	"fmt"
	"io"
	"slices"
	"strings"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/report"
	ui "github.com/temporalio/deputy/internal/ui"
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

// maxPolicySubjectsShown caps how many subjects a grouped policy result lists
// before collapsing the tail into an "and N more" line, keeping large diffs
// readable while the full list stays available in structured output.
const maxPolicySubjectsShown = 5

// PolicyActionsSection renders structured policy results as one cohesive
// section: a status line followed by results grouped by rule, deduplicated,
// with the evaluated subjects listed beneath each group.
//
// This is the collect-then-render seam for policy output: evaluation never
// prints, so warnings cannot interleave with the report body, and the same
// grouped shape is what CI renderers derive from the JSON contract. Denies
// render before warns; allow results are counted as passed and not listed.
func PolicyActionsSection(w io.Writer, policyCount int, actions []*policyv1.Action) {
	if policyCount == 0 {
		return
	}

	groups := groupPolicyActions(actions)

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Policy Evaluation:"))

	denies, warns := 0, 0
	for _, act := range actions {
		switch act.GetType() {
		case policyv1.ActionType_ACTION_TYPE_DENY:
			denies++
		case policyv1.ActionType_ACTION_TYPE_WARN:
			warns++
		}
	}
	switch {
	case denies > 0:
		renderPolicyStatus(w, policyCount, denies, warns, "denied")
	case warns > 0:
		renderPolicyStatus(w, policyCount, denies, warns, "warned")
	default:
		renderPolicyPassed(w, policyCount)
	}

	for _, g := range groups {
		renderPolicyActionGroup(w, g)
	}
}

// policyActionGroup is one deduplicated policy result: a (policy, rule,
// action, reason) tuple plus every subject it fired for, in evaluation order.
type policyActionGroup struct {
	actionType  policyv1.ActionType
	policyName  string
	ruleName    string
	reason      string
	remediation string
	subjects    []*policyv1.Subject
	// count is the number of underlying actions, which can exceed
	// len(subjects) when report-level results carry no subject.
	count int
}

// groupPolicyActions deduplicates deny and warn actions by (type, policy,
// rule, reason), collecting subjects per group. Denies order before warns;
// within a type, groups keep first-seen order so output follows the report.
func groupPolicyActions(actions []*policyv1.Action) []*policyActionGroup {
	byKey := make(map[string]*policyActionGroup)
	var order []*policyActionGroup
	for _, act := range actions {
		t := act.GetType()
		if t != policyv1.ActionType_ACTION_TYPE_DENY && t != policyv1.ActionType_ACTION_TYPE_WARN {
			continue
		}
		reason := firstNonEmpty(act.GetReason(), act.GetMessage())
		key := strings.Join([]string{t.String(), act.GetPolicyName(), act.GetRuleName(), reason}, "\x00")
		g, ok := byKey[key]
		if !ok {
			g = &policyActionGroup{
				actionType:  t,
				policyName:  act.GetPolicyName(),
				ruleName:    act.GetRuleName(),
				reason:      reason,
				remediation: act.GetRemediation(),
			}
			byKey[key] = g
			order = append(order, g)
		}
		g.count++
		if s := act.GetSubject(); s != nil {
			g.subjects = append(g.subjects, s)
		}
	}
	slices.SortStableFunc(order, func(a, b *policyActionGroup) int {
		return denyFirst(a.actionType) - denyFirst(b.actionType)
	})
	return order
}

// denyFirst orders deny groups ahead of warn groups.
func denyFirst(t policyv1.ActionType) int {
	if t == policyv1.ActionType_ACTION_TYPE_DENY {
		return 0
	}
	return 1
}

// renderPolicyActionGroup renders one deduplicated group: header line with
// rule and policy file, the reason, capped subject list, and remediation.
func renderPolicyActionGroup(w io.Writer, g *policyActionGroup) {
	var styledAction string
	switch g.actionType {
	case policyv1.ActionType_ACTION_TYPE_DENY:
		styledAction = ui.StyleStatusError.Render("[DENY]")
	default:
		styledAction = ui.StyleStatusWarning.Render("[WARN]")
	}

	line := fmt.Sprintf("  %s %s", ui.StyleVersion.Render("•"), styledAction)
	if g.ruleName != "" {
		line += " " + g.ruleName
	}
	if g.policyName != "" {
		line += " " + ui.StylePolicyFile.Render(g.policyName)
	}
	if g.count > 1 {
		line += " " + ui.StyleMeta.Render(fmt.Sprintf("(%d %s)", g.count, policySubjectNoun(g)))
	}
	fmt.Fprintln(w, line)

	if g.reason != "" {
		fmt.Fprintln(w, "    "+ui.StyleSymbol.Render(g.reason))
	}

	shown := min(len(g.subjects), maxPolicySubjectsShown)
	for _, s := range g.subjects[:shown] {
		fmt.Fprintln(w, "      "+ui.StyleDim.Render(formatPolicySubject(s)))
	}
	if rest := len(g.subjects) - shown; rest > 0 {
		fmt.Fprintln(w, "      "+ui.StyleMeta.Render(fmt.Sprintf("… and %d more", rest)))
	}

	if rem := strings.TrimSpace(g.remediation); rem != "" {
		fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Remediation: ")+rem)
	}
}

// policySubjectNoun picks the collective noun for a group's dedup count:
// findings when the subjects are advisories, packages when they are
// packages, and the generic results otherwise (mixed or subjectless).
func policySubjectNoun(g *policyActionGroup) string {
	if len(g.subjects) != g.count {
		return "results"
	}
	advisories, packages := 0, 0
	for _, s := range g.subjects {
		if s.GetAdvisory() != "" {
			advisories++
		} else if s.GetPackage() != "" {
			packages++
		}
	}
	switch {
	case advisories == len(g.subjects):
		return "findings"
	case packages == len(g.subjects):
		return "packages"
	default:
		return "results"
	}
}

// formatPolicySubject renders one evaluated subject as a compact identity:
// "pkg @ version" for packages (matching the diff report's package lines),
// prefixed with the advisory ID for findings.
func formatPolicySubject(s *policyv1.Subject) string {
	id := s.GetPackage()
	if v := s.GetVersion(); v != "" && id != "" {
		id += " @ " + v
	}
	if adv := s.GetAdvisory(); adv != "" {
		if id != "" {
			return adv + " (" + id + ")"
		}
		return adv
	}
	return id
}
