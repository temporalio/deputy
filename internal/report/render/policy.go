package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/picatz/deputy/internal/report"
	ui "github.com/picatz/deputy/internal/ui"
)

// PolicyFindings writes policy findings to w in a human-friendly format.
func PolicyFindings(w io.Writer, findings []report.PolicyFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Policy Findings:"))
	for _, f := range findings {
		action := strings.ToUpper(strings.TrimSpace(f.Action))
		if action == "" {
			action = "ACTION"
		}
		source := strings.TrimSpace(f.Source)
		line := fmt.Sprintf("  %s [%s]", ui.StyleVersion.Render("•"), ui.StyleBold.Render(action))
		if source != "" {
			line += " " + ui.StyleMeta.Render(source)
		}
		fmt.Fprintln(w, line)

		msg := strings.TrimSpace(firstNonEmpty(f.Reason, f.Message))
		if msg != "" {
			fmt.Fprintln(w, "    "+ui.StyleSymbol.Render("• ")+msg)
		}
		if rem := strings.TrimSpace(f.Remediation); rem != "" {
			fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Remediation: ")+rem)
		}
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
