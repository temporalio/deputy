package render

import (
	"fmt"
	"io"
	"strings"

	remediation "github.com/picatz/deputy/internal/remediation"
	ui "github.com/picatz/deputy/internal/ui"
)

// RemediationCommands prints grouped remediation commands using the
// provided prefixes for group headers and command lines.
func RemediationCommands(w io.Writer, commands []remediation.Command, groupPrefix, commandPrefix string) {
	if len(commands) == 0 {
		return
	}
	order, grouped, groupIsPath := groupRemediationCommands(commands)
	for _, label := range order {
		if groupIsPath[label] {
			fmt.Fprintln(w, groupPrefix+ui.StylePath.Render(label)+":")
		} else {
			fmt.Fprintln(w, groupPrefix+ui.StyleManager.Render(label)+":")
		}
		for _, rec := range grouped[label] {
			symbol := "›"
			if rec.Command == "go mod tidy" {
				symbol = "↻"
			}
			style := ui.StyleVersion
			if rec.IsDirect {
				style = ui.StyleUpgraded
			}
			marker := style.Render(symbol)
			contexts := []string{}
			if len(rec.Groups) > 0 {
				contexts = append(contexts, strings.Join(rec.Groups, ","))
			}
			if rec.Hint != "" {
				contexts = append(contexts, rec.Hint)
			}
			suffix := ""
			if len(contexts) > 0 {
				suffix = ui.StyleDim.Render("  # " + strings.Join(contexts, "; "))
			}
			fmt.Fprintf(w, "%s%s %s%s\n", commandPrefix, marker, rec.Command, suffix)
		}
	}
}

// groupRemediationCommands organizes commands by manifest path/manager label and
// preserves their first-seen order for stable rendering.
func groupRemediationCommands(commands []remediation.Command) ([]string, map[string][]remediation.Command, map[string]bool) {
	order := []string{}
	grouped := map[string][]remediation.Command{}
	groupIsPath := map[string]bool{}
	for _, rec := range commands {
		label := strings.TrimSpace(rec.Path)
		isPath := true
		if label == "" {
			label = strings.TrimSpace(rec.Manager)
			isPath = false
			if label == "" {
				label = "other"
			}
		}
		if _, ok := grouped[label]; !ok {
			order = append(order, label)
			groupIsPath[label] = isPath
		}
		grouped[label] = append(grouped[label], rec)
	}
	return order, grouped, groupIsPath
}
