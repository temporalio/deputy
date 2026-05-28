package render

import (
	"fmt"
	"io"
	"strings"

	remediation "github.com/temporalio/deputy/internal/remediation"
	ui "github.com/temporalio/deputy/internal/ui"
)

// RemediationCommands prints grouped remediation commands using the
// provided prefixes for group headers and command lines.
// Follow-up commands (like "go mod tidy", "uv lock") are deduplicated and
// printed once at the end of each group.
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

		// Collect unique follow-up commands for this group
		followUps := []string{}
		seenFollowUps := make(map[string]bool)

		for _, rec := range grouped[label] {
			// Print the main command
			printCommand(w, commandPrefix, rec.Command, rec.IsDirect, rec.Groups, rec.Hint)

			// Collect unique follow-up commands
			if rec.FollowUp != "" && !seenFollowUps[rec.FollowUp] {
				seenFollowUps[rec.FollowUp] = true
				followUps = append(followUps, rec.FollowUp)
			}
		}

		// Print all unique follow-up commands at the end of the group
		for _, followUp := range followUps {
			printCommand(w, commandPrefix, followUp, false, nil, "")
		}
	}
}

// printCommand renders a single remediation command line with optional context.
func printCommand(w io.Writer, prefix, command string, isDirect bool, groups []string, hint string) {
	symbol := "›"
	if command == "go mod tidy" {
		symbol = "↻"
	}
	style := ui.StyleVersion
	if isDirect {
		style = ui.StyleUpgraded
	}
	marker := style.Render(symbol)
	contexts := []string{}
	if len(groups) > 0 {
		contexts = append(contexts, strings.Join(groups, ","))
	}
	if hint != "" {
		contexts = append(contexts, hint)
	}
	suffix := ""
	if len(contexts) > 0 {
		suffix = ui.StyleDim.Render("  # " + strings.Join(contexts, "; "))
	}
	fmt.Fprintf(w, "%s%s %s%s\n", prefix, marker, command, suffix)
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
