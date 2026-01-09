package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/deputy/internal/vulnerability/severity/cvss"
)

// Predefined lipgloss style palette used by CLI presentation layers. Grouping
// styles here keeps formatting concerns separate from formatting logic.
var (
	// StyleAdded is used for newly added items or positive changes.
	StyleAdded = lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")).Bold(true)
	// StyleRemoved is used for removed items or negative changes.
	StyleRemoved = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)
	// StyleHeader is used for section headers.
	StyleHeader = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")).Bold(true)
	// StyleDim is used for less important or secondary text.
	StyleDim = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	// StyleAlias is used for primary aliases or alternative names.
	StyleAlias = lipgloss.NewStyle().Foreground(lipgloss.Color("#BBBBBB")).Bold(true)
	// StyleAliasOther is used for secondary aliases.
	StyleAliasOther = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC")).Bold(true)
	// StyleMeta is used for metadata or supplementary information.
	StyleMeta = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Italic(true)
	// StyleBold is a generic bold style.
	StyleBold = lipgloss.NewStyle().Bold(true)
	// StyleUpgraded is used for version upgrades.
	StyleUpgraded = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Bold(true)
	// StyleDowngraded is used for version downgrades.
	StyleDowngraded = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	// StyleNeutral is a generic neutral bold style.
	StyleNeutral = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)

	// StylePackageName is used for displaying package names.
	StylePackageName = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	// StyleVersion is used for displaying package versions (old/base version in diffs).
	StyleVersion = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true)
	// StyleVersionNew is used for displaying new/target versions in diffs (slightly brighter).
	StyleVersionNew = lipgloss.NewStyle().Foreground(lipgloss.Color("#C8C8C8"))
	// StyleLicense is used for displaying package licenses.
	StyleLicense = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true)
	// StyleDirect is used for [direct] dependency labels (brighter, more prominent).
	StyleDirect = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB")) // Sky blue
	// StyleIndirect is used for [indirect] dependency labels (dimmer).
	StyleIndirect = lipgloss.NewStyle().Foreground(lipgloss.Color("#808080")).Faint(true)
	// StyleUpdateArrow is used for the arrow in upgrade paths.
	StyleUpdateArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Faint(true)
	// StyleDowngradeArrow is used for the arrow in downgrade paths.
	StyleDowngradeArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Faint(true)
	// StyleSymbol is used for generic symbols or icons.
	StyleSymbol = lipgloss.NewStyle().Bold(true)
	// StylePath is used for file or directory paths.
	StylePath = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6E6FA"))
	// StyleManager is used for package manager names (e.g., npm, gomod).
	StyleManager = lipgloss.NewStyle().Foreground(lipgloss.Color("#7FDBFF")).Faint(true)

	// StyleCritical is used for critical severity vulnerabilities.
	StyleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true)

	// StylePolicyFile is used for policy file references in proxy output.
	StylePolicyFile = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB")) // Sky blue
	// StylePolicyRule is used for policy rule names in proxy output.
	StylePolicyRule = lipgloss.NewStyle().Foreground(lipgloss.Color("#B0C4DE")) // Light steel blue
	// StyleSeparator is used for punctuation or separators in proxy output.
	StyleSeparator = lipgloss.NewStyle().Foreground(lipgloss.Color("#708090")) // Slate gray

	// Agent metadata styles - used for spinner status and footer metadata
	// These use a muted gray palette for subtle, non-distracting visual cues.

	// StyleAgentBracket is used for brackets around status hints [thinking].
	StyleAgentBracket = lipgloss.NewStyle().Foreground(lipgloss.Color("#4E4E4E")) // Dark gray
	// StyleAgentStatus is used for status text inside brackets (e.g., "thinking", "reading").
	StyleAgentStatus = lipgloss.NewStyle().Foreground(lipgloss.Color("#8A8A8A")) // Medium gray
	// StyleAgentProvider is used for provider/model names in metadata.
	StyleAgentProvider = lipgloss.NewStyle().Foreground(lipgloss.Color("#B0B0B0")) // Light gray
	// StyleAgentModel is used for model identifiers.
	StyleAgentModel = lipgloss.NewStyle().Foreground(lipgloss.Color("#9A9A9A")) // Slightly darker gray
	// StyleAgentSandbox is used for sandbox mode indicators.
	StyleAgentSandbox = lipgloss.NewStyle().Foreground(lipgloss.Color("#7A7A7A")) // Medium-dark gray
	// StyleAgentTokens is used for token count numbers.
	StyleAgentTokens = lipgloss.NewStyle().Foreground(lipgloss.Color("#A8A8A8")) // Light-medium gray
	// StyleAgentTokensLabel is used for "tokens" and "(in, out)" labels.
	StyleAgentTokensLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("#606060")) // Darker gray
	// StyleAgentDuration is used for timing information.
	StyleAgentDuration = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")) // Light gray
	// StyleAgentDot is used for the · separator in metadata lines.
	StyleAgentDot = lipgloss.NewStyle().Foreground(lipgloss.Color("#505050")) // Dark gray
	// StyleAgentStar is used for the AI indicator star (✦) in metadata lines.
	StyleAgentStar = lipgloss.NewStyle().Foreground(lipgloss.Color("#B8860B")) // Dark goldenrod (muted yellow)

	// Command output status indicators - softer circles instead of harsh checkmarks
	// StyleStatusSuccess is for successful operations (green circle).
	StyleStatusSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("#50C878")) // Emerald green
	// StyleStatusError is for failed operations (red circle).
	StyleStatusError = lipgloss.NewStyle().Foreground(lipgloss.Color("#E57373")) // Soft red
	// StyleStatusWarning is for warnings or uncertain states (amber circle).
	StyleStatusWarning = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB74D")) // Amber
	// StyleStatusPending is for in-progress operations (blue circle).
	StyleStatusPending = lipgloss.NewStyle().Foreground(lipgloss.Color("#64B5F6")) // Soft blue

	// Output line threading - connects output to its command with matching colors
	// StyleLineSuccess threads successful command output.
	StyleLineSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("#3D7A4A")) // Muted green
	// StyleLineError threads failed command output.
	StyleLineError = lipgloss.NewStyle().Foreground(lipgloss.Color("#A84444")) // Muted red
	// StyleLineWarning threads warning output.
	StyleLineWarning = lipgloss.NewStyle().Foreground(lipgloss.Color("#B38B3D")) // Muted amber
	// StyleLineDim threads neutral/info output.
	StyleLineDim = lipgloss.NewStyle().Foreground(lipgloss.Color("#4A4A4A")) // Dark gray
)

// AIStarPrefix returns a styled AI indicator star for metadata footers.
// Uses ✦ (filled four-pointed star) with a muted yellow color.
func AIStarPrefix() string {
	return StyleAgentStar.Render("✦") + " "
}

// SeverityLabel returns a consistently styled severity label in the format [CRITICAL], [HIGH], [MED], [LOW], or [?].
// It normalizes GHSA-style severity names (CRITICAL, HIGH, MODERATE/MEDIUM, LOW) and CVSS scores.
func SeverityLabel(severity, severityType string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))

	// Handle GHSA-style severity names
	if severityType == "GHSA" || isGHSASeverity(sev) {
		switch sev {
		case "CRITICAL":
			return StyleCritical.Render("[CRITICAL]")
		case "HIGH":
			return StyleRemoved.Render("[HIGH]")
		case "MODERATE", "MEDIUM":
			return StyleDowngraded.Render("[MED]")
		case "LOW":
			return StyleVersion.Render("[LOW]")
		}
	}

	// Try to parse as CVSS score
	score := cvss.ParseScore(severity)
	return ScoreLabel(score)
}

// ScoreLabel returns a styled severity label based on a numeric CVSS score.
func ScoreLabel(score float64) string {
	switch {
	case score >= 9.0:
		return StyleCritical.Render("[CRITICAL]")
	case score >= 7.0:
		return StyleRemoved.Render("[HIGH]")
	case score >= 4.0:
		return StyleDowngraded.Render("[MED]")
	case score >= 0.0:
		return StyleVersion.Render("[LOW]")
	default:
		return StyleVersion.Render("[?]")
	}
}

// isGHSASeverity checks if a severity string looks like a GHSA severity name.
func isGHSASeverity(sev string) bool {
	switch sev {
	case "CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW":
		return true
	}
	return false
}
