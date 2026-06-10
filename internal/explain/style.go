package explain

import "github.com/charmbracelet/lipgloss"

// Style definitions for vulnerability explanation rendering.
// These styles align with Deputy's existing UI palette (internal/ui/style.go)
// while adding explain-specific styles for comprehensive vulnerability display.
//
// Color palette (aligned with Deputy conventions from internal/ui/style.go):
// - #FFFFFF: Primary text, identifiers (StyleNeutral, StylePackageName)
// - #00BFFF: Headers, section titles (StyleHeader)
// - #FF00FF: Critical severity (StyleCritical)
// - #FF5555: High severity, errors, warnings (StyleRemoved)
// - #FFD700: Medium severity, caution (StyleDowngraded)
// - #A9A9A9: Low/unknown severity, versions (StyleVersion) - faint
// - #32CD32: Positive/fixed/added items (StyleAdded)
// - #666666: Dimmed, secondary text (StyleDim)
// - #A0A0A0: Metadata, descriptions (StyleMeta)
// - #BBBBBB: Primary aliases (StyleAlias)
// - #87CEEB: Code, commands, policies (StylePolicyFile)
// - #7FDBFF: Package managers, ecosystems (StyleManager)
var (
	// Header styles - aligned with ui.StyleHeader (#00BFFF)
	styleID      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	styleSummary = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Italic(true) // StyleMeta
	styleSection = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")).Bold(true)   // StyleHeader

	// Severity badge styles - aligned with ui.SeverityLabel (see internal/ui/style.go)
	styleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true)  // StyleCritical
	styleHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)  // StyleRemoved
	styleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)  // StyleDowngraded
	styleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true) // StyleVersion (matches scan output)
	styleUnknown  = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true) // StyleVersion (matches scan [?])

	// Content styles
	styleLabel    = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")) // Subtle labels (lighter than dim)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")) // StyleDim
	styleEmphasis = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")) // StyleNeutral
	styleAlias    = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC")) // Aliases - visible but not bold
	styleLink     = lipgloss.NewStyle().Foreground(lipgloss.Color("#6699AA")) // Dimmer links - readable but not overpowering
	styleFix      = lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")) // StyleAdded - for fix versions

	// Package/code styles - aligned with ui styles
	stylePackage = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))             // StylePackageName
	styleVersion = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true) // StyleVersion

	// Threat intelligence styles
	styleWarning = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")) // StyleRemoved
	styleCaution = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")) // StyleDowngraded
	styleGood    = lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")) // StyleAdded

	// CWE styles - purple for technical identifiers
	styleCWE = lipgloss.NewStyle().Foreground(lipgloss.Color("#BB99FF"))

	// Contextual hint style
	styleHint = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")).Italic(true) // StyleDim + italic
)

// Unicode symbols for visual markers (no emojis)
const (
	symbolBullet    = "•"
	symbolArrow     = "→"
	symbolCheck     = "✓"
	symbolCross     = "✗"
	symbolWarning   = "!"
	symbolInfo      = "i"
	symbolStar      = "*"
	symbolDash      = "─"
	symbolTreeVert  = "│"
	symbolTreeBr    = "├"
	symbolTreeEnd   = "└"
	symbolTreeHoriz = "──"
)
