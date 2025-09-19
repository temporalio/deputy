package ui

import "github.com/charmbracelet/lipgloss"

// Predefined lipgloss style palette used by CLI presentation layers. Grouping
// styles here keeps formatting concerns separate from formatting logic.
var (
	StyleAdded      = lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")).Bold(true)
	StyleRemoved    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true)
	StyleHeader     = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")).Bold(true)
	StyleDim        = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))
	StyleAlias      = lipgloss.NewStyle().Foreground(lipgloss.Color("#BBBBBB")).Bold(true)
	StyleAliasOther = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC")).Bold(true)
	StyleMeta       = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Italic(true)
	StyleBold       = lipgloss.NewStyle().Bold(true)
	StyleUpgraded   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Bold(true)
	StyleDowngraded = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	StyleNeutral    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)

	StylePackageName    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	StyleVersion        = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true)
	StyleLicense        = lipgloss.NewStyle().Foreground(lipgloss.Color("#A9A9A9")).Faint(true)
	StyleUpdateArrow    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CED1")).Faint(true)
	StyleDowngradeArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Faint(true)
	StyleSymbol         = lipgloss.NewStyle().Bold(true)
	StylePath           = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6E6FA"))
	StyleManager        = lipgloss.NewStyle().Foreground(lipgloss.Color("#7FDBFF")).Faint(true)
)
