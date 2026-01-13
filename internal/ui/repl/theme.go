package repl

import (
	"github.com/charmbracelet/lipgloss"
)

// Theme defines the visual appearance of the REPL.
type Theme struct {
	Name string

	// Prompt elements
	Prompt      lipgloss.Style // The prompt indicator
	Context     lipgloss.Style // Context label (entrypoint name)
	Cursor      lipgloss.Style // Cursor style

	// Output styling
	Result      lipgloss.Style // Successful result
	ResultFalse lipgloss.Style // False boolean result (attention)
	Error       lipgloss.Style // Error messages
	Warning     lipgloss.Style // Warning messages
	Info        lipgloss.Style // Informational text
	Hint        lipgloss.Style // Inline hints (ghost text)
	Ghost       lipgloss.Style // Ghost completion text

	// Completion styling
	CompletionSelected  lipgloss.Style // Selected completion
	CompletionNormal    lipgloss.Style // Unselected completion
	CompletionKind      lipgloss.Style // Kind indicator (func, var, etc)
	CompletionType      lipgloss.Style // Type annotation
	CompletionDesc      lipgloss.Style // Description text

	// Syntax highlighting
	SyntaxKeyword  lipgloss.Style // true, false, null, in
	SyntaxString   lipgloss.Style // "strings"
	SyntaxNumber   lipgloss.Style // 123, 3.14
	SyntaxOperator lipgloss.Style // ==, &&, ||
	SyntaxFunction lipgloss.Style // function names
	SyntaxField    lipgloss.Style // field.access
	SyntaxVariable lipgloss.Style // variable names
	SyntaxComment  lipgloss.Style // // comments
	SyntaxEnum     lipgloss.Style // enum values

	// Structural
	Key       lipgloss.Style // Key in key=value pairs
	Value     lipgloss.Style // Value in key=value pairs
	Label     lipgloss.Style // Section labels
	Divider   lipgloss.Style // Dividers and borders
	Command   lipgloss.Style // Meta-commands (:help, :set)

	// Command syntax styling (for help text)
	Placeholder lipgloss.Style // Metavariables like <key>, NAME (italic, distinct)
	Punctuation lipgloss.Style // Subtle punctuation (=, /, etc.)
	Literal     lipgloss.Style // Literal example values
	Optional    lipgloss.Style // Optional parts [optional]

	// Status indicators
	Success lipgloss.Style // Success indicator
	Failure lipgloss.Style // Failure indicator

	// Symbols
	PromptSymbol    string // Usually "›" or ">"
	ContinueSymbol  string // Multi-line continuation
	ResultSymbol    string // Result indicator
	ErrorSymbol     string // Error indicator
	HintSymbol      string // Hint indicator
	CompletionLeft  string // Left bracket for completions
	CompletionRight string // Right bracket for completions
}

// DefaultTheme returns the default REPL theme.
func DefaultTheme() *Theme {
	return &Theme{
		Name: "default",

		// Prompt - cyan/blue tones
		Prompt:  lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")).Bold(true),
		Context: lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")),
		Cursor:  lipgloss.NewStyle().Reverse(true),

		// Output
		Result:      lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")),
		ResultFalse: lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")),
		Error:       lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")),
		Warning:     lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB74D")),
		Info:        lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")),
		Hint:        lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")).Italic(true),
		Ghost:       lipgloss.NewStyle().Foreground(lipgloss.Color("#555555")),

		// Completions
		CompletionSelected: lipgloss.NewStyle().
			Background(lipgloss.Color("#3A3A3A")).
			Foreground(lipgloss.Color("#FFFFFF")),
		CompletionNormal: lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC")),
		CompletionKind:   lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")),
		CompletionType:   lipgloss.NewStyle().Foreground(lipgloss.Color("#6A9955")).Italic(true),
		CompletionDesc:   lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")),

		// Syntax highlighting
		SyntaxKeyword:  lipgloss.NewStyle().Foreground(lipgloss.Color("#C586C0")), // purple
		SyntaxString:   lipgloss.NewStyle().Foreground(lipgloss.Color("#CE9178")), // orange
		SyntaxNumber:   lipgloss.NewStyle().Foreground(lipgloss.Color("#B5CEA8")), // light green
		SyntaxOperator: lipgloss.NewStyle().Foreground(lipgloss.Color("#D4D4D4")), // light gray
		SyntaxFunction: lipgloss.NewStyle().Foreground(lipgloss.Color("#DCDCAA")), // yellow
		SyntaxField:    lipgloss.NewStyle().Foreground(lipgloss.Color("#9CDCFE")), // light blue
		SyntaxVariable: lipgloss.NewStyle().Foreground(lipgloss.Color("#9CDCFE")), // light blue
		SyntaxComment:  lipgloss.NewStyle().Foreground(lipgloss.Color("#6A9955")), // green
		SyntaxEnum:     lipgloss.NewStyle().Foreground(lipgloss.Color("#4EC9B0")), // teal

		// Structural
		Key:     lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB")),
		Value:   lipgloss.NewStyle().Foreground(lipgloss.Color("#E6E6FA")),
		Label:   lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")).Bold(true),
		Divider: lipgloss.NewStyle().Foreground(lipgloss.Color("#444444")),
		Command: lipgloss.NewStyle().Foreground(lipgloss.Color("#5FAFFF")), // Brighter blue for commands

		// Command syntax styling
		Placeholder: lipgloss.NewStyle().Foreground(lipgloss.Color("#B0B0B0")).Italic(true), // Gray italic for metavars
		Punctuation: lipgloss.NewStyle().Foreground(lipgloss.Color("#606060")),              // Dim for punctuation
		Literal:     lipgloss.NewStyle().Foreground(lipgloss.Color("#CE9178")),              // Orange for literals
		Optional:    lipgloss.NewStyle().Foreground(lipgloss.Color("#808080")),              // Gray for optional parts

		// Status
		Success: lipgloss.NewStyle().Foreground(lipgloss.Color("#50C878")),
		Failure: lipgloss.NewStyle().Foreground(lipgloss.Color("#E57373")),

		// Symbols
		PromptSymbol:    "›",
		ContinueSymbol:  "·",
		ResultSymbol:    "→",
		ErrorSymbol:     "✗",
		HintSymbol:      "·",
		CompletionLeft:  "‹",
		CompletionRight: "›",
	}
}

// MinimalTheme returns a minimal, low-color theme.
func MinimalTheme() *Theme {
	t := DefaultTheme()
	t.Name = "minimal"

	// Use mostly default terminal colors
	gray := lipgloss.NewStyle().Faint(true)
	bold := lipgloss.NewStyle().Bold(true)
	normal := lipgloss.NewStyle()

	t.Prompt = bold
	t.Context = gray
	t.Result = bold
	t.ResultFalse = bold
	t.Error = bold
	t.Warning = bold
	t.Info = gray
	t.Hint = gray
	t.Ghost = gray

	t.CompletionSelected = lipgloss.NewStyle().Reverse(true)
	t.CompletionNormal = normal
	t.CompletionKind = gray
	t.CompletionType = gray
	t.CompletionDesc = gray

	t.SyntaxKeyword = bold
	t.SyntaxString = normal
	t.SyntaxNumber = normal
	t.SyntaxOperator = normal
	t.SyntaxFunction = bold
	t.SyntaxField = normal
	t.SyntaxVariable = normal
	t.SyntaxComment = gray
	t.SyntaxEnum = bold

	t.Key = bold
	t.Value = normal
	t.Label = bold
	t.Divider = gray
	t.Command = bold

	t.Placeholder = lipgloss.NewStyle().Italic(true)
	t.Punctuation = gray
	t.Literal = normal
	t.Optional = gray

	// ASCII symbols
	t.PromptSymbol = ">"
	t.ContinueSymbol = "."
	t.ResultSymbol = "->"
	t.ErrorSymbol = "X"
	t.HintSymbol = "-"
	t.CompletionLeft = "["
	t.CompletionRight = "]"

	return t
}

// MonokaiTheme returns a Monokai-inspired theme.
func MonokaiTheme() *Theme {
	t := DefaultTheme()
	t.Name = "monokai"

	// Monokai color palette
	pink := lipgloss.Color("#F92672")
	orange := lipgloss.Color("#FD971F")
	yellow := lipgloss.Color("#E6DB74")
	green := lipgloss.Color("#A6E22E")
	cyan := lipgloss.Color("#66D9EF")
	purple := lipgloss.Color("#AE81FF")
	gray := lipgloss.Color("#75715E")
	white := lipgloss.Color("#F8F8F2")

	t.Prompt = lipgloss.NewStyle().Foreground(green).Bold(true)
	t.Result = lipgloss.NewStyle().Foreground(green)
	t.ResultFalse = lipgloss.NewStyle().Foreground(orange)
	t.Error = lipgloss.NewStyle().Foreground(pink)
	t.Warning = lipgloss.NewStyle().Foreground(orange)

	t.SyntaxKeyword = lipgloss.NewStyle().Foreground(pink)
	t.SyntaxString = lipgloss.NewStyle().Foreground(yellow)
	t.SyntaxNumber = lipgloss.NewStyle().Foreground(purple)
	t.SyntaxOperator = lipgloss.NewStyle().Foreground(pink)
	t.SyntaxFunction = lipgloss.NewStyle().Foreground(green)
	t.SyntaxField = lipgloss.NewStyle().Foreground(cyan)
	t.SyntaxVariable = lipgloss.NewStyle().Foreground(white)
	t.SyntaxComment = lipgloss.NewStyle().Foreground(gray)
	t.SyntaxEnum = lipgloss.NewStyle().Foreground(purple)

	return t
}

// DraculaTheme returns a Dracula-inspired theme.
func DraculaTheme() *Theme {
	t := DefaultTheme()
	t.Name = "dracula"

	// Dracula color palette
	background := lipgloss.Color("#282A36")
	foreground := lipgloss.Color("#F8F8F2")
	cyan := lipgloss.Color("#8BE9FD")
	green := lipgloss.Color("#50FA7B")
	orange := lipgloss.Color("#FFB86C")
	pink := lipgloss.Color("#FF79C6")
	purple := lipgloss.Color("#BD93F9")
	red := lipgloss.Color("#FF5555")
	yellow := lipgloss.Color("#F1FA8C")
	comment := lipgloss.Color("#6272A4")

	t.Prompt = lipgloss.NewStyle().Foreground(purple).Bold(true)
	t.Result = lipgloss.NewStyle().Foreground(green)
	t.ResultFalse = lipgloss.NewStyle().Foreground(orange)
	t.Error = lipgloss.NewStyle().Foreground(red)
	t.Warning = lipgloss.NewStyle().Foreground(orange)
	t.Info = lipgloss.NewStyle().Foreground(comment)
	t.Hint = lipgloss.NewStyle().Foreground(comment).Italic(true)

	t.CompletionSelected = lipgloss.NewStyle().
		Background(background).
		Foreground(foreground)

	t.SyntaxKeyword = lipgloss.NewStyle().Foreground(pink)
	t.SyntaxString = lipgloss.NewStyle().Foreground(yellow)
	t.SyntaxNumber = lipgloss.NewStyle().Foreground(purple)
	t.SyntaxOperator = lipgloss.NewStyle().Foreground(pink)
	t.SyntaxFunction = lipgloss.NewStyle().Foreground(green)
	t.SyntaxField = lipgloss.NewStyle().Foreground(cyan)
	t.SyntaxVariable = lipgloss.NewStyle().Foreground(foreground)
	t.SyntaxComment = lipgloss.NewStyle().Foreground(comment)
	t.SyntaxEnum = lipgloss.NewStyle().Foreground(purple)

	return t
}

// ThemeByName returns a theme by name, or the default if not found.
func ThemeByName(name string) *Theme {
	switch name {
	case "minimal":
		return MinimalTheme()
	case "monokai":
		return MonokaiTheme()
	case "dracula":
		return DraculaTheme()
	default:
		return DefaultTheme()
	}
}

// AvailableThemes returns the names of all available themes.
func AvailableThemes() []string {
	return []string{"default", "minimal", "monokai", "dracula"}
}
