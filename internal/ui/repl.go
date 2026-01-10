package ui

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
)

// REPL styles for interactive policy evaluation.
var (
	// StyleREPLPrompt is for the primary prompt indicator.
	StyleREPLPrompt = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")).Bold(true)

	// StyleREPLContinue is for continuation prompts (multi-line input).
	StyleREPLContinue = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))

	// StyleREPLCommand is for meta-commands (:help, :set).
	StyleREPLCommand = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB"))

	// StyleREPLResult is for successful evaluation results.
	StyleREPLResult = lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32"))

	// StyleREPLResultFalse is for false boolean results (attention-drawing).
	StyleREPLResultFalse = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))

	// StyleREPLError is for error messages.
	StyleREPLError = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555"))

	// StyleREPLInfo is for informational messages.
	StyleREPLInfo = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0"))

	// StyleREPLKey is for variable/field names in context display.
	StyleREPLKey = lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB"))

	// StyleREPLValue is for values in context display.
	StyleREPLValue = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6E6FA"))

	// StyleREPLLabel is for section labels.
	StyleREPLLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")).Bold(true)

	// StyleREPLHint is for hints and suggestions.
	StyleREPLHint = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")).Italic(true)

	// StyleREPLType is for type annotations.
	StyleREPLType = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))

	// StyleREPLPlaceholder is for metavariables/placeholders in help text.
	StyleREPLPlaceholder = lipgloss.NewStyle().Foreground(lipgloss.Color("#B0B0B0")).Italic(true)

	// StyleREPLPunctuation is for subtle punctuation.
	StyleREPLPunctuation = lipgloss.NewStyle().Foreground(lipgloss.Color("#606060"))

	// StyleREPLLiteral is for literal values in examples.
	StyleREPLLiteral = lipgloss.NewStyle().Foreground(lipgloss.Color("#CE9178"))

	// StyleREPLOptional is for optional parts [optional].
	StyleREPLOptional = lipgloss.NewStyle().Foreground(lipgloss.Color("#808080"))
)

// REPLOutput provides styled output methods for REPL implementations.
type REPLOutput struct {
	w              io.Writer
	useColor       bool
	highlightStyle string
}

// NewREPLOutput creates a new REPLOutput writer.
func NewREPLOutput(w io.Writer) *REPLOutput {
	return &REPLOutput{
		w:              w,
		useColor:       true,
		highlightStyle: "monokai",
	}
}

// SetColorEnabled enables or disables colored output.
func (r *REPLOutput) SetColorEnabled(enabled bool) {
	r.useColor = enabled
}

// SetHighlightStyle sets the syntax highlighting style name.
func (r *REPLOutput) SetHighlightStyle(style string) {
	r.highlightStyle = style
}

// Prompt writes the REPL prompt.
func (r *REPLOutput) Prompt(context string) {
	if context != "" {
		fmt.Fprint(r.w, StyleREPLInfo.Render(context)+" ")
	}
	fmt.Fprint(r.w, StyleREPLPrompt.Render("cel")+" "+StyleREPLPrompt.Render(">")+" ")
}

// Continue writes a continuation prompt for multi-line input.
func (r *REPLOutput) Continue() {
	fmt.Fprint(r.w, StyleREPLContinue.Render("...  "))
}

// Result writes a successful evaluation result.
func (r *REPLOutput) Result(value any) {
	var style lipgloss.Style
	switch v := value.(type) {
	case bool:
		if v {
			style = StyleREPLResult
		} else {
			style = StyleREPLResultFalse
		}
	default:
		style = StyleREPLResult
	}
	fmt.Fprintf(r.w, "%s %s\n", StyleREPLLabel.Render("→"), style.Render(fmt.Sprintf("%v", value)))
}

// ResultWithType writes a result with type annotation.
func (r *REPLOutput) ResultWithType(value any, typeName string) {
	var style lipgloss.Style
	switch v := value.(type) {
	case bool:
		if v {
			style = StyleREPLResult
		} else {
			style = StyleREPLResultFalse
		}
	default:
		style = StyleREPLResult
	}
	typeStr := StyleREPLType.Render("(" + typeName + ")")
	fmt.Fprintf(r.w, "%s %s %s\n", StyleREPLLabel.Render("→"), style.Render(fmt.Sprintf("%v", value)), typeStr)
}

// Error writes an error message.
func (r *REPLOutput) Error(msg string) {
	fmt.Fprintf(r.w, "%s %s\n", StyleREPLError.Render("✗"), StyleREPLError.Render(msg))
}

// ErrorWithHint writes an error with a suggestion.
func (r *REPLOutput) ErrorWithHint(msg, hint string) {
	fmt.Fprintf(r.w, "%s %s\n", StyleREPLError.Render("✗"), StyleREPLError.Render(msg))
	if hint != "" {
		fmt.Fprintf(r.w, "  %s\n", StyleREPLHint.Render("hint: "+hint))
	}
}

// Info writes an informational message.
func (r *REPLOutput) Info(msg string) {
	fmt.Fprintln(r.w, StyleREPLInfo.Render(msg))
}

// CommandHelp writes a formatted help entry with syntax highlighting.
// The command string is parsed to highlight:
//   - Commands starting with : are styled as commands
//   - UPPERCASE words are styled as placeholders
//   - = and other punctuation are styled subtly
func (r *REPLOutput) CommandHelp(command, description string) {
	styled := styleCommandSyntax(command)
	fmt.Fprintf(r.w, "  %s  %s\n", styled, StyleREPLInfo.Render(description))
}

// CommandHelpRow represents a single command help entry for aligned output.
type CommandHelpRow struct {
	Command     string
	Description string
}

// CommandHelpAligned writes multiple command help entries with aligned descriptions.
func (r *REPLOutput) CommandHelpAligned(rows []CommandHelpRow) {
	// Calculate max command width (using raw length, not styled)
	maxWidth := 0
	for _, row := range rows {
		if len(row.Command) > maxWidth {
			maxWidth = len(row.Command)
		}
	}

	for _, row := range rows {
		styled := styleCommandSyntax(row.Command)
		padding := strings.Repeat(" ", maxWidth-len(row.Command))
		fmt.Fprintf(r.w, "  %s%s  %s\n", styled, padding, StyleREPLInfo.Render(row.Description))
	}
}

// CELExample writes a syntax-highlighted CEL expression as an example.
func (r *REPLOutput) CELExample(expr string) {
	highlighted := r.HighlightCEL(expr)
	fmt.Fprintf(r.w, "  %s\n", highlighted)
}

// styleCommandSyntax applies semantic styling to command syntax.
func styleCommandSyntax(cmd string) string {
	var result strings.Builder

	i := 0
	for i < len(cmd) {
		switch {
		// Command starting with :
		case cmd[i] == ':':
			j := i + 1
			for j < len(cmd) && (cmd[j] >= 'a' && cmd[j] <= 'z' || cmd[j] >= 'A' && cmd[j] <= 'Z' || cmd[j] == '-' || cmd[j] == '_') {
				j++
			}
			result.WriteString(StyleREPLCommand.Render(cmd[i:j]))
			i = j

		// UPPERCASE placeholder (KEY, VALUE, NAME)
		case cmd[i] >= 'A' && cmd[i] <= 'Z':
			j := i
			for j < len(cmd) && ((cmd[j] >= 'A' && cmd[j] <= 'Z') || cmd[j] == '_') {
				j++
			}
			result.WriteString(StyleREPLPlaceholder.Render(cmd[i:j]))
			i = j

		// Punctuation: =, /, |
		case cmd[i] == '=' || cmd[i] == '/' || cmd[i] == '|':
			result.WriteString(StyleREPLPunctuation.Render(string(cmd[i])))
			i++

		// Quoted string literal
		case cmd[i] == '"':
			j := i + 1
			for j < len(cmd) && cmd[j] != '"' {
				j++
			}
			if j < len(cmd) {
				j++
			}
			result.WriteString(StyleREPLLiteral.Render(cmd[i:j]))
			i = j

		// Optional brackets [...]
		case cmd[i] == '[':
			j := i + 1
			for j < len(cmd) && cmd[j] != ']' {
				j++
			}
			if j < len(cmd) {
				j++
			}
			result.WriteString(StyleREPLOptional.Render(cmd[i:j]))
			i = j

		// Space
		case cmd[i] == ' ':
			result.WriteByte(' ')
			i++

		// lowercase words (placeholders like key, value)
		case cmd[i] >= 'a' && cmd[i] <= 'z':
			j := i
			for j < len(cmd) && ((cmd[j] >= 'a' && cmd[j] <= 'z') || cmd[j] == '-' || cmd[j] == '_') {
				j++
			}
			result.WriteString(StyleREPLPlaceholder.Render(cmd[i:j]))
			i = j

		default:
			result.WriteByte(cmd[i])
			i++
		}
	}

	return result.String()
}

// KeyValue writes a key-value pair.
func (r *REPLOutput) KeyValue(key string, value any) {
	fmt.Fprintf(r.w, "  %s %s %s\n",
		StyleREPLKey.Render(key),
		StyleREPLInfo.Render("="),
		StyleREPLValue.Render(fmt.Sprintf("%v", value)),
	)
}

// Section writes a section header.
func (r *REPLOutput) Section(title string) {
	fmt.Fprintf(r.w, "\n%s\n", StyleREPLLabel.Render(title))
}

// Blank writes a blank line.
func (r *REPLOutput) Blank() {
	fmt.Fprintln(r.w)
}

// Welcome writes a REPL welcome message.
func (r *REPLOutput) Welcome(title, subtitle string) {
	fmt.Fprintf(r.w, "%s\n", StyleHeader.Render(title))
	if subtitle != "" {
		fmt.Fprintf(r.w, "%s\n", StyleREPLInfo.Render(subtitle))
	}
	fmt.Fprintln(r.w)
}

// Goodbye writes a REPL exit message.
func (r *REPLOutput) Goodbye() {
	fmt.Fprintln(r.w, StyleREPLInfo.Render("Goodbye!"))
}

// HighlightCEL applies syntax highlighting to a CEL expression.
// Falls back to plain text if highlighting fails.
func (r *REPLOutput) HighlightCEL(expr string) string {
	if !r.useColor {
		return expr
	}
	return HighlightCEL(expr, r.highlightStyle)
}

// HighlightCEL applies syntax highlighting to a CEL expression.
// Uses a Go-like lexer since CEL syntax is similar.
func HighlightCEL(expr, styleName string) string {
	// CEL is similar to Go expressions, so we use Go lexer
	lexer := lexers.Get("go")
	if lexer == nil {
		return expr
	}
	lexer = chroma.Coalesce(lexer)

	style := styles.Get(styleName)
	if style == nil {
		style = styles.Fallback
	}

	formatter := formatters.Get("terminal256")
	if formatter == nil {
		formatter = formatters.Fallback
	}

	iterator, err := lexer.Tokenise(nil, expr)
	if err != nil {
		return expr
	}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, style, iterator); err != nil {
		return expr
	}

	return strings.TrimSuffix(buf.String(), "\n")
}

// FormatContext formats a context map for display.
func (r *REPLOutput) FormatContext(name string, ctx map[string]any) {
	if len(ctx) == 0 {
		fmt.Fprintf(r.w, "  %s\n", StyleREPLHint.Render("("+name+" is empty)"))
		return
	}
	for k, v := range ctx {
		r.KeyValue(name+"."+k, v)
	}
}

// Divider writes a subtle divider line.
func (r *REPLOutput) Divider() {
	fmt.Fprintln(r.w, StyleREPLInfo.Render(strings.Repeat("─", 40)))
}

// Table writes a simple table.
type TableRow struct {
	Label string
	Value string
}

func (r *REPLOutput) Table(rows []TableRow) {
	maxLabel := 0
	for _, row := range rows {
		if len(row.Label) > maxLabel {
			maxLabel = len(row.Label)
		}
	}
	for _, row := range rows {
		padding := strings.Repeat(" ", maxLabel-len(row.Label))
		fmt.Fprintf(r.w, "  %s%s  %s\n",
			StyleREPLKey.Render(row.Label),
			padding,
			StyleREPLValue.Render(row.Value),
		)
	}
}

// CompletionHint writes available completions inline.
func (r *REPLOutput) CompletionHint(completions []string, maxShow int) {
	if len(completions) == 0 {
		return
	}
	show := completions
	more := 0
	if len(completions) > maxShow {
		show = completions[:maxShow]
		more = len(completions) - maxShow
	}
	line := strings.Join(show, " ")
	if more > 0 {
		line += fmt.Sprintf(" (+%d more)", more)
	}
	fmt.Fprintf(r.w, "  %s\n", StyleREPLHint.Render(line))
}
