package repl

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
)

// Config configures REPL behavior.
type Config struct {
	// Theme controls visual appearance
	Theme *Theme

	// ShowHints enables inline hints
	ShowHints bool

	// ShowCompletions enables tab completion
	ShowCompletions bool

	// MaxCompletions limits completion list size
	MaxCompletions int

	// HighlightSyntax enables CEL syntax highlighting
	HighlightSyntax bool

	// ChromaStyle sets the chroma syntax highlighting style
	ChromaStyle string

	// ShowTypes shows type annotations on results
	ShowTypes bool

	// Entrypoint sets the default entrypoint context
	Entrypoint string

	// HistorySize limits command history
	HistorySize int
}

// DefaultConfig returns the default REPL configuration.
func DefaultConfig() *Config {
	return &Config{
		Theme:           DefaultTheme(),
		ShowHints:       true,
		ShowCompletions: true,
		MaxCompletions:  10,
		HighlightSyntax: true,
		ChromaStyle:     "monokai",
		ShowTypes:       true,
		Entrypoint:      "proxy",
		HistorySize:     1000,
	}
}

// Engine is the main REPL engine.
type Engine struct {
	config     *Config
	schema     *SchemaRegistry
	completion *CompletionEngine
	in         io.Reader
	out        io.Writer
	history    []string
	historyIdx int
}

// NewEngine creates a new REPL engine.
func NewEngine(in io.Reader, out io.Writer, config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}
	schema := NewSchemaRegistry()
	return &Engine{
		config:     config,
		schema:     schema,
		completion: NewCompletionEngine(schema),
		in:         in,
		out:        out,
		history:    make([]string, 0, config.HistorySize),
	}
}

// Output provides access to styled output methods.
type Output struct {
	engine *Engine
}

// Output returns the styled output helper.
func (e *Engine) Output() *Output {
	return &Output{engine: e}
}

// Print writes styled text to the output.
func (o *Output) Print(text string) {
	fmt.Fprint(o.engine.out, text)
}

// Println writes styled text with a newline.
func (o *Output) Println(text string) {
	fmt.Fprintln(o.engine.out, text)
}

// Prompt writes the REPL prompt.
func (o *Output) Prompt(ctx string) {
	t := o.engine.config.Theme
	if ctx != "" {
		fmt.Fprint(o.engine.out, t.Context.Render(ctx)+" ")
	}
	fmt.Fprint(o.engine.out, t.Prompt.Render("cel")+" ")
	fmt.Fprint(o.engine.out, t.Prompt.Render(t.PromptSymbol)+" ")
}

// Result writes a successful result.
func (o *Output) Result(value any, typeName string) {
	t := o.engine.config.Theme
	style := t.Result
	if v, ok := value.(bool); ok && !v {
		style = t.ResultFalse
	}

	fmt.Fprint(o.engine.out, t.Label.Render(t.ResultSymbol)+" ")
	fmt.Fprint(o.engine.out, style.Render(fmt.Sprintf("%v", value)))
	if o.engine.config.ShowTypes && typeName != "" {
		fmt.Fprint(o.engine.out, " "+t.CompletionType.Render("("+typeName+")"))
	}
	fmt.Fprintln(o.engine.out)
}

// Error writes an error message.
func (o *Output) Error(msg string) {
	t := o.engine.config.Theme
	fmt.Fprintln(o.engine.out, t.Error.Render(t.ErrorSymbol+" "+msg))
}

// ErrorWithHint writes an error with a suggestion.
func (o *Output) ErrorWithHint(msg, hint string) {
	o.Error(msg)
	if hint != "" {
		t := o.engine.config.Theme
		fmt.Fprintln(o.engine.out, "  "+t.Hint.Render("hint: "+hint))
	}
}

// Info writes informational text.
func (o *Output) Info(msg string) {
	t := o.engine.config.Theme
	fmt.Fprintln(o.engine.out, t.Info.Render(msg))
}

// Section writes a section header.
func (o *Output) Section(title string) {
	fmt.Fprintln(o.engine.out)
	t := o.engine.config.Theme
	fmt.Fprintln(o.engine.out, t.Label.Render(title))
}

// KeyValue writes a key-value pair.
func (o *Output) KeyValue(key string, value any) {
	t := o.engine.config.Theme
	fmt.Fprintf(o.engine.out, "  %s %s %s\n",
		t.Key.Render(key),
		t.Info.Render("="),
		t.Value.Render(fmt.Sprintf("%v", value)),
	)
}

// CommandHelp writes a command help entry with syntax highlighting.
// The cmd string is parsed to highlight:
//   - Commands starting with : are styled as commands
//   - UPPERCASE words are styled as placeholders (metavariables)
//   - = and other punctuation are styled subtly
//   - Quoted strings are styled as literals
func (o *Output) CommandHelp(cmd, desc string) {
	t := o.engine.config.Theme
	styled := o.styleCommandSyntax(cmd)
	fmt.Fprintf(o.engine.out, "  %s  %s\n", styled, t.Info.Render(desc))
}

// styleCommandSyntax applies semantic styling to command syntax.
func (o *Output) styleCommandSyntax(cmd string) string {
	t := o.engine.config.Theme
	var result strings.Builder

	i := 0
	for i < len(cmd) {
		switch {
		// Command starting with :
		case cmd[i] == ':':
			// Find end of command word
			j := i + 1
			for j < len(cmd) && (cmd[j] >= 'a' && cmd[j] <= 'z' || cmd[j] >= 'A' && cmd[j] <= 'Z' || cmd[j] == '-' || cmd[j] == '_') {
				j++
			}
			result.WriteString(t.Command.Render(cmd[i:j]))
			i = j

		// UPPERCASE placeholder (like KEY, VALUE, NAME)
		case cmd[i] >= 'A' && cmd[i] <= 'Z':
			j := i
			for j < len(cmd) && ((cmd[j] >= 'A' && cmd[j] <= 'Z') || cmd[j] == '_') {
				j++
			}
			result.WriteString(t.Placeholder.Render(cmd[i:j]))
			i = j

		// Punctuation: =, /, |
		case cmd[i] == '=' || cmd[i] == '/' || cmd[i] == '|':
			result.WriteString(t.Punctuation.Render(string(cmd[i])))
			i++

		// Quoted string literal
		case cmd[i] == '"':
			j := i + 1
			for j < len(cmd) && cmd[j] != '"' {
				j++
			}
			if j < len(cmd) {
				j++ // include closing quote
			}
			result.WriteString(t.Literal.Render(cmd[i:j]))
			i = j

		// Optional brackets [...]
		case cmd[i] == '[':
			j := i + 1
			for j < len(cmd) && cmd[j] != ']' {
				j++
			}
			if j < len(cmd) {
				j++ // include closing bracket
			}
			result.WriteString(t.Optional.Render(cmd[i:j]))
			i = j

		// Space
		case cmd[i] == ' ':
			result.WriteByte(' ')
			i++

		// lowercase words (like "key" as placeholder hint)
		case cmd[i] >= 'a' && cmd[i] <= 'z':
			j := i
			for j < len(cmd) && ((cmd[j] >= 'a' && cmd[j] <= 'z') || cmd[j] == '-' || cmd[j] == '_') {
				j++
			}
			word := cmd[i:j]
			// Treat lowercase words after = as placeholder values
			if i > 0 && cmd[i-1] == '=' {
				result.WriteString(t.Placeholder.Render(word))
			} else {
				result.WriteString(t.Placeholder.Render(word))
			}
			i = j

		default:
			result.WriteByte(cmd[i])
			i++
		}
	}

	return result.String()
}

// StyledText applies inline styling to text, highlighting :commands.
// Use this for prose text that mentions commands.
func (o *Output) StyledText(text string) string {
	t := o.engine.config.Theme
	var result strings.Builder

	i := 0
	for i < len(text) {
		// Look for :command patterns
		if text[i] == ':' && i+1 < len(text) && (text[i+1] >= 'a' && text[i+1] <= 'z') {
			j := i + 1
			for j < len(text) && ((text[j] >= 'a' && text[j] <= 'z') || text[j] == '-' || text[j] == '_') {
				j++
			}
			result.WriteString(t.Command.Render(text[i:j]))
			i = j
		} else {
			result.WriteByte(text[i])
			i++
		}
	}

	return result.String()
}

// Hint writes styled hint text with inline command highlighting.
func (o *Output) Hint(text string) {
	t := o.engine.config.Theme
	styled := o.StyledText(text)
	fmt.Fprintln(o.engine.out, t.Info.Render(styled))
}

// Completions writes a completion list.
func (o *Output) Completions(completions []Completion, selected int) {
	t := o.engine.config.Theme
	max := o.engine.config.MaxCompletions
	if len(completions) > max {
		completions = completions[:max]
	}

	for i, c := range completions {
		style := t.CompletionNormal
		if i == selected {
			style = t.CompletionSelected
		}

		symbol := t.CompletionKind.Render(c.Kind.Symbol())
		name := style.Render(c.Text)
		desc := t.CompletionDesc.Render(c.Description)

		fmt.Fprintf(o.engine.out, "  %s %s  %s\n", symbol, name, desc)
	}

	if len(o.engine.completion.Complete("", 0)) > max {
		fmt.Fprintf(o.engine.out, "  %s\n",
			t.Info.Render(fmt.Sprintf("(+%d more)", len(completions)-max)))
	}
}

// Blank writes a blank line.
func (o *Output) Blank() {
	fmt.Fprintln(o.engine.out)
}

// Divider writes a divider line.
func (o *Output) Divider() {
	t := o.engine.config.Theme
	fmt.Fprintln(o.engine.out, t.Divider.Render(strings.Repeat("─", 40)))
}

// Welcome writes the welcome message.
func (o *Output) Welcome(title, subtitle string) {
	t := o.engine.config.Theme
	fmt.Fprintln(o.engine.out, t.Prompt.Render(title))
	if subtitle != "" {
		fmt.Fprintln(o.engine.out, t.Info.Render(subtitle))
	}
	fmt.Fprintln(o.engine.out)
}

// Goodbye writes the exit message.
func (o *Output) Goodbye() {
	t := o.engine.config.Theme
	fmt.Fprintln(o.engine.out, t.Info.Render("Goodbye!"))
}

// HighlightCEL applies syntax highlighting to a CEL expression.
func (e *Engine) HighlightCEL(expr string) string {
	if !e.config.HighlightSyntax {
		return expr
	}

	lexer := lexers.Get("go") // CEL is similar to Go
	if lexer == nil {
		return expr
	}
	lexer = chroma.Coalesce(lexer)

	style := styles.Get(e.config.ChromaStyle)
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

// Complete returns completions for input at cursor position.
func (e *Engine) Complete(input string, cursor int) []Completion {
	return e.completion.Complete(input, cursor)
}

// GetHint returns a contextual hint for the current input.
func (e *Engine) GetHint(input string, cursor int) *Hint {
	if !e.config.ShowHints {
		return nil
	}
	return e.completion.GetHint(input, cursor)
}

// DescribeVariable returns documentation for a variable.
func (e *Engine) DescribeVariable(path string) string {
	return e.completion.DescribeVariable(path)
}

// DescribeFunction returns documentation for a function.
func (e *Engine) DescribeFunction(name string) string {
	return e.completion.DescribeFunction(name)
}

// AddToHistory adds a line to command history.
func (e *Engine) AddToHistory(line string) {
	if line == "" {
		return
	}
	// Avoid duplicates at end
	if len(e.history) > 0 && e.history[len(e.history)-1] == line {
		return
	}
	e.history = append(e.history, line)
	if len(e.history) > e.config.HistorySize {
		e.history = e.history[1:]
	}
	e.historyIdx = len(e.history)
}

// HistoryPrev returns the previous history entry.
func (e *Engine) HistoryPrev() string {
	if e.historyIdx > 0 {
		e.historyIdx--
		return e.history[e.historyIdx]
	}
	return ""
}

// HistoryNext returns the next history entry.
func (e *Engine) HistoryNext() string {
	if e.historyIdx < len(e.history)-1 {
		e.historyIdx++
		return e.history[e.historyIdx]
	}
	e.historyIdx = len(e.history)
	return ""
}

// ReadLineFunc is the type for the line reading callback.
type ReadLineFunc func(ctx context.Context) (string, error)

// SimpleReadLine creates a simple line reader using bufio (no terminal features).
func (e *Engine) SimpleReadLine() ReadLineFunc {
	scanner := bufio.NewScanner(e.in)
	return func(ctx context.Context) (string, error) {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			return "", io.EOF
		}
		return scanner.Text(), nil
	}
}

// InteractiveReadLine creates a readline instance with full terminal support.
func (e *Engine) InteractiveReadLine() *ReadLine {
	rl := NewReadLine(e.in, e.out)
	rl.SetHistory(e.history)
	return rl
}

// Schema returns the schema registry.
func (e *Engine) Schema() *SchemaRegistry {
	return e.schema
}

// Completion returns the completion engine.
func (e *Engine) Completion() *CompletionEngine {
	return e.completion
}

// Config returns the current configuration.
func (e *Engine) Config() *Config {
	return e.config
}

// SetTheme changes the active theme.
func (e *Engine) SetTheme(name string) {
	e.config.Theme = ThemeByName(name)
}
