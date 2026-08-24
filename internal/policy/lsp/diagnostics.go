package lsp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	protocol "github.com/sourcegraph/go-lsp"
	"github.com/temporalio/deputy/internal/policy"
	"gopkg.in/yaml.v3"
)

// celParser is a reusable CEL parser configured with the standard macros,
// matching the behavior of the deprecated top-level parser.Parse. NewParser
// only errors on invalid options, so a failure here is a programming error.
var celParser = func() *parser.Parser {
	p, err := parser.NewParser(parser.Macros(parser.AllMacros...))
	if err != nil {
		panic(fmt.Sprintf("policy/lsp: build CEL parser: %v", err))
	}
	return p
}()

// diagnosticEngine produces LSP diagnostics for a document.
type diagnosticEngine struct{}

// newDiagnosticEngine creates a new instance of the diagnostic engine.
func newDiagnosticEngine() *diagnosticEngine { return &diagnosticEngine{} }

// analyze runs the shared policy bundle validation and renders its issues as LSP
// diagnostics, supplying the editor's richer CEL error formatting. The checks
// themselves live in the policy package so `deputy policy lint` and the editor
// agree on what a valid policy is.
func (d *diagnosticEngine) analyze(uri protocol.DocumentURI, text string) ([]protocol.Diagnostic, error) {
	issues, err := policy.ValidateBundle(text, policy.ValidateOptions{
		Source: string(uri),
		CheckWhen: func(when policy.RuleWhen) []policy.Issue {
			compileErr := policy.Compile(when.Expr, when.DeclaredVars)
			if compileErr == nil {
				return nil
			}
			knownNames := append(policy.DefaultVariableNames(), when.DeclaredVars...)
			return []policy.Issue{celErrorIssue(when, compileErr, knownNames)}
		},
	})
	if err != nil {
		return []protocol.Diagnostic{yamlErrorToDiagnostic(uri, err)}, nil
	}
	diag := make([]protocol.Diagnostic, 0, len(issues))
	for _, issue := range issues {
		diag = append(diag, issueToDiagnostic(uri, issue))
	}
	return diag, nil
}

// issueToDiagnostic renders a shared validation issue as an LSP diagnostic,
// preserving its position, width, and quick-fix code.
func issueToDiagnostic(uri protocol.DocumentURI, issue policy.Issue) protocol.Diagnostic {
	severity := protocol.Error
	switch issue.Severity {
	case policy.IssueWarning:
		severity = protocol.Warning
	case policy.IssueHint:
		severity = protocol.Hint
	}
	if issue.Length > 0 {
		return diagWithRangeAndCode(uri, issue.Line, issue.Column, issue.Length, issue.Message, severity, issue.Code)
	}
	d := makeDiagnostic(uri, issue.Line, issue.Column, issue.Message, severity)
	if issue.Code != "" {
		d.Code = issue.Code
	}
	return d
}

// yamlErrorToDiagnostic converts a YAML parsing error into an LSP diagnostic.
// It attempts to parse the line number from the error message.
func yamlErrorToDiagnostic(_ protocol.DocumentURI, err error) protocol.Diagnostic {
	msg := err.Error()
	line, col := 0, 0
	// gopkg.in/yaml.v3 formats as "line X: ...".
	if idx := strings.Index(msg, "line "); idx >= 0 {
		var parsedLine int
		if _, scanErr := fmt.Sscanf(msg[idx:], "line %d", &parsedLine); scanErr == nil {
			line = parsedLine - 1
		}
	}
	return protocol.Diagnostic{
		Range: protocol.Range{
			Start: protocol.Position{Line: line, Character: col},
			End:   protocol.Position{Line: line, Character: col + 1},
		},
		Severity: protocol.Error,
		Source:   "deputy-policy",
		Message:  msg,
	}
}

// makeDiagnostic creates a basic LSP diagnostic with the given severity and message.
// It handles 1-based to 0-based line/column conversion.
func makeDiagnostic(_ protocol.DocumentURI, line, col int, msg string, sev protocol.DiagnosticSeverity) protocol.Diagnostic {
	// yaml.Node.Line/Column are 1-based
	if line < 1 {
		line = 1
	}
	if col < 1 {
		col = 1
	}
	return protocol.Diagnostic{
		Range: protocol.Range{
			Start: protocol.Position{Line: line - 1, Character: col - 1},
			End:   protocol.Position{Line: line - 1, Character: col},
		},
		Severity: sev,
		Source:   "deputy-policy",
		Message:  msg,
	}
}

// diagWithRangeAndCode creates a diagnostic with a specific length and error code.
// It is useful for highlighting specific tokens or ranges.
func diagWithRangeAndCode(uri protocol.DocumentURI, line, col, length int, msg string, sev protocol.DiagnosticSeverity, code string) protocol.Diagnostic {
	d := makeDiagnostic(uri, line, col, msg, sev)
	d.Range.End.Character = d.Range.Start.Character + length
	d.Code = code
	return d
}

// celErrorIssue converts a CEL compilation error into a validation issue placed
// on the offending token. It maps the compiler's line and column back onto the
// YAML document, widens the range to the smallest covering AST node, and adds a
// name suggestion and source snippet the plain compiler message lacks.
func celErrorIssue(when policy.RuleWhen, err error, knownNames []string) policy.Issue {
	msg := err.Error()
	lineOffset, colOffset := 0, 0
	var parsedLine, parsedCol int
	if _, scanErr := fmt.Sscanf(msg, "ERROR: <input>:%d:%d", &parsedLine, &parsedCol); scanErr == nil {
		lineOffset = parsedLine - 1
		colOffset = parsedCol - 1
	}
	line := when.Line + lineOffset
	col := when.Column + colOffset
	length := 1
	// Try to map to AST offset to widen the range (ident, select chain, call target/args)
	if rngLen, adjustedCol := widenWithAST(when.Expr, when.Column, lineOffset, colOffset); rngLen > 0 {
		col = adjustedCol
		length = rngLen
	}
	// Fallback to undeclared name widen
	if length <= 1 {
		if name := extractUndeclaredName(msg); name != "" {
			if idx := strings.Index(when.Expr, name); idx >= 0 {
				col = when.Column + idx
				length = len(name)
			}
		}
	}
	// Final fallback: extend token until whitespace
	if length <= 1 {
		if offset := offsetFromLineCol(when.Expr, lineOffset, colOffset); offset >= 0 && offset < len(when.Expr) {
			end := offset
			for end < len(when.Expr) && !isSpaceOrPunct(rune(when.Expr[end])) {
				end++
			}
			length = end - offset
		}
	}
	display := celDetail(msg)
	if name := extractUndeclaredName(msg); name != "" {
		if suggestion, ok := suggestName(name, knownNames); ok {
			display = fmt.Sprintf("%s (did you mean '%s'?)", display, suggestion)
		}
	}
	if snippet := snippetFromCelError(when.Expr, parsedLine, parsedCol, extractUndeclaredName(msg)); snippet.code != "" {
		display = fmt.Sprintf("%s\n  %s\n  %s", display, snippet.code, snippet.caret)
	}
	code := "cel-error"
	if strings.Contains(msg, "undeclared reference to '") {
		code = "undeclared"
	}
	return policy.Issue{
		Policy:    when.Policy,
		RuleIndex: when.RuleIndex,
		Line:      line,
		Column:    col,
		Length:    length,
		Severity:  policy.IssueError,
		Code:      code,
		Message:   display,
	}
}

// widenWithAST attempts to find the smallest AST node (ident/select/call target/arg) containing the offset and returns its length and adjusted column.
func widenWithAST(expr string, yamlCol int, lineOffset, colOffset int) (length int, adjustedCol int) {
	src := common.NewTextSource(expr)
	parsed, parseErrs := celParser.Parse(src)
	if len(parseErrs.GetErrors()) > 0 {
		return 0, 0
	}
	info := parsed.SourceInfo()
	offset := offsetFromLineCol(expr, lineOffset, colOffset)
	if offset < 0 {
		return 0, 0
	}
	var best ast.OffsetRange
	found := false
	walkExpr(parsed.Expr(), func(e ast.Expr) {
		rng, ok := info.GetOffsetRange(e.ID())
		if !ok {
			return
		}
		if offset >= int(rng.Start) && offset <= int(rng.Stop) {
			// prefer smallest covering range
			if !found || (rng.Stop-rng.Start) < (best.Stop-best.Start) {
				best = rng
				found = true
			}
		}
	})
	// If no covering node found, try call target names by traversing calls
	if !found {
		walkExpr(parsed.Expr(), func(e ast.Expr) {
			if e.Kind() != ast.CallKind {
				return
			}
			call := e.AsCall()
			fn := call.FunctionName()
			if fn == "" {
				return
			}
			if rng, ok := info.GetOffsetRange(e.ID()); ok {
				start := int(rng.Start)
				stop := start + len(fn)
				if offset >= start && offset <= stop {
					best = ast.OffsetRange{Start: int32(start), Stop: int32(stop)}
					found = true
				}
			}
			// Also consider arguments for coverage if still not found
			for _, arg := range call.Args() {
				if rng, ok := info.GetOffsetRange(arg.ID()); ok {
					if offset >= int(rng.Start) && offset <= int(rng.Stop) {
						if !found || (rng.Stop-rng.Start) < (best.Stop-best.Start) {
							best = rng
							found = true
						}
					}
				}
			}
		})
	}
	if !found {
		return 0, 0
	}
	length = int(best.Stop - best.Start)
	if length <= 0 {
		length = 1
	}
	adjustedCol = yamlCol + int(best.Start)
	return length, adjustedCol
}

// offsetFromLineCol calculates the byte offset for a given line and column in the text.
// It returns -1 if the line offset is out of bounds.
func offsetFromLineCol(text string, lineOffset, colOffset int) int {
	lines := strings.Split(text, "\n")
	if lineOffset < 0 || lineOffset >= len(lines) {
		return -1
	}
	offset := 0
	for i := range lineOffset {
		offset += len(lines[i]) + 1 // include newline
	}
	return offset + colOffset
}

// isSpaceOrPunct checks if a rune is a whitespace or punctuation character.
// This is used to determine token boundaries.
func isSpaceOrPunct(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ')' || r == '(' || r == '+' || r == '-' || r == '*' || r == '/' || r == '='
}

// firstLine returns the first line of a string.
func firstLine(s string) string {
	if before, _, ok := strings.Cut(s, "\n"); ok {
		return before
	}
	return s
}

// stripCelContainer removes the trailing " (in container '...')" noise from cel-go errors.
func stripCelContainer(s string) string {
	const needle = " (in container"
	if before, _, ok := strings.Cut(s, needle); ok {
		return before
	}
	return s
}

// celDetail extracts a concise error detail from a cel-go error string.
func celDetail(s string) string {
	s = stripCelContainer(firstLine(s))
	s = celErrPrefixRe.ReplaceAllString(s, "")
	if idx := strings.Index(s, " | "); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

var celErrPrefixRe = regexp.MustCompile(`(?i)^(cel:\s*)?error:\s*<input>:\d+:\d+:\s*`)

// snippetInfo holds a code snippet and a caret pointing to the error location.
type snippetInfo struct {
	code  string
	caret string
}

// snippetFromCelError returns a one-line excerpt and caret for the CEL expression at the given offset.
func snippetFromCelError(expr string, line, col int, hint string) snippetInfo {
	lines := strings.Split(strings.ReplaceAll(expr, "\r\n", "\n"), "\n")
	if line < 1 || line > len(lines) {
		return snippetInfo{}
	}
	codeLine := lines[line-1]
	codeLine = strings.ReplaceAll(codeLine, "\t", " ")
	if len(codeLine) == 0 {
		return snippetInfo{}
	}
	target := max(col-1, 0)
	if hint != "" {
		if idx := strings.Index(codeLine, hint); idx >= 0 {
			target = idx
		}
	}
	if target >= len(codeLine) {
		target = len(codeLine) - 1
	}
	return snippetInfo{
		code:  codeLine,
		caret: strings.Repeat(" ", target) + "^",
	}
}

// findMapValue returns the value node for the given key inside a mapping node.
// The policy package owns the bundle's YAML shape, so this delegates rather than
// keeping a second copy of the lookup.
func findMapValue(mapNode *yaml.Node, key string) *yaml.Node {
	return policy.MappingValue(mapNode, key)
}
