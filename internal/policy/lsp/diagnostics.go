package lsp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
	"github.com/temporalio/deputy/internal/policy"
	protocol "github.com/sourcegraph/go-lsp"
	"gopkg.in/yaml.v3"
)

// diagnosticEngine produces LSP diagnostics for a document.
type diagnosticEngine struct{}

// newDiagnosticEngine creates a new instance of the diagnostic engine.
func newDiagnosticEngine() *diagnosticEngine { return &diagnosticEngine{} }

// analyze runs YAML parsing, structural checks, and CEL compilation.
func (d *diagnosticEngine) analyze(uri protocol.DocumentURI, text string) ([]protocol.Diagnostic, error) {
	root := &yaml.Node{}
	if err := yaml.Unmarshal([]byte(text), root); err != nil {
		return []protocol.Diagnostic{yamlErrorToDiagnostic(uri, err)}, nil
	}
	diag := make([]protocol.Diagnostic, 0)

	// Navigate to mapping under document.
	if len(root.Content) == 0 {
		return diag, nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		diag = append(diag, makeDiagnostic(uri, doc.Line, doc.Column, "root must be a mapping", protocol.Error))
		return diag, nil
	}
	policiesNode := findMapValue(doc, "policies")
	if policiesNode == nil {
		diag = append(diag, makeDiagnostic(uri, doc.Line, doc.Column, "missing required 'policies' list", protocol.Error))
		return diag, nil
	}
	if policiesNode.Kind != yaml.SequenceNode {
		diag = append(diag, makeDiagnostic(uri, policiesNode.Line, policiesNode.Column, "'policies' must be a list", protocol.Error))
		return diag, nil
	}
	seenNames := map[string]struct{}{}
	for _, item := range policiesNode.Content {
		if item.Kind != yaml.MappingNode {
			diag = append(diag, makeDiagnostic(uri, item.Line, item.Column, "policy must be a mapping", protocol.Error))
			continue
		}
		// name
		nameNode := findMapValue(item, "name")
		if nameNode != nil && nameNode.Kind == yaml.ScalarNode {
			name := strings.TrimSpace(nameNode.Value)
			if name != "" {
				if _, dup := seenNames[name]; dup {
					diag = append(diag, makeDiagnostic(uri, nameNode.Line, nameNode.Column, fmt.Sprintf("duplicate policy name %q", name), protocol.Error))
				}
				seenNames[name] = struct{}{}
			}
		}
		// entrypoints / commands enums
		checkListEnum := func(key string, validator func(string) bool) {
			node := findMapValue(item, key)
			if node == nil {
				return
			}
			if node.Kind != yaml.SequenceNode {
				diag = append(diag, makeDiagnostic(uri, node.Line, node.Column, fmt.Sprintf("'%s' must be a list", key), protocol.Error))
				return
			}
			for _, v := range node.Content {
				if v.Kind != yaml.ScalarNode {
					diag = append(diag, makeDiagnostic(uri, v.Line, v.Column, fmt.Sprintf("'%s' items must be strings", key), protocol.Error))
					continue
				}
				if !validator(v.Value) {
					diag = append(diag, makeDiagnostic(uri, v.Line, v.Column, fmt.Sprintf("invalid %s %q", key[:len(key)-1], v.Value), protocol.Warning))
				}
			}
		}
		checkListEnum("entrypoints", policy.IsAllowedEntrypoint)
		checkListEnum("commands", policy.IsAllowedCommand)

		declaredVars := collectDeclaredVars(item)
		knownNames := append(policy.DefaultVariableNames(), declaredVars...)

		// rules
		diag = append(diag, validateRulesNode(uri, item, declaredVars, knownNames)...)
	}

	// Compile the whole policy to ensure bundled vars/metadata are valid.
	if _, err := policy.ParseStructuredSources([]byte(text), string(uri)); err != nil {
		diag = append(diag, makeDiagnostic(uri, 0, 0, err.Error(), protocol.Warning))
	}
	return diag, nil
}

// validateRulesNode validates the rules list for a policy item and returns diagnostics.
// It checks for the presence of a rules list, validates each rule's structure,
// compiles CEL expressions, and checks for missing required fields.
func validateRulesNode(uri protocol.DocumentURI, item *yaml.Node, declaredVars, knownNames []string) []protocol.Diagnostic {
	var diag []protocol.Diagnostic
	rulesNode := findMapValue(item, "rules")
	if rulesNode == nil {
		return []protocol.Diagnostic{makeDiagnostic(uri, item.Line, item.Column, "policy missing 'rules'", protocol.Error)}
	}
	if rulesNode.Kind != yaml.SequenceNode {
		return []protocol.Diagnostic{makeDiagnostic(uri, rulesNode.Line, rulesNode.Column, "'rules' must be a list", protocol.Error)}
	}
	for _, rule := range rulesNode.Content {
		if rule.Kind != yaml.MappingNode {
			diag = append(diag, makeDiagnostic(uri, rule.Line, rule.Column, "rule must be a mapping", protocol.Error))
			continue
		}
		whenNode := findMapValue(rule, "when")
		if whenNode == nil || whenNode.Kind != yaml.ScalarNode {
			diag = append(diag, diagWithCode(uri, rule.Line, rule.Column, "rule missing 'when' expression", protocol.Error, "missing-when"))
			continue
		}
		// CEL compile of the when expression with location mapping.
		if err := policy.Compile(whenNode.Value, declaredVars); err != nil {
			diag = append(diag, celErrorDiagnostic(uri, whenNode, err, knownNames))
		}
		actionNode := findMapValue(rule, "action")
		if actionNode == nil || actionNode.Kind != yaml.ScalarNode {
			diag = append(diag, diagWithCode(uri, rule.Line, rule.Column, "rule missing 'action'", protocol.Error, "missing-action"))
		} else {
			if actionNode.Value == "deny" || actionNode.Value == "warn" {
				reasonNode := findMapValue(rule, "reason")
				if reasonNode == nil || strings.TrimSpace(reasonNode.Value) == "" {
					diag = append(diag, diagWithRangeAndCode(uri, actionNode.Line, actionNode.Column, len(actionNode.Value), "missing 'reason' for warn/deny", protocol.Hint, "missing-reason"))
				}
			}
		}
	}
	return diag
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

// diagWithCode creates a diagnostic with an associated error code.
// This code is used by the code action handler to provide quick fixes.
func diagWithCode(uri protocol.DocumentURI, line, col int, msg string, sev protocol.DiagnosticSeverity, code string) protocol.Diagnostic {
	d := makeDiagnostic(uri, line, col, msg, sev)
	d.Code = code
	return d
}

// diagWithRangeAndCode creates a diagnostic with a specific length and error code.
// It is useful for highlighting specific tokens or ranges.
func diagWithRangeAndCode(uri protocol.DocumentURI, line, col, length int, msg string, sev protocol.DiagnosticSeverity, code string) protocol.Diagnostic {
	d := makeDiagnostic(uri, line, col, msg, sev)
	d.Range.End.Character = d.Range.Start.Character + length
	d.Code = code
	return d
}

// celErrorDiagnostic converts a CEL compilation error into an LSP diagnostic.
// It attempts to map the error location to the specific AST node in the YAML.
func celErrorDiagnostic(uri protocol.DocumentURI, node *yaml.Node, err error, knownNames []string) protocol.Diagnostic {
	msg := err.Error()
	lineOffset, colOffset := 0, 0
	var parsedLine, parsedCol int
	if _, scanErr := fmt.Sscanf(msg, "ERROR: <input>:%d:%d", &parsedLine, &parsedCol); scanErr == nil {
		lineOffset = parsedLine - 1
		colOffset = parsedCol - 1
	}
	line := node.Line + lineOffset
	col := node.Column + colOffset
	length := 1
	// Try to map to AST offset to widen the range (ident, select chain, call target/args)
	if rngLen, adjustedCol := widenWithAST(node.Value, node.Column, lineOffset, colOffset); rngLen > 0 {
		col = adjustedCol
		length = rngLen
	}
	// Fallback to undeclared name widen
	if length <= 1 {
		if name := extractUndeclaredName(msg); name != "" {
			if idx := strings.Index(node.Value, name); idx >= 0 {
				col = node.Column + idx
				length = len(name)
			}
		}
	}
	// Final fallback: extend token until whitespace
	if length <= 1 {
		if offset := offsetFromLineCol(node.Value, lineOffset, colOffset); offset >= 0 && offset < len(node.Value) {
			end := offset
			for end < len(node.Value) && !isSpaceOrPunct(rune(node.Value[end])) {
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
	if snippet := snippetFromCelError(node.Value, parsedLine, parsedCol, extractUndeclaredName(msg)); snippet.code != "" {
		display = fmt.Sprintf("%s\n  %s\n  %s", display, snippet.code, snippet.caret)
	}
	d := diagWithRangeAndCode(uri, line, col, length, display, protocol.Error, "cel-error")
	if strings.Contains(msg, "undeclared reference to '") {
		d.Code = "undeclared"
	}
	return d
}

// widenWithAST attempts to find the smallest AST node (ident/select/call target/arg) containing the offset and returns its length and adjusted column.
func widenWithAST(expr string, yamlCol int, lineOffset, colOffset int) (length int, adjustedCol int) {
	src := common.NewTextSource(expr)
	parsed, parseErrs := parser.Parse(src)
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
	for i := 0; i < lineOffset; i++ {
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
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		return s[:idx]
	}
	return s
}

// stripCelContainer removes the trailing " (in container '...')" noise from cel-go errors.
func stripCelContainer(s string) string {
	const needle = " (in container"
	if idx := strings.Index(s, needle); idx >= 0 {
		return s[:idx]
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
	target := col - 1
	if target < 0 {
		target = 0
	}
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

// collectDeclaredVars returns the set of variable names declared under vars: for a policy mapping node.
func collectDeclaredVars(policyNode *yaml.Node) []string {
	var names []string
	varsNode := findMapValue(policyNode, "vars")
	if varsNode == nil || varsNode.Kind != yaml.MappingNode {
		return names
	}
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		k := varsNode.Content[i]
		if k.Kind == yaml.ScalarNode && strings.TrimSpace(k.Value) != "" {
			names = append(names, k.Value)
		}
	}
	return names
}

// findMapValue returns the value node for the given key inside a mapping node.
func findMapValue(mapNode *yaml.Node, key string) *yaml.Node {
	if mapNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return mapNode.Content[i+1]
		}
	}
	return nil
}
