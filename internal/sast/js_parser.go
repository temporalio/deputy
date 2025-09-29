package sast

import (
	"fmt"
	"regexp"
	"strings"
)

// jsParser parses JavaScript/TypeScript code and builds an IR graph
type jsParser struct {
	content    string
	unitPath   string
	files      []string
	graph      *Graph
	symbols    []Symbol
	scopeStack []string
	position   int
	line       int
	column     int
}

// jsCall represents a JavaScript function/method call
type jsCall struct {
	name     string
	receiver string
	args     []string
	line     int
	column   int
}

// jsFunction represents a JavaScript function
type jsFunction struct {
	name       string
	receiver   string
	parameters []string
	isExported bool
	isAsync    bool
	line       int
	column     int
}

func (p *jsParser) parse() error {
	content := p.content
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		p.line = lineNum + 1
		p.column = 1

		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Parse function declarations
		p.parseFunctionDeclarations(line)

		// Parse class declarations
		p.parseClassDeclarations(line)

		// Parse function calls
		p.parseFunctionCalls(line)

		// Parse variable assignments
		p.parseVariableAssignments(line)

		// Parse import/export statements
		p.parseImportExport(line)
	}

	return nil
}

func (p *jsParser) parseFunctionDeclarations(line string) {
	// Regular expressions for different function declaration patterns
	patterns := []*regexp.Regexp{
		// function name() {} or async function name() {}
		regexp.MustCompile(`(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)`),
		// const/let/var name = function() {} or const/let/var name = async function() {}
		regexp.MustCompile(`(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)`),
		// const/let/var name = () => {} or const/let/var name = async () => {}
		regexp.MustCompile(`(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>`),
		// name: function() {} or name: async function() {}
		regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*(?:async\s+)?function\s*\(([^)]*)\)`),
		// name() {} (method shorthand)
		regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*\{`),
		// class methods: methodName() {} or async methodName() {}
		regexp.MustCompile(`(?:async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*\{`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) >= 3 {
			functionName := matches[1]
			parameters := strings.TrimSpace(matches[2])

			isAsync := strings.Contains(line, "async")
			isExported := strings.Contains(line, "export") || strings.Contains(line, "module.exports")

			var paramList []string
			if parameters != "" {
				paramList = strings.Split(parameters, ",")
				for i, param := range paramList {
					paramList[i] = strings.TrimSpace(param)
				}
			}

			function := &jsFunction{
				name:       functionName,
				parameters: paramList,
				isExported: isExported,
				isAsync:    isAsync,
				line:       p.line,
				column:     p.column,
			}

			p.addFunction(function)
			break
		}
	}
}

func (p *jsParser) parseClassDeclarations(line string) {
	// Pattern for class declarations: class ClassName { ... }
	classPattern := regexp.MustCompile(`class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:extends\s+[a-zA-Z_$][a-zA-Z0-9_$]*)?\s*\{`)

	matches := classPattern.FindStringSubmatch(line)
	if len(matches) >= 2 {
		className := matches[1]

		isExported := strings.Contains(line, "export")

		class := &jsFunction{
			name:       className,
			parameters: []string{},
			isExported: isExported,
			isAsync:    false,
			line:       p.line,
			column:     p.column,
		}

		p.addFunction(class)
	}
}

func (p *jsParser) parseFunctionCalls(line string) {
	// Pattern for function calls: functionName(args) or object.method(args)
	callPattern := regexp.MustCompile(`([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*)\s*\(([^)]*)\)`)

	matches := callPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			fullCall := match[1]
			args := strings.TrimSpace(match[2])

			var receiver, name string
			if strings.Contains(fullCall, ".") {
				parts := strings.Split(fullCall, ".")
				receiver = strings.Join(parts[:len(parts)-1], ".")
				name = parts[len(parts)-1]
			} else {
				name = fullCall
			}

			var argList []string
			if args != "" {
				argList = strings.Split(args, ",")
				for i, arg := range argList {
					argList[i] = strings.TrimSpace(arg)
				}
			}

			call := &jsCall{
				name:     name,
				receiver: receiver,
				args:     argList,
				line:     p.line,
				column:   p.column,
			}

			p.addCall(call)
		}
	}
}

func (p *jsParser) parseVariableAssignments(line string) {
	// Pattern for variable assignments: var/let/const name = value
	assignPattern := regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(.+)`)

	matches := assignPattern.FindStringSubmatch(line)
	if len(matches) >= 3 {
		varName := matches[1]
		value := strings.TrimSpace(matches[2])

		// Check if it's a taint source (e.g., user input)
		p.checkTaintSource(varName, value)
	}
}

func (p *jsParser) parseImportExport(line string) {
	// Pattern for ES6 exports: export function/const/etc.
	if strings.Contains(line, "export") {
		exportPattern := regexp.MustCompile(`export\s+(?:default\s+)?(?:function|const|let|var|class)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)`)
		matches := exportPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			exportName := matches[1]
			p.markAsExported(exportName)
		}
	}

	// Pattern for CommonJS exports: module.exports = { name1, name2, ... }
	if strings.Contains(line, "module.exports") {
		// Handle module.exports = { ... } pattern
		objectExportPattern := regexp.MustCompile(`module\.exports\s*=\s*\{\s*([^}]+)\s*\}`)
		matches := objectExportPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			exports := matches[1]
			// Split by comma and extract each exported name
			exportedNames := strings.Split(exports, ",")
			for _, name := range exportedNames {
				name = strings.TrimSpace(name)
				// Handle both 'name' and 'name: value' patterns
				if colonIndex := strings.Index(name, ":"); colonIndex > 0 {
					name = strings.TrimSpace(name[:colonIndex])
				}
				if name != "" {
					p.markAsExported(name)
				}
			}
		}

		// Handle module.exports.name = ... pattern
		propertyExportPattern := regexp.MustCompile(`module\.exports\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=`)
		matches = propertyExportPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			exportName := matches[1]
			p.markAsExported(exportName)
		}
	}
}

func (p *jsParser) addFunction(function *jsFunction) {
	symbolID := SymbolID{
		Dialect: "javascript",
		Package: p.unitPath,
		Name:    function.name,
		Recv:    function.receiver,
	}

	attributes := map[string]any{
		"kind":       "function",
		"line":       function.line,
		"column":     function.column,
		"async":      function.isAsync,
		"parameters": function.parameters,
	}

	if function.isExported {
		attributes["exported"] = true
		attributes["entry_point"] = true
	}

	symbol := Symbol{
		ID:         symbolID,
		Display:    function.name,
		Kind:       SymbolKindFunction,
		Attributes: attributes,
	}

	p.symbols = append(p.symbols, symbol)
	p.graph.AddSymbol(symbol)
}

func (p *jsParser) addCall(call *jsCall) {
	// Create a symbol for this call site
	callSiteID := SymbolID{
		Dialect: "javascript",
		Package: p.unitPath,
		Name:    fmt.Sprintf("%s_call_%d_%d", call.name, call.line, call.column),
	}

	callSymbol := Symbol{
		ID:      callSiteID,
		Display: fmt.Sprintf("%s()", call.name),
		Kind:    SymbolKindCallsite,
		Attributes: map[string]any{
			"kind":     "call",
			"line":     call.line,
			"column":   call.column,
			"receiver": call.receiver,
			"args":     call.args,
		},
	}

	p.symbols = append(p.symbols, callSymbol)
	p.graph.AddSymbol(callSymbol)

	// Create target symbol for the called function
	targetID := SymbolID{
		Dialect: "javascript",
		Package: p.unitPath,
		Name:    call.name,
		Recv:    call.receiver,
	}

	targetSymbol := Symbol{
		ID:      targetID,
		Display: call.name,
		Kind:    SymbolKindFunction,
		Attributes: map[string]any{
			"kind":        "function",
			"placeholder": true,
		},
	}

	p.graph.AddSymbol(targetSymbol)

	// Add edge from call site to target
	p.graph.AddEdgeWithAttributes(EdgeKindCall, callSiteID, targetID, EdgeAttributes{
		Confidence: EdgeConfidenceCertain,
		Metadata: map[string]any{
			"call_name": call.name,
			"receiver":  call.receiver,
			"args":      call.args,
			"arg_count": len(call.args),
		},
	})
}

func (p *jsParser) checkTaintSource(varName, value string) {
	// Check for common taint sources in JavaScript/Node.js
	taintSources := []string{
		"req.body", "req.query", "req.params", "req.headers", "req.cookies",
		"process.argv", "process.env", "window.location", "document.cookie",
		"localStorage", "sessionStorage", "URLSearchParams",
	}

	for _, source := range taintSources {
		if strings.Contains(value, source) {
			p.markAsTaintSource(varName, source)
			break
		}
	}
}

func (p *jsParser) markAsTaintSource(varName, source string) {
	symbolID := SymbolID{
		Dialect: "javascript",
		Package: p.unitPath,
		Name:    varName,
	}

	symbol := Symbol{
		ID:      symbolID,
		Display: varName,
		Kind:    SymbolKindField,
		Attributes: map[string]any{
			"kind":         "variable",
			"taint_source": true,
			"source_type":  source,
		},
	}

	p.symbols = append(p.symbols, symbol)
	p.graph.AddSymbol(symbol)
}

func (p *jsParser) markAsExported(name string) {
	// Find existing symbol and mark as exported
	for i, symbol := range p.symbols {
		if symbol.ID.Name == name {
			if symbol.Attributes == nil {
				symbol.Attributes = make(map[string]any)
			}
			symbol.Attributes["exported"] = true
			symbol.Attributes["entry_point"] = true
			p.symbols[i] = symbol
			p.graph.AddSymbol(symbol)
			break
		}
	}
}
