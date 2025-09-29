package sast

import (
	"fmt"
	"regexp"
	"strings"
)

// pythonParser handles parsing of Python source code and converts it to IR representation
type pythonParser struct {
	content    string
	unitPath   string
	files      []string
	graph      *Graph
	symbols    []Symbol
	scopeStack []string
}

// Python-specific patterns for parsing
var (
	// Function definitions: def function_name(args):
	pythonFunctionDefRegex = regexp.MustCompile(`(?m)^(\s*)def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*:`)

	// Class definitions: class ClassName:
	pythonClassDefRegex = regexp.MustCompile(`(?m)^(\s*)class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*:`)

	// Method calls: obj.method(args) or function(args)
	pythonCallRegex = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\([^)]*\)`)

	// Import statements: import module, from module import name
	pythonImportRegex = regexp.MustCompile(`(?m)^(?:from\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s+)?import\s+([a-zA-Z_][a-zA-Z0-9_,\s*]+)`)

	// Variable assignments: var = value
	pythonAssignmentRegex = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)`)

	// String literals (for detecting potential taint sources)
	pythonStringLiteralRegex = regexp.MustCompile(`(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"[^"\\]*(?:\\.[^"\\]*)*"|'[^'\\]*(?:\\.[^'\\]*)*')`)
)

// parse analyzes the Python content and builds the IR graph
func (p *pythonParser) parse() error {
	lines := strings.Split(p.content, "\n")

	// First pass: identify all functions and classes
	for lineNum, line := range lines {
		p.parseFunctionDefinitions(line, lineNum)
		p.parseClassDefinitions(line, lineNum)
		p.parseImportStatements(line, lineNum)
	}

	// Second pass: identify method calls and assignments
	for lineNum, line := range lines {
		p.parseMethodCalls(line, lineNum)
		p.parseAssignments(line, lineNum)
	}

	// Identify entry points
	p.identifyEntryPoints()

	return nil
}

// parseFunctionDefinitions extracts function definitions from Python code
func (p *pythonParser) parseFunctionDefinitions(line string, lineNum int) {
	matches := pythonFunctionDefRegex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			indent := match[1]
			funcName := match[2]

			// Determine scope based on indentation
			scope := p.getScopeFromIndentation(indent)

			// Create symbol for the function
			symbolID := SymbolID{
				Dialect: "python",
				Package: p.unitPath,
				Name:    funcName,
				Recv:    scope,
			}

			symbol := Symbol{
				ID:   symbolID,
				Kind: SymbolKindFunction,
				Attributes: map[string]any{
					"line":        lineNum + 1,
					"file":        p.getCurrentFile(lineNum),
					"scope":       scope,
					"language":    "python",
					"entry_point": funcName == "__main__" || funcName == "main" || scope == "",
				},
			}

			p.symbols = append(p.symbols, symbol)
			p.graph.AddSymbol(symbol)
		}
	}
}

// parseClassDefinitions extracts class definitions from Python code
func (p *pythonParser) parseClassDefinitions(line string, lineNum int) {
	matches := pythonClassDefRegex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			indent := match[1]
			className := match[2]

			// Determine scope based on indentation
			scope := p.getScopeFromIndentation(indent)

			// Create symbol for the class
			symbolID := SymbolID{
				Dialect: "python",
				Package: p.unitPath,
				Name:    className,
				Recv:    scope,
			}

			symbol := Symbol{
				ID:   symbolID,
				Kind: SymbolKindType,
				Attributes: map[string]any{
					"line":        lineNum + 1,
					"file":        p.getCurrentFile(lineNum),
					"scope":       scope,
					"language":    "python",
					"entry_point": false,
				},
			}

			p.symbols = append(p.symbols, symbol)
			p.graph.AddSymbol(symbol)
		}
	}
}

// parseImportStatements extracts import statements
func (p *pythonParser) parseImportStatements(line string, lineNum int) {
	matches := pythonImportRegex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			moduleName := match[1]
			importedNames := match[2]

			// Create symbols for imported modules/names
			names := strings.Split(importedNames, ",")
			for _, name := range names {
				name = strings.TrimSpace(name)
				if name != "" {
					symbolID := SymbolID{
						Dialect: "python",
						Package: moduleName,
						Name:    name,
					}

					symbol := Symbol{
						ID:   symbolID,
						Kind: SymbolKindPackage,
						Attributes: map[string]any{
							"line":        lineNum + 1,
							"file":        p.getCurrentFile(lineNum),
							"module":      moduleName,
							"language":    "python",
							"entry_point": false,
						},
					}

					p.symbols = append(p.symbols, symbol)
					p.graph.AddSymbol(symbol)
				}
			}
		}
	}
}

// parseMethodCalls extracts method and function calls
func (p *pythonParser) parseMethodCalls(line string, lineNum int) {
	// Remove string literals to avoid false positives
	cleanLine := pythonStringLiteralRegex.ReplaceAllString(line, `""`)

	matches := pythonCallRegex.FindAllStringSubmatch(cleanLine, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			fullCall := match[1]

			// Parse receiver and method name
			parts := strings.Split(fullCall, ".")
			var receiver, methodName string

			if len(parts) > 1 {
				receiver = strings.Join(parts[:len(parts)-1], ".")
				methodName = parts[len(parts)-1]
			} else {
				methodName = parts[0]
			}

			// Create edge for the call
			p.addCall(receiver, methodName, lineNum)
		}
	}
}

// parseAssignments extracts variable assignments
func (p *pythonParser) parseAssignments(line string, lineNum int) {
	// Remove string literals and comments to avoid false positives
	cleanLine := pythonStringLiteralRegex.ReplaceAllString(line, `""`)
	if idx := strings.Index(cleanLine, "#"); idx != -1 {
		cleanLine = cleanLine[:idx]
	}

	matches := pythonAssignmentRegex.FindAllStringSubmatch(cleanLine, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			varName := match[1]
			value := strings.TrimSpace(match[2])

			// Check if this is a potential taint source
			isTaintSource := p.isTaintSource(value)

			// Create symbol for the variable
			symbolID := SymbolID{
				Dialect: "python",
				Package: p.unitPath,
				Name:    varName,
			}

			symbol := Symbol{
				ID:   symbolID,
				Kind: SymbolKindField,
				Attributes: map[string]any{
					"line":         lineNum + 1,
					"file":         p.getCurrentFile(lineNum),
					"value":        value,
					"taint_source": isTaintSource,
					"language":     "python",
					"entry_point":  false,
				},
			}

			p.symbols = append(p.symbols, symbol)
			p.graph.AddSymbol(symbol)
		}
	}
}

// addCall creates a call edge in the graph
func (p *pythonParser) addCall(receiver, methodName string, lineNum int) {
	// Create a unique call site symbol ID
	callSiteID := SymbolID{
		Dialect: "python",
		Package: p.unitPath,
		Name:    fmt.Sprintf("call_%d_%s", lineNum+1, methodName),
	}

	// Create target symbol ID
	targetID := SymbolID{
		Dialect: "python",
		Package: p.unitPath,
		Name:    methodName,
		Recv:    receiver,
	}

	// Create call site symbol
	callSiteSymbol := Symbol{
		ID:   callSiteID,
		Kind: SymbolKindCallsite,
		Attributes: map[string]any{
			"line":     lineNum + 1,
			"file":     p.getCurrentFile(lineNum),
			"receiver": receiver,
			"method":   methodName,
			"language": "python",
		},
	}

	p.symbols = append(p.symbols, callSiteSymbol)
	p.graph.AddSymbol(callSiteSymbol)

	// Create edge for the call
	p.graph.AddEdgeWithAttributes(EdgeKindCall, callSiteID, targetID, EdgeAttributes{
		Confidence: EdgeConfidenceCertain,
		Metadata: map[string]any{
			"line":     lineNum + 1,
			"file":     p.getCurrentFile(lineNum),
			"receiver": receiver,
			"method":   methodName,
			"language": "python",
		},
	})
}

// isTaintSource checks if a value represents a potential taint source
func (p *pythonParser) isTaintSource(value string) bool {
	taintSources := []string{
		"request.", "flask.request", "django.request",
		"input(", "raw_input(",
		"os.environ", "sys.argv",
		"bottle.request", "tornado.get_argument",
		"cherrypy.request", "web.input",
		"cgi.FieldStorage", "BaseHTTPServer",
	}

	value = strings.ToLower(value)
	for _, source := range taintSources {
		if strings.Contains(value, source) {
			return true
		}
	}

	return false
}

// getScopeFromIndentation determines scope based on indentation level
func (p *pythonParser) getScopeFromIndentation(indent string) string {
	level := len(indent)
	if level == 0 {
		return "" // Module level
	}

	// For simplicity, return a scope level indicator
	return fmt.Sprintf("scope_%d", level/4) // Assuming 4-space indentation
}

// getCurrentFile determines which file we're currently parsing based on line number
func (p *pythonParser) getCurrentFile(lineNum int) string {
	if len(p.files) == 1 {
		return p.files[0]
	}

	// For multi-file units, we'd need to track file boundaries
	// For now, return the first file
	if len(p.files) > 0 {
		return p.files[0]
	}

	return p.unitPath
}

// identifyEntryPoints marks functions and classes that serve as entry points
func (p *pythonParser) identifyEntryPoints() {
	for i, symbol := range p.symbols {
		if symbol.Kind == SymbolKindFunction {
			// Mark main functions and module-level functions as entry points
			if attrs := symbol.Attributes; attrs != nil {
				name := symbol.ID.Name
				scope := ""
				if s, ok := attrs["scope"].(string); ok {
					scope = s
				}

				// Entry points: main functions, __main__, module-level functions
				if name == "main" || name == "__main__" || scope == "" {
					attrs["entry_point"] = true
					p.symbols[i] = symbol
				}
			}
		}
	}
}
