package sast

import (
	"regexp"
)

// pythonSecurityAnalyzer performs security analysis on Python code
type pythonSecurityAnalyzer struct{}

// Python security sinks and patterns
var (
	// Command injection sinks - Python subprocess and os execution functions
	pythonCommandSinks = map[string]bool{
		"os.system":                true,
		"os.popen":                 true,
		"os.execl":                 true,
		"os.execle":                true,
		"os.execlp":                true,
		"os.execlpe":               true,
		"os.execv":                 true,
		"os.execve":                true,
		"os.execvp":                true,
		"os.execvpe":               true,
		"subprocess.call":          true,
		"subprocess.check_call":    true,
		"subprocess.check_output":  true,
		"subprocess.run":           true,
		"subprocess.Popen":         true,
		"commands.getoutput":       true,
		"commands.getstatusoutput": true,
	}

	// Code injection sinks - Dynamic code execution
	pythonCodeSinks = map[string]bool{
		"eval":       true,
		"exec":       true,
		"compile":    true,
		"__import__": true,
	}

	// SQL injection sinks - Database operations
	pythonSQLSinks = map[string]bool{
		"cursor.execute":       true,
		"cursor.executemany":   true,
		"cursor.executescript": true,
		"sqlite3.execute":      true,
		"pymongo.find":         true,
		"pymongo.find_one":     true,
		"pymongo.update":       true,
		"pymongo.delete":       true,
		"MySQLdb.execute":      true,
		"psycopg2.execute":     true,
		"sqlalchemy.execute":   true,
		"django.raw":           true,
		"django.extra":         true,
	}

	// XSS sinks - Web output and rendering
	pythonXSSSinks = map[string]bool{
		"HttpResponse":          true,
		"render":                true,
		"render_to_response":    true,
		"redirect":              true,
		"flask.render_template": true,
		"bottle.template":       true,
		"tornado.write":         true,
		"cherrypy.response":     true,
		"print":                 true, // Can be XSS in web contexts
	}

	// Path traversal sinks - File system operations
	pythonPathSinks = map[string]bool{
		"open":            true,
		"file":            true,
		"codecs.open":     true,
		"os.open":         true,
		"os.listdir":      true,
		"os.walk":         true,
		"os.path.join":    true,
		"shutil.copy":     true,
		"shutil.copy2":    true,
		"shutil.copyfile": true,
		"shutil.move":     true,
		"shutil.rmtree":   true,
		"pathlib.Path":    true,
	}

	// Deserialization sinks - Unsafe object reconstruction
	pythonDeserializationSinks = map[string]bool{
		"pickle.load":       true,
		"pickle.loads":      true,
		"cPickle.load":      true,
		"cPickle.loads":     true,
		"yaml.load":         true,
		"yaml.load_all":     true,
		"marshal.load":      true,
		"marshal.loads":     true,
		"jsonpickle.decode": true,
		"dill.load":         true,
		"dill.loads":        true,
	}

	// Taint sources - Input vectors
	pythonTaintSources = map[string]bool{
		"request.GET":        true,
		"request.POST":       true,
		"request.FILES":      true,
		"request.META":       true,
		"flask.request.args": true,
		"flask.request.form": true,
		"flask.request.json": true,
		"bottle.request":     true,
		"input":              true,
		"raw_input":          true,
		"sys.argv":           true,
		"os.environ":         true,
		"cgi.FieldStorage":   true,
	}

	// Sanitizers - Security functions
	pythonSanitizers = map[string]bool{
		"html.escape":              true,
		"cgi.escape":               true,
		"urllib.quote":             true,
		"urllib.quote_plus":        true,
		"urllib.parse.quote":       true,
		"urllib.parse.quote_plus":  true,
		"django.utils.html.escape": true,
		"markupsafe.escape":        true,
		"bleach.clean":             true,
		"re.escape":                true,
	}
)

// analyze performs comprehensive security analysis on the graph
func (a *pythonSecurityAnalyzer) analyze(graph *Graph, symbols []Symbol) {
	// Create a snapshot for analysis
	snapshot := graph.Snapshot()

	// Analyze each symbol for security vulnerabilities
	for _, symbol := range symbols {
		// Check for calls that represent security sinks
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			a.analyzeCall(graph, edge, symbols)
		}
	}
}

// analyzeCall examines a specific call edge for security vulnerabilities
func (a *pythonSecurityAnalyzer) analyzeCall(graph *Graph, edge Edge, symbols []Symbol) {
	// Extract method name and receiver
	methodName := ""
	receiver := ""

	if edge.Attributes.Metadata != nil {
		if name, ok := edge.Attributes.Metadata["method"].(string); ok {
			methodName = name
		}
		if recv, ok := edge.Attributes.Metadata["receiver"].(string); ok {
			receiver = recv
		}
	}

	// Create full method call name
	fullCall := methodName
	if receiver != "" {
		fullCall = receiver + "." + methodName
	}

	// Check each vulnerability type
	a.checkCommandInjection(graph, edge, fullCall, symbols)
	a.checkCodeInjection(graph, edge, fullCall, symbols)
	a.checkSQLInjection(graph, edge, fullCall, symbols)
	a.checkXSS(graph, edge, fullCall, symbols)
	a.checkPathTraversal(graph, edge, fullCall, symbols)
	a.checkUnsafeDeserialization(graph, edge, fullCall, symbols)
	a.checkTaintSources(graph, edge, fullCall, symbols)
	a.checkSanitizers(graph, edge, fullCall, symbols)
}

// checkCommandInjection identifies command injection vulnerabilities
func (a *pythonSecurityAnalyzer) checkCommandInjection(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonCommandSinks[fullCall] || a.matchesPattern(fullCall, []string{"subprocess\\.", "os\\.exec", "os\\.system", "os\\.popen"}) {
		a.addSecurityMetadata(graph, edge, "command_injection", "CWE-78", "High",
			"Potential command injection vulnerability in "+fullCall)
	}
}

// checkCodeInjection identifies code injection vulnerabilities
func (a *pythonSecurityAnalyzer) checkCodeInjection(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonCodeSinks[fullCall] || a.matchesPattern(fullCall, []string{"eval", "exec", "compile", "__import__"}) {
		a.addSecurityMetadata(graph, edge, "code_injection", "CWE-94", "Critical",
			"Potential code injection vulnerability in "+fullCall)
	}
}

// checkSQLInjection identifies SQL injection vulnerabilities
func (a *pythonSecurityAnalyzer) checkSQLInjection(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonSQLSinks[fullCall] || a.matchesPattern(fullCall, []string{"execute", "executemany", "raw", "find", "update", "delete"}) {
		a.addSecurityMetadata(graph, edge, "sql_injection", "CWE-89", "High",
			"Potential SQL injection vulnerability in "+fullCall)
	}
}

// checkXSS identifies cross-site scripting vulnerabilities
func (a *pythonSecurityAnalyzer) checkXSS(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonXSSSinks[fullCall] || a.matchesPattern(fullCall, []string{"render", "HttpResponse", "write", "print"}) {
		a.addSecurityMetadata(graph, edge, "xss", "CWE-79", "Medium",
			"Potential XSS vulnerability in "+fullCall)
	}
}

// checkPathTraversal identifies path traversal vulnerabilities
func (a *pythonSecurityAnalyzer) checkPathTraversal(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonPathSinks[fullCall] || a.matchesPattern(fullCall, []string{"open", "listdir", "walk", "copy", "move", "Path"}) {
		a.addSecurityMetadata(graph, edge, "path_traversal", "CWE-22", "High",
			"Potential path traversal vulnerability in "+fullCall)
	}
}

// checkUnsafeDeserialization identifies unsafe deserialization vulnerabilities
func (a *pythonSecurityAnalyzer) checkUnsafeDeserialization(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonDeserializationSinks[fullCall] || a.matchesPattern(fullCall, []string{"pickle\\.", "yaml\\.load", "marshal\\.", "dill\\."}) {
		a.addSecurityMetadata(graph, edge, "unsafe_deserialization", "CWE-502", "Critical",
			"Potential unsafe deserialization vulnerability in "+fullCall)
	}
}

// checkTaintSources identifies data input sources
func (a *pythonSecurityAnalyzer) checkTaintSources(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonTaintSources[fullCall] || a.matchesPattern(fullCall, []string{"request\\.", "input", "argv", "environ"}) {
		a.addSecurityMetadata(graph, edge, "taint_source", "INFO", "Info",
			"Identified taint source: "+fullCall)
	}
}

// checkSanitizers identifies security sanitization functions
func (a *pythonSecurityAnalyzer) checkSanitizers(graph *Graph, edge Edge, fullCall string, symbols []Symbol) {
	if pythonSanitizers[fullCall] || a.matchesPattern(fullCall, []string{"escape", "quote", "clean"}) {
		a.addSecurityMetadata(graph, edge, "sanitizer", "INFO", "Info",
			"Identified sanitizer: "+fullCall)
	}
}

// matchesPattern checks if a string matches any of the given regex patterns
func (a *pythonSecurityAnalyzer) matchesPattern(str string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := regexp.MatchString(pattern, str)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// addSecurityMetadata adds security vulnerability metadata to the graph edge
func (a *pythonSecurityAnalyzer) addSecurityMetadata(graph *Graph, edge Edge, vulnType, cwe, severity, description string) {
	if edge.Attributes.Metadata == nil {
		edge.Attributes.Metadata = make(map[string]any)
	}

	// Add or append vulnerability information
	var vulns []map[string]any
	if existing, ok := edge.Attributes.Metadata["vulnerabilities"].([]map[string]any); ok {
		vulns = existing
	}

	vuln := map[string]any{
		"type":        vulnType,
		"cwe":         cwe,
		"severity":    severity,
		"description": description,
		"language":    "python",
	}

	vulns = append(vulns, vuln)
	edge.Attributes.Metadata["vulnerabilities"] = vulns

	// Also set individual flags for easier filtering
	edge.Attributes.Metadata[vulnType] = true
	edge.Attributes.Metadata["has_vulnerability"] = true

	// Re-add the edge with updated attributes
	graph.AddEdgeWithAttributes(edge.Kind, edge.From, edge.To, edge.Attributes)
}
