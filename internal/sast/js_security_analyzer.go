package sast

// jsSecurityAnalyzer performs security analysis on JavaScript/TypeScript code
type jsSecurityAnalyzer struct{}

// analyze examines the IR graph and symbols for security vulnerabilities
func (a *jsSecurityAnalyzer) analyze(graph *Graph, symbols []Symbol) {
	snapshot := graph.Snapshot()

	// Analyze each symbol for security issues
	for _, symbol := range snapshot.Symbols() {
		// Check outgoing call edges for vulnerabilities
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			a.analyzeCall(graph, edge, symbol)
		}
	}
}

// analyzeCall examines a function call for security vulnerabilities
func (a *jsSecurityAnalyzer) analyzeCall(graph *Graph, edge Edge, caller Symbol) {
	if edge.Attributes.Metadata == nil {
		return
	}

	callName, ok := edge.Attributes.Metadata["call_name"].(string)
	if !ok {
		return
	}

	receiver, _ := edge.Attributes.Metadata["receiver"].(string)
	args, _ := edge.Attributes.Metadata["args"].([]string)

	// Create a call context for analysis
	call := &jsCallContext{
		name:     callName,
		receiver: receiver,
		args:     args,
		edge:     edge,
	}

	// Check for different types of vulnerabilities
	a.checkCommandInjection(graph, call)
	a.checkCodeInjection(graph, call)
	a.checkSQLInjection(graph, call)
	a.checkXSS(graph, call)
	a.checkPathTraversal(graph, call)
	a.checkUnsafeDeserialization(graph, call)
	a.checkTaintSources(graph, call)
	a.checkSanitizers(graph, call)
}

// jsCallContext holds information about a function call for security analysis
type jsCallContext struct {
	name     string
	receiver string
	args     []string
	edge     Edge
}

// checkCommandInjection detects command injection vulnerabilities
func (a *jsSecurityAnalyzer) checkCommandInjection(graph *Graph, call *jsCallContext) {
	if a.isCommandInjectionSink(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"vulnerability_type": "command_injection",
			"cwe":                "CWE-78",
			"severity":           "high",
		})
	}
}

// checkCodeInjection detects code injection vulnerabilities
func (a *jsSecurityAnalyzer) checkCodeInjection(graph *Graph, call *jsCallContext) {
	if a.isCodeInjectionSink(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"vulnerability_type": "code_injection",
			"cwe":                "CWE-94",
			"severity":           "critical",
		})
	}
}

// checkSQLInjection detects SQL injection vulnerabilities
func (a *jsSecurityAnalyzer) checkSQLInjection(graph *Graph, call *jsCallContext) {
	if a.isSQLInjectionSink(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"vulnerability_type": "sql_injection",
			"cwe":                "CWE-89",
			"severity":           "high",
		})
	}
}

// checkXSS detects cross-site scripting vulnerabilities
func (a *jsSecurityAnalyzer) checkXSS(graph *Graph, call *jsCallContext) {
	if a.isXSSSink(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"vulnerability_type": "xss",
			"cwe":                "CWE-79",
			"severity":           "medium",
		})
	}
}

// checkPathTraversal detects path traversal vulnerabilities
func (a *jsSecurityAnalyzer) checkPathTraversal(graph *Graph, call *jsCallContext) {
	if a.isPathTraversalSink(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"vulnerability_type": "path_traversal",
			"cwe":                "CWE-22",
			"severity":           "high",
		})
	}
}

// checkUnsafeDeserialization detects unsafe deserialization vulnerabilities
func (a *jsSecurityAnalyzer) checkUnsafeDeserialization(graph *Graph, call *jsCallContext) {
	if a.isUnsafeDeserializationSink(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"vulnerability_type": "unsafe_deserialization",
			"cwe":                "CWE-502",
			"severity":           "critical",
		})
	}
}

// checkTaintSources identifies taint sources
func (a *jsSecurityAnalyzer) checkTaintSources(graph *Graph, call *jsCallContext) {
	if a.isTaintSource(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"taint_source": true,
			"source_type":  "user_input",
		})
	}
}

// checkSanitizers identifies sanitization functions
func (a *jsSecurityAnalyzer) checkSanitizers(graph *Graph, call *jsCallContext) {
	if a.isSanitizer(call.name, call.receiver) {
		a.addVulnerabilityMetadata(graph, call, map[string]any{
			"sanitizer": true,
		})
	}
}

// addVulnerabilityMetadata adds security metadata to the edge
func (a *jsSecurityAnalyzer) addVulnerabilityMetadata(graph *Graph, call *jsCallContext, metadata map[string]any) {
	if call.edge.Attributes.Metadata == nil {
		call.edge.Attributes.Metadata = make(map[string]any)
	}

	for key, value := range metadata {
		call.edge.Attributes.Metadata[key] = value
	}

	// Update the edge in the graph
	graph.AddEdgeWithAttributes(EdgeKindCall, call.edge.From, call.edge.To, call.edge.Attributes)
}

// Security sink detection functions

func (a *jsSecurityAnalyzer) isCommandInjectionSink(name, receiver string) bool {
	// Global command execution functions
	globalSinks := []string{"exec", "execSync", "spawn", "spawnSync", "fork", "system"}
	for _, sink := range globalSinks {
		if name == sink {
			return true
		}
	}

	sinks := map[string][]string{
		"child_process": {"exec", "execSync", "spawn", "spawnSync", "fork", "execFile", "execFileSync"},
		"process":       {"exec"},
		"require":       {"child_process"},
	}

	if methods, ok := sinks[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

func (a *jsSecurityAnalyzer) isCodeInjectionSink(name, receiver string) bool {
	// Global code execution functions
	globalSinks := []string{"eval", "Function", "setTimeout", "setInterval"}
	for _, sink := range globalSinks {
		if name == sink {
			return true
		}
	}

	sinks := map[string][]string{
		"vm":     {"runInThisContext", "runInNewContext", "runInContext"},
		"global": {"eval"},
		"window": {"eval", "setTimeout", "setInterval"},
	}

	if methods, ok := sinks[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

func (a *jsSecurityAnalyzer) isSQLInjectionSink(name, receiver string) bool {
	sinks := map[string][]string{
		"mysql":     {"query", "execute"},
		"mysql2":    {"query", "execute"},
		"pg":        {"query"},
		"sqlite3":   {"run", "get", "all", "each"},
		"mongodb":   {"find", "findOne", "aggregate", "update", "remove"},
		"mongoose":  {"find", "findOne", "findOneAndUpdate", "updateOne", "deleteOne"},
		"sequelize": {"query"},
		"knex":      {"raw"},
	}

	if methods, ok := sinks[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

func (a *jsSecurityAnalyzer) isXSSSink(name, receiver string) bool {
	// Global XSS sinks
	globalSinks := []string{"write", "writeln", "innerHTML", "outerHTML"}
	for _, sink := range globalSinks {
		if name == sink {
			return true
		}
	}

	sinks := map[string][]string{
		"document": {"write", "writeln"},
		"element":  {"innerHTML", "outerHTML", "insertAdjacentHTML"},
		"response": {"write", "send", "json"},
		"res":      {"write", "send", "json", "render"},
		"express":  {"render"},
		"$":        {"html", "append", "prepend", "after", "before"},
		"jQuery":   {"html", "append", "prepend", "after", "before"},
	}

	if methods, ok := sinks[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

func (a *jsSecurityAnalyzer) isPathTraversalSink(name, receiver string) bool {
	sinks := map[string][]string{
		"fs":   {"readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "unlink", "unlinkSync"},
		"path": {"join", "resolve"},
		"":     {"require"}, // require() with dynamic paths
	}

	if methods, ok := sinks[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

func (a *jsSecurityAnalyzer) isUnsafeDeserializationSink(name, receiver string) bool {
	sinks := map[string][]string{
		"JSON":           {"parse"},
		"eval":           {""},
		"vm":             {"runInThisContext", "runInNewContext"},
		"serialize":      {"unserialize"},
		"node-serialize": {"unserialize"},
		"funcster":       {"deepDeserialize"},
	}

	if methods, ok := sinks[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	// Global deserialization functions
	if name == "eval" || name == "unserialize" {
		return true
	}

	return false
}

func (a *jsSecurityAnalyzer) isTaintSource(name, receiver string) bool {
	// Global taint sources
	globalSources := []string{"params", "query", "body", "headers", "cookies", "argv"}
	for _, source := range globalSources {
		if name == source {
			return true
		}
	}

	sources := map[string][]string{
		"req":             {"body", "query", "params", "headers", "cookies", "url", "path"},
		"request":         {"body", "query", "params", "headers", "cookies"},
		"process":         {"argv", "env"},
		"window":          {"location", "search"},
		"document":        {"cookie", "referrer", "URL"},
		"location":        {"search", "hash", "href"},
		"URLSearchParams": {"get", "getAll"},
	}

	if methods, ok := sources[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

func (a *jsSecurityAnalyzer) isSanitizer(name, receiver string) bool {
	// Global sanitizers
	globalSanitizers := []string{"escape", "sanitize", "clean", "encodeURIComponent", "encodeURI"}
	for _, sanitizer := range globalSanitizers {
		if name == sanitizer {
			return true
		}
	}

	sanitizers := map[string][]string{
		"validator":     {"escape", "blacklist", "whitelist", "stripLow"},
		"he":            {"encode", "escape"},
		"lodash":        {"escape", "escapeRegExp"},
		"_":             {"escape", "escapeRegExp"},
		"dompurify":     {"sanitize"},
		"xss":           {"filterXSS"},
		"html-entities": {"encode"},
		"entities":      {"encodeHTML", "encodeXML"},
	}

	if methods, ok := sanitizers[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}
