package policy

// HelperFunction describes a CEL helper exposed in the Deputy environment.
// It is used both by the runtime (for registration) and by tooling (LSP, docs)
// to keep completions/hovers in sync with the functions actually available.
type HelperFunction struct {
	Name      string // Name is the function name as it appears in CEL.
	Signature string // Signature is the function signature for documentation/hover.
	Doc       string // Doc is the documentation string for the function.
}

// helperFunctions centralizes the catalog so tooling (LSP, docs) stay in sync
// with registered functions in envWithNames.
var helperFunctions = []HelperFunction{
	// Custom Deputy functions
	{Name: "levenshtein", Signature: "levenshtein(string, string) int", Doc: "Compute Levenshtein distance (capped length)."},
	{Name: "levenshteinWithin", Signature: "levenshteinWithin(string, string, int) bool", Doc: "True if distance within limit."},

	// Time functions (useful for JWT/token policies)
	// Note: timestamp(int), timestamp(string), and duration(string) are CEL built-ins.
	{Name: "now", Signature: "now() timestamp", Doc: "Returns current time as a timestamp. Use int(now()) for Unix seconds."},
	{Name: "age", Signature: "age(int|timestamp) duration", Doc: "Duration since the given Unix timestamp or timestamp. Convenience for now() - timestamp(x)."},
	{Name: "purl", Signature: "purl(string) map", Doc: "Parse a Package URL into a map (type, namespace, name, version, qualifiers, subpath, purl). Returns null on invalid input."},
	{Name: "timestamp", Signature: "timestamp(int|string) timestamp", Doc: "CEL built-in: convert Unix seconds or RFC 3339 string to timestamp."},
	{Name: "duration", Signature: "duration(string) duration", Doc: "CEL built-in: parse duration string (e.g., '1h', '30m', '24h')."},

	// Standard CEL/extension helpers we rely on
	{Name: "exists", Signature: "list.exists(var, predicate)", Doc: "CEL macro: any element matches predicate."},
	{Name: "map", Signature: "list.map(var, expr)", Doc: "CEL macro: transform list elements."},
	{Name: "filter", Signature: "list.filter(var, predicate)", Doc: "CEL macro: filter list elements."},
	{Name: "has", Signature: "has(field)", Doc: "CEL macro: check if field is present."},

	// ext.Strings
	{Name: "matches", Signature: "string.matches(pattern)", Doc: "Regex match (ext.Regex)."},
	{Name: "join", Signature: "list.join(sep)", Doc: "Join list elements (ext.Strings)."},
	{Name: "lowerAscii", Signature: "string.lowerAscii()", Doc: "Lowercase ASCII (ext.Strings)."},
	{Name: "upperAscii", Signature: "string.upperAscii()", Doc: "Uppercase ASCII (ext.Strings)."},
	{Name: "split", Signature: "string.split(sep)", Doc: "Split string into list (ext.Strings)."},
	{Name: "trim", Signature: "string.trim()", Doc: "Remove leading/trailing whitespace (ext.Strings)."},
	{Name: "replace", Signature: "string.replace(old, new)", Doc: "Replace all occurrences (ext.Strings)."},

	// ext.Bindings
	{Name: "cel.bind", Signature: "cel.bind(var, init, expr)", Doc: "Bind variable to value in expression (ext.Bindings)."},

	// ext.Encoders
	{Name: "base64.encode", Signature: "base64.encode(bytes)", Doc: "Encode bytes as base64 string (ext.Encoders)."},
	{Name: "base64.decode", Signature: "base64.decode(string)", Doc: "Decode base64 string to bytes (ext.Encoders)."},

	// ext.Math
	{Name: "math.abs", Signature: "math.abs(number)", Doc: "Absolute value (ext.Math)."},
	{Name: "math.ceil", Signature: "math.ceil(double)", Doc: "Round up to nearest integer (ext.Math)."},
	{Name: "math.floor", Signature: "math.floor(double)", Doc: "Round down to nearest integer (ext.Math)."},
	{Name: "math.round", Signature: "math.round(double)", Doc: "Round to nearest integer (ext.Math)."},
	{Name: "math.greatest", Signature: "math.greatest(a, b, ...)", Doc: "Return greatest value (ext.Math)."},
	{Name: "math.least", Signature: "math.least(a, b, ...)", Doc: "Return least value (ext.Math)."},

	// Container Image Helper Functions
	// These provide complex parsing that can't be done well in pure CEL.
	// Use CEL's built-in string functions (contains, matches, startsWith, endsWith)
	// and macros (exists, filter, map) for pattern matching and iteration.
	{Name: "imageRef", Signature: "imageRef(string) map", Doc: "Parse container image reference into components (registry, repository, name, tag, digest). Handles implicit docker.io, port vs tag disambiguation, and scheme stripping."},
	{Name: "baseImage", Signature: "baseImage(list) string", Doc: "Extract base image reference from build history (first FROM). Handles multi-stage builds, --platform flags, and Docker's nop format."},

	// SSVC (Stakeholder-Specific Vulnerability Categorization)
	{Name: "ssvc", Signature: "ssvc(vulnerability) map", Doc: "Evaluate vulnerability using CISA SSVC decision tree. Returns map with decision (act/attend/track*/track), reasoning, and input factors."},

	// Graph Helper Functions
	// These provide dependency graph analysis for graph_report, graph_node, and graph_edge entrypoints.
	{Name: "graphMatch", Signature: "graphMatch(string, pattern) bool", Doc: "Check if string matches glob pattern. Supports exact, prefix (*), suffix (*), and contains (*x*) matching."},
	{Name: "isDirectDep", Signature: "isDirectDep(node) bool", Doc: "Check if node is a direct dependency."},
	{Name: "nodeDepth", Signature: "nodeDepth(node) int", Doc: "Get dependency depth of node (0 = direct, 1+ = transitive)."},
	{Name: "nodeEcosystem", Signature: "nodeEcosystem(node) string", Doc: "Get ecosystem of node (e.g., 'npm', 'Go', 'PyPI')."},
	{Name: "hasVulnerabilities", Signature: "hasVulnerabilities(node) bool", Doc: "Check if node has any known vulnerabilities."},
	{Name: "vulnerabilityCount", Signature: "vulnerabilityCount(node) int", Doc: "Get total vulnerability count for node."},

	// Path Analysis Functions
	// These work with vulnerability.path (when --with-graph is enabled) and graph traversal results.
	{Name: "pathLength", Signature: "pathLength(list) int", Doc: "Get length of a dependency path (number of nodes)."},
	{Name: "pathContains", Signature: "pathContains(list, pattern) bool", Doc: "Check if any path element matches the glob pattern."},
	{Name: "pathDepth", Signature: "pathDepth(list) int", Doc: "Get dependency depth from path (path length - 1). Direct = 0."},

	// Node Accessor Functions
	// Convenient accessors for node fields, composable with filter/map.
	{Name: "nodePurl", Signature: "nodePurl(node) string", Doc: "Get PURL of a node."},
	{Name: "nodeName", Signature: "nodeName(node) string", Doc: "Get name of a node."},
	{Name: "nodeVersion", Signature: "nodeVersion(node) string", Doc: "Get version of a node."},

	// Edge Functions
	{Name: "edgeScope", Signature: "edgeScope(edge) string", Doc: "Get scope of an edge (runtime, dev, test, build, optional)."},

	// Vulnerability Helper Functions
	// These work with vulnerability objects in scan_vulnerability and scan_report entrypoints.
	{Name: "vulnerabilitySeverity", Signature: "vulnerabilitySeverity(vulnerability) string", Doc: "Get severity level (CRITICAL, HIGH, MEDIUM, LOW)."},
	{Name: "vulnerabilityId", Signature: "vulnerabilityId(vulnerability) string", Doc: "Get advisory ID (CVE-xxx, GHSA-xxx)."},
	{Name: "hasFix", Signature: "hasFix(vulnerability) bool", Doc: "Check if vulnerability has a known fix."},
	{Name: "inKEV", Signature: "inKEV(vulnerability) bool", Doc: "Check if vulnerability is in CISA's KEV catalog."},
	{Name: "epssScore", Signature: "epssScore(vulnerability) double", Doc: "Get EPSS score (0.0-1.0), returns 0 if unavailable."},
}

// HelperCatalog returns the CEL helper catalog.
func HelperCatalog() []HelperFunction {
	out := make([]HelperFunction, len(helperFunctions))
	copy(out, helperFunctions)
	return out
}
