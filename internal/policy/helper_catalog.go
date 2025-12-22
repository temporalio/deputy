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
}

// HelperCatalog returns the CEL helper catalog.
func HelperCatalog() []HelperFunction {
	out := make([]HelperFunction, len(helperFunctions))
	copy(out, helperFunctions)
	return out
}
