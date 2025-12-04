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
	{Name: "levenshtein", Signature: "levenshtein(string, string) int", Doc: "Compute Levenshtein distance (capped length)."},
	{Name: "levenshteinWithin", Signature: "levenshteinWithin(string, string, int) bool", Doc: "True if distance within limit."},
	// Standard CEL/extension helpers we rely on
	{Name: "exists", Signature: "list.exists(var, predicate)", Doc: "CEL macro: any element matches predicate."},
	{Name: "map", Signature: "list.map(var, expr)", Doc: "CEL macro: transform list elements."},
	{Name: "filter", Signature: "list.filter(var, predicate)", Doc: "CEL macro: filter list elements."},
	{Name: "matches", Signature: "string.matches(pattern)", Doc: "Regex match (ext.Regex)."},
	{Name: "join", Signature: "list.join(sep)", Doc: "Join list elements (ext.Strings)."},
	{Name: "lowerAscii", Signature: "string.lowerAscii()", Doc: "Lowercase ASCII (ext.Strings)."},
	{Name: "upperAscii", Signature: "string.upperAscii()", Doc: "Uppercase ASCII (ext.Strings)."},
}

// HelperCatalog returns the CEL helper catalog.
func HelperCatalog() []HelperFunction {
	out := make([]HelperFunction, len(helperFunctions))
	copy(out, helperFunctions)
	return out
}
