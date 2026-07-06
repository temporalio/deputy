package policy

// commonHelpers are the CEL helper functions available at every entrypoint.
var commonHelpers = []string{"now()", "age()", "levenshtein()", "levenshteinWithin()"}

// helpersByCategory lists the additional CEL helper functions each entrypoint
// category provides beyond the common set.
var helpersByCategory = map[string][]string{
	"scan":  {"ssvc()", "hasFix()", "inKEV()", "epssScore()"},
	"graph": {"graphMatch()", "isDirectDep()", "nodeDepth()", "nodeEcosystem()", "hasVulnerabilities()", "vulnerabilityCount()", "pathLength()", "pathContains()"},
	"proxy": {"imageRef()", "baseImage()"},
}

// EntrypointHelpers returns the CEL helper functions available at an
// entrypoint. It is the single source shared by the policy discovery API, the
// MCP list_policy_entrypoints tool, and docs generation.
func EntrypointHelpers(ep Entrypoint) []string {
	helpers := make([]string, 0, len(commonHelpers)+8)
	helpers = append(helpers, commonHelpers...)
	return append(helpers, helpersByCategory[ep.Category()]...)
}
