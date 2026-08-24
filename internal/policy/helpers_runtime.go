package policy

import (
	"cmp"
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/vulnerability/ssvc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// levenshteinMaxInputLen is the maximum string length accepted by the levenshtein
// functions. Inputs exceeding this limit return -1 to prevent excessive computation.
const levenshteinMaxInputLen = 128

// customHelperFunctions returns cel.EnvOption entries that register custom
// helper functions declared in helperFunctions. This keeps the runtime and
// catalog aligned.
func customHelperFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		// String distance functions
		cel.Function("levenshtein",
			cel.Overload("levenshtein_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.IntType,
				cel.BinaryBinding(func(a, b ref.Val) ref.Val {
					return types.Int(levenshtein(toString(a), toString(b), levenshteinMaxInputLen, -1))
				}),
			),
		),
		cel.Function("levenshteinWithin",
			cel.Overload("levenshteinWithin_string",
				[]*cel.Type{cel.StringType, cel.StringType, cel.IntType},
				cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 3 {
						return types.Bool(false)
					}
					a, b, limit := toString(args[0]), toString(args[1]), toInt64(args[2])
					dist := levenshtein(a, b, levenshteinMaxInputLen, limit)
					if dist < 0 {
						return types.Bool(false)
					}
					return types.Bool(dist <= limit)
				}),
			),
		),

		// Time functions for JWT/time-based policies
		// Note: CEL natively provides timestamp(int) and timestamp(string) constructors,
		// as well as duration(string). We only need to add now() since it's not built-in.
		cel.Function("now",
			cel.Overload("now_timestamp",
				[]*cel.Type{},
				cel.TimestampType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					return types.Timestamp{Time: time.Now()}
				}),
			),
		),
		// age() is a convenience function for computing time since a Unix timestamp.
		// While you can use `now() - timestamp(jwt.iat)`, `age(jwt.iat)` is more readable.
		cel.Function("age",
			cel.Overload("age_timestamp",
				[]*cel.Type{cel.TimestampType},
				cel.DurationType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					ts, ok := val.(types.Timestamp)
					if !ok {
						return types.Duration{Duration: 0}
					}
					return types.Duration{Duration: time.Since(ts.Time)}
				}),
			),
			cel.Overload("age_int",
				[]*cel.Type{cel.IntType},
				cel.DurationType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					secs := toInt64(val)
					t := time.Unix(secs, 0)
					return types.Duration{Duration: time.Since(t)}
				}),
			),
		),
		// purl() parses a Package URL and returns a map of fields or null when invalid.
		cel.Function("purl",
			cel.Overload("purl_string",
				[]*cel.Type{cel.StringType},
				cel.DynType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					raw := strings.TrimSpace(toString(val))
					if raw == "" {
						return types.NullValue
					}
					parsed, err := purlx.ParseLoose(raw)
					if err != nil {
						return types.NullValue
					}
					out := map[string]any{
						"type":       parsed.Type,
						"namespace":  parsed.Namespace,
						"name":       parsed.Name,
						"version":    parsed.Version,
						"qualifiers": parsed.Qualifiers.Map(),
						"subpath":    parsed.Subpath,
						"purl":       parsed.String(),
					}
					return types.DefaultTypeAdapter.NativeToValue(out)
				}),
			),
		),

		// ===== Container Image Helper Functions =====
		//
		// These functions provide parsing capabilities that are difficult or impossible
		// to implement correctly in pure CEL. They are designed to be composable with
		// CEL's built-in string functions, macros, and pattern matching.
		//
		// Design principles:
		// - Only add functions that parse complex formats (image refs, FROM commands)
		// - Return structured data that users can query with CEL
		// - Let CEL handle pattern matching, existence checks, counting, etc.

		// imageRef() parses a container image reference and returns structured components.
		// This handles the complex parsing of image references including:
		// - Implicit docker.io registry for short names (nginx -> docker.io/library/nginx)
		// - Port vs tag disambiguation (localhost:5000/app vs app:latest)
		// - Digest extraction (image@sha256:...)
		// - Scheme stripping (oci://, docker-daemon://)
		//
		// Returns: map with registry, repository, name, tag, digest fields
		//
		// Example usage in CEL:
		//   imageRef("nginx:latest").registry == "docker.io"
		//   imageRef(target.reference).tag == "latest" || imageRef(target.reference).digest == ""
		//   imageRef(ref).registry.endsWith(".gcr.io")
		//   imageRef(ref).tag.matches("^v?[0-9]+\\.[0-9]+\\.[0-9]+")
		cel.Function("imageRef",
			cel.Overload("imageRef_string",
				[]*cel.Type{cel.StringType},
				cel.DynType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					return types.DefaultTypeAdapter.NativeToValue(parseImageRef(toString(val)))
				}),
			),
		),

		// baseImage() extracts the base image reference from build history.
		// This parses the first FROM instruction in the history, handling:
		// - Standard FROM: "FROM alpine:3.19"
		// - Multi-stage: "FROM golang:1.21 AS builder"
		// - Platform-specific: "FROM --platform=linux/amd64 ubuntu:22.04"
		// - Docker's nop format: "/bin/sh -c #(nop) FROM gcr.io/distroless/static"
		//
		// Returns: the base image reference string (e.g., "alpine:3.19"), or "" if not found
		//
		// Example usage in CEL:
		//   baseImage(image.history).contains("alpine")
		//   baseImage(image.history).contains("distroless")
		//   imageRef(baseImage(image.history)).registry == "gcr.io"
		//   cel.bind(base, baseImage(image.history),
		//     base != "" && !base.contains("alpine") && !base.contains("distroless"))
		cel.Function("baseImage",
			cel.Overload("baseImage_list",
				[]*cel.Type{cel.ListType(cel.DynType)},
				cel.StringType,
				cel.UnaryBinding(func(history ref.Val) ref.Val {
					histList, ok := history.(traits.Lister)
					if !ok {
						return types.String("")
					}
					it := histList.Iterator()
					for it.HasNext() == types.True {
						entry := it.Next()
						if cmd := extractCreatedBy(entry); cmd != "" {
							if base := extractBaseImage(cmd); base != "" {
								return types.String(base)
							}
						}
					}
					return types.String("")
				}),
			),
		),

		// ===== SSVC (Stakeholder-Specific Vulnerability Categorization) =====
		//
		// ssvc() evaluates a vulnerability using the CISA SSVC decision tree.
		// Returns a map with decision, reasoning, and input factors.
		//
		// The function accepts a vulnerability map (from scan_vulnerability entrypoint)
		// and derives SSVC factors from available data:
		//   - exploitation: from inKEV (active if in KEV) or epss (poc if > 0.1)
		//   - automatable: inferred from epss > 0.5
		//   - technical_impact: from severity (CRITICAL/HIGH = total, else partial)
		//
		// Optional fields can be provided to override defaults:
		//   - mission_prevalence: "minimal", "support", "essential"
		//   - public_wellbeing_impact: "minimal", "material", "irreversible"
		//
		// Returns: map with:
		//   - decision: "act", "attend", "track*", or "track"
		//   - reasoning: explanation of the decision
		//   - input: the factors used for the decision
		//
		// Example usage in CEL:
		//   ssvc(vulnerability).decision == "act"
		//   ssvc(vulnerability).decision in ["act", "attend"]
		//   cel.bind(result, ssvc(vulnerability),
		//     result.decision == "act" || (result.decision == "attend" && vulnerability.severity == "CRITICAL"))
		cel.Function("ssvc",
			cel.Overload("ssvc_map",
				[]*cel.Type{cel.DynType},
				cel.DynType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					return types.DefaultTypeAdapter.NativeToValue(evaluateSSVC(val))
				}),
			),
		),

		// ===== Graph Helper Functions =====
		//
		// These functions provide graph analysis capabilities for dependency policies.
		// They work with the graph, node, and nodes variables available in graph entrypoints.

		// graphMatch(pattern) checks if a string matches a glob-like pattern.
		// Patterns support:
		//   - Exact: "lodash" matches "lodash"
		//   - Prefix: "lodash*" matches "lodash-es", "lodash.merge"
		//   - Suffix: "*crypto" matches "x/crypto", "node-crypto"
		//   - Contains: "*util*" matches "core-util-is", "util-deprecate"
		//
		// Example usage in CEL:
		//   graphMatch(node.name, "lodash*")
		//   nodes.filter(n, graphMatch(n.purl, "*crypto*"))
		cel.Function("graphMatch",
			cel.Overload("graphMatch_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(value, pattern ref.Val) ref.Val {
					return types.Bool(graphMatchesPattern(toString(value), toString(pattern)))
				}),
			),
		),

		// isDirectDep(node) checks if a node is a direct dependency.
		// Convenience wrapper around node.direct.
		//
		// Example usage in CEL:
		//   isDirectDep(node)
		//   nodes.filter(n, isDirectDep(n))
		cel.Function("isDirectDep",
			cel.Overload("isDirectDep_map",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.Bool(false)
					}
					return types.Bool(getBoolField(node, "direct"))
				}),
			),
		),

		// nodeDepth(node) returns the dependency depth of a node.
		// Direct dependencies have depth 0, their dependencies have depth 1, etc.
		//
		// Example usage in CEL:
		//   nodeDepth(node) > 2
		//   nodes.filter(n, nodeDepth(n) <= 1)
		cel.Function("nodeDepth",
			cel.Overload("nodeDepth_map",
				[]*cel.Type{cel.DynType},
				cel.IntType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.Int(0)
					}
					if depth, ok := node["depth"]; ok {
						switch d := depth.(type) {
						case int64:
							return types.Int(d)
						case int32:
							return types.Int(d)
						case int:
							return types.Int(d)
						case float64:
							return types.Int(int64(d))
						}
					}
					return types.Int(0)
				}),
			),
		),

		// nodeEcosystem(node) returns the ecosystem of a node (e.g., "npm", "Go", "PyPI").
		//
		// Example usage in CEL:
		//   nodeEcosystem(node) == "npm"
		//   nodes.filter(n, nodeEcosystem(n) in ["npm", "PyPI"])
		cel.Function("nodeEcosystem",
			cel.Overload("nodeEcosystem_map",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.String("")
					}
					return types.String(getStringField(node, "ecosystem"))
				}),
			),
		),

		// hasVulnerabilities(node) checks if a node has any known vulnerabilities.
		// Returns true if vulnerability_count.total > 0.
		//
		// Example usage in CEL:
		//   hasVulnerabilities(node)
		//   nodes.filter(n, hasVulnerabilities(n) && isDirectDep(n))
		cel.Function("hasVulnerabilities",
			cel.Overload("hasVulnerabilities_map",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.Bool(false)
					}
					// Check vulnerability_count.total (also vuln_count for backwards compat)
					vulnCount, ok := node["vulnerability_count"].(map[string]any)
					if !ok {
						vulnCount, ok = node["vuln_count"].(map[string]any)
					}
					if ok {
						if total, ok := vulnCount["total"]; ok {
							switch t := total.(type) {
							case int64:
								return types.Bool(t > 0)
							case int32:
								return types.Bool(t > 0)
							case int:
								return types.Bool(t > 0)
							case float64:
								return types.Bool(t > 0)
							}
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// vulnerabilityCount(node) returns the total vulnerability count for a node.
		//
		// Example usage in CEL:
		//   vulnerabilityCount(node) > 5
		//   nodes.filter(n, vulnerabilityCount(n) > 0).size()
		cel.Function("vulnerabilityCount",
			cel.Overload("vulnerabilityCount_map",
				[]*cel.Type{cel.DynType},
				cel.IntType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.Int(0)
					}
					// Check vulnerability_count.total (also vuln_count for backwards compat)
					vulnCount, ok := node["vulnerability_count"].(map[string]any)
					if !ok {
						vulnCount, ok = node["vuln_count"].(map[string]any)
					}
					if ok {
						if total, ok := vulnCount["total"]; ok {
							switch t := total.(type) {
							case int64:
								return types.Int(t)
							case int32:
								return types.Int(int64(t))
							case int:
								return types.Int(int64(t))
							case float64:
								return types.Int(int64(t))
							}
						}
					}
					return types.Int(0)
				}),
			),
		),

		// ===== Advanced Graph CEL Functions =====
		//
		// These functions provide path analysis and graph queries for dependency
		// graph policies. They work with the nodes/edges variables at graph entrypoints.

		// pathLength(path) returns the length of a dependency path (number of nodes).
		//
		// Example usage in CEL:
		//   pathLength(vulnerability.path) > 5
		//   vulnerability.?path.orValue([]).size() > 3  // equivalent using CEL builtin
		cel.Function("pathLength",
			cel.Overload("pathLength_list",
				[]*cel.Type{cel.ListType(cel.DynType)},
				cel.IntType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					if lister, ok := val.(traits.Lister); ok {
						return lister.Size()
					}
					return types.Int(0)
				}),
			),
		),

		// pathContains(path, pattern) checks if any element in the path matches the pattern.
		// Uses the same glob matching as graphMatch.
		//
		// Example usage in CEL:
		//   pathContains(vulnerability.path, "*lodash*")
		//   pathContains(vulnerability.path, "express")
		cel.Function("pathContains",
			cel.Overload("pathContains_list_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(pathVal, patternVal ref.Val) ref.Val {
					pattern := toString(patternVal)
					if pattern == "" {
						return types.Bool(false)
					}
					path := extractStringList(pathVal)
					for _, elem := range path {
						if graphMatchesPattern(elem, pattern) {
							return types.Bool(true)
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// pathDepth(path) returns the dependency depth (path length - 1).
		// Direct dependencies have depth 0.
		//
		// Example usage in CEL:
		//   pathDepth(vulnerability.path) > 3
		cel.Function("pathDepth",
			cel.Overload("pathDepth_list",
				[]*cel.Type{cel.ListType(cel.DynType)},
				cel.IntType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					if lister, ok := val.(traits.Lister); ok {
						size := lister.Size()
						if sizeInt, ok := size.(types.Int); ok {
							depth := int64(sizeInt) - 1
							if depth < 0 {
								return types.Int(0)
							}
							return types.Int(depth)
						}
					}
					return types.Int(0)
				}),
			),
		),

		// nodePurl(node) returns the PURL of a node.
		//
		// Example usage in CEL:
		//   nodePurl(node).contains("lodash")
		cel.Function("nodePurl",
			cel.Overload("nodePurl_map",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.String("")
					}
					if purl, ok := node["purl"].(string); ok {
						return types.String(purl)
					}
					return types.String("")
				}),
			),
		),

		// nodeName(node) returns the name of a node.
		//
		// Example usage in CEL:
		//   nodeName(node) == "lodash"
		cel.Function("nodeName",
			cel.Overload("nodeName_map",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.String("")
					}
					if name, ok := node["name"].(string); ok {
						return types.String(name)
					}
					return types.String("")
				}),
			),
		),

		// nodeVersion(node) returns the version of a node.
		//
		// Example usage in CEL:
		//   nodeVersion(node).startsWith("1.")
		cel.Function("nodeVersion",
			cel.Overload("nodeVersion_map",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					node := extractNodeFromMap(val)
					if node == nil {
						return types.String("")
					}
					if version, ok := node["version"].(string); ok {
						return types.String(version)
					}
					return types.String("")
				}),
			),
		),

		// edgeScope(edge) returns the scope of an edge (runtime, dev, test, etc.).
		//
		// Example usage in CEL:
		//   edgeScope(edge) == "dev"
		//   edges.filter(e, edgeScope(e) == "runtime")
		cel.Function("edgeScope",
			cel.Overload("edgeScope_map",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					edge := extractNodeFromMap(val)
					if edge == nil {
						return types.String("")
					}
					// Scope is stored as int in proto, map to string
					if scope, ok := edge["scope"]; ok {
						switch s := scope.(type) {
						case int32:
							return types.String(scopeToString(s))
						case int64:
							return types.String(scopeToString(int32(s)))
						case int:
							return types.String(scopeToString(int32(s)))
						case string:
							return types.String(s)
						}
					}
					return types.String("")
				}),
			),
		),

		// ===== Severity Comparison Helpers =====
		//
		// These helpers provide ordered severity comparisons that CEL can't do natively.
		// For simple equality checks, use proto field access directly:
		//   vulnerability.advisory.severity.level == deputy.vulnerability.v1.SeverityLevel.SEVERITY_LEVEL_CRITICAL
		//
		// For ordered comparisons (>= HIGH means HIGH or CRITICAL), use these helpers.

		// severityAtLeast(vuln, level) returns true if the vulnerability's severity
		// is at or above the specified level. This enables ordered comparisons without
		// repeating severity lists.
		// Works with proto Finding messages and map-based vulnerability objects.
		//
		// Severity order (highest to lowest): CRITICAL > HIGH > MEDIUM > LOW > UNSPECIFIED
		// A level outside that vocabulary fails evaluation with an error instead of
		// silently matching every finding.
		//
		// Example usage in CEL (both syntaxes supported):
		//   severityAtLeast(vulnerability, "HIGH")       // global function syntax
		//   vulnerability.severityAtLeast("HIGH")        // method syntax
		//   vulnerabilities.filter(v, v.severityAtLeast("MEDIUM"))
		cel.Function("severityAtLeast",
			// Global function syntax: severityAtLeast(vuln, level)
			cel.Overload("severityAtLeast_finding_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(severityAtLeastBinding),
			),
			// Method syntax: vuln.severityAtLeast(level)
			cel.MemberOverload("finding_severityAtLeast_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(severityAtLeastBinding),
			),
		),

		// isCritical(vuln) is a shorthand for severityAtLeast(vuln, "CRITICAL").
		// Works with proto Finding messages and map-based vulnerability objects.
		//
		// Example usage in CEL (both syntaxes supported):
		//   isCritical(vulnerability)        // global function syntax
		//   vulnerability.isCritical()       // method syntax
		//   vulnerabilities.filter(v, v.isCritical())
		cel.Function("isCritical",
			// Global function syntax: isCritical(vuln)
			cel.Overload("isCritical_finding",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(isCriticalBinding),
			),
			// Method syntax: vuln.isCritical()
			cel.MemberOverload("finding_isCritical",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(isCriticalBinding),
			),
		),

		// isHighOrAbove(vuln) is a shorthand for severityAtLeast(vuln, "HIGH").
		// Works with proto Finding messages and map-based vulnerability objects.
		//
		// Example usage in CEL (both syntaxes supported):
		//   isHighOrAbove(vulnerability)        // global function syntax
		//   vulnerability.isHighOrAbove()       // method syntax
		//   vulnerabilities.filter(v, v.isHighOrAbove())
		cel.Function("isHighOrAbove",
			// Global function syntax: isHighOrAbove(vuln)
			cel.Overload("isHighOrAbove_finding",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(isHighOrAboveBinding),
			),
			// Method syntax: vuln.isHighOrAbove()
			cel.MemberOverload("finding_isHighOrAbove",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(isHighOrAboveBinding),
			),
		),

		// ===== Import Status Helpers (Extended Graph Mode) =====
		//
		// These helpers check the import status of nodes in extended graph mode.
		// Import status indicates how a dependency is included:
		//   IMPORTED (1) - actively used by source code (highest risk)
		//   REQUIRED (2) - in go.mod but not directly imported (medium risk)
		//   DECLARED (3) - in full module graph but not selected (latent risk)

		// isImported(node) returns true if the node is actively imported by source code.
		// These packages are compiled into the binary (highest security relevance).
		//
		// Example usage in CEL:
		//   isImported(node)
		//   nodes.filter(n, isImported(n) && hasVulnerabilities(n))
		cel.Function("isImported",
			cel.Overload("isImported_node",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					status := extractImportStatus(val)
					return types.Bool(status == 1) // IMPORT_STATUS_IMPORTED
				}),
			),
		),

		// isRequired(node) returns true if the node is in go.mod/lockfile but not imported.
		// These packages are selected by MVS but may only be transitive deps.
		//
		// Example usage in CEL:
		//   isRequired(node)
		//   nodes.filter(n, isRequired(n))
		cel.Function("isRequired",
			cel.Overload("isRequired_node",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					status := extractImportStatus(val)
					return types.Bool(status == 2) // IMPORT_STATUS_REQUIRED
				}),
			),
		),

		// isDeclared(node) returns true if the node is in the full module graph but not selected.
		// These are "phantom" dependencies - latent supply chain risk.
		//
		// Example usage in CEL:
		//   isDeclared(node)
		//   nodes.filter(n, isDeclared(n) && hasVulnerabilities(n))
		cel.Function("isDeclared",
			cel.Overload("isDeclared_node",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					status := extractImportStatus(val)
					return types.Bool(status == 3) // IMPORT_STATUS_DECLARED
				}),
			),
		),

		// importStatus(node) returns the import status as a string.
		// Returns: "imported", "required", "declared", or "unknown".
		//
		// Example usage in CEL:
		//   importStatus(node) == "declared"
		//   nodes.filter(n, importStatus(n) in ["imported", "required"])
		cel.Function("importStatus",
			cel.Overload("importStatus_node",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					status := extractImportStatus(val)
					return types.String(importStatusToString(status))
				}),
			),
		),
	}
}

// Severity ranks order severity levels for comparison. Higher is more severe.
// They are the enum numbers of deputy.vulnerability.v1.SeverityLevel, which the
// proto declares in ascending severity order, so ranking never needs a
// hand-maintained copy of the level list.
const (
	severityRankUnspecified = int(vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED)
	severityRankHigh        = int(vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH)
	severityRankCritical    = int(vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL)
)

// severityLevelPrefix is the generated enum's value prefix. Policies write the
// bare level ("CRITICAL"), not the proto spelling.
const severityLevelPrefix = "SEVERITY_LEVEL_"

// severityLevels is the severity vocabulary derived from the generated
// SeverityLevel descriptor.
var severityLevels = newSeverityVocabulary()

// severityVocabulary is the set of severity level names Deputy accepts, together
// with their rank. It is built from the proto descriptor rather than written out
// by hand so that a new or renamed enum value cannot drift away from what
// severityAtLeast accepts or from the error message it prints.
type severityVocabulary struct {
	ranks map[string]int // ranks maps a bare level name to its enum number.
	names []string       // names lists the bare level names ordered least to most severe.
}

// newSeverityVocabulary reads the SeverityLevel enum descriptor once at startup,
// strips the generated prefix from each value, and orders the names by enum
// number so messages read least to most severe.
func newSeverityVocabulary() severityVocabulary {
	values := vulnerabilityv1.SeverityLevel(0).Descriptor().Values()
	vocab := severityVocabulary{ranks: make(map[string]int, values.Len())}
	byRank := make([]protoreflect.EnumValueDescriptor, 0, values.Len())
	for i := range values.Len() {
		byRank = append(byRank, values.Get(i))
	}
	slices.SortFunc(byRank, func(a, b protoreflect.EnumValueDescriptor) int {
		return cmp.Compare(a.Number(), b.Number())
	})
	for _, value := range byRank {
		name := strings.TrimPrefix(string(value.Name()), severityLevelPrefix)
		vocab.ranks[name] = int(value.Number())
		vocab.names = append(vocab.names, name)
	}
	return vocab
}

// nameFor returns the bare level name for a rank, and whether the rank is one
// the enum defines.
func (v severityVocabulary) nameFor(rank int) (string, bool) {
	for name, known := range v.ranks {
		if known == rank {
			return name, true
		}
	}
	return "", false
}

// severityAtLeastBinding is the CEL binding for the severityAtLeast function.
// The threshold is authored, not observed, so an unrecognized level is a
// programming mistake in the policy: it returns a CEL error naming the valid
// levels rather than ranking the typo below everything, which would have made
// the comparison true for every finding.
func severityAtLeastBinding(vulnVal, levelVal ref.Val) ref.Val {
	level := toString(levelVal)
	threshold, ok := severityRank(level)
	if !ok {
		return types.NewErr("severityAtLeast: unknown severity level %q (expected %s)", level, strings.Join(severityLevels.names, "|"))
	}
	return types.Bool(findingSeverityRank(vulnVal) >= threshold)
}

// isCriticalBinding is the CEL binding for isCritical function.
func isCriticalBinding(val ref.Val) ref.Val {
	return types.Bool(findingSeverityRank(val) == severityRankCritical)
}

// isHighOrAboveBinding is the CEL binding for isHighOrAbove function.
func isHighOrAboveBinding(val ref.Val) ref.Val {
	return types.Bool(findingSeverityRank(val) >= severityRankHigh)
}

// severityRank returns the ordered rank of a severity level name and whether the
// name belongs to the known vocabulary. Matching ignores case and surrounding
// whitespace. Callers must not collapse the false result into rank zero for
// author-supplied levels: zero sorts below LOW, so an unknown level would
// compare "at least" true for every finding.
func severityRank(name string) (int, bool) {
	rank, ok := severityLevels.ranks[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return severityRankUnspecified, false
	}
	return rank, true
}

// findingSeverityRank ranks the severity carried by a finding. Unlike an authored
// threshold, observed data can legitimately be missing or carry a level Deputy
// does not model, so it ranks as unspecified instead of failing evaluation.
func findingSeverityRank(val ref.Val) int {
	rank, ok := severityRank(extractSeverityString(val))
	if !ok {
		return severityRankUnspecified
	}
	return rank
}

// extractSeverityString extracts the severity level as a string from a proto Finding or map.
// Works with both proto Finding messages and map-based vulnerability objects (after ProtoToMap conversion).
func extractSeverityString(val ref.Val) string {
	// Try proto extraction first
	finding := extractFindingProto(val)
	if finding != nil {
		if advisory := finding.GetAdvisory(); advisory != nil {
			if severity := advisory.GetSeverity(); severity != nil {
				return severityLevelProtoToString(severity.GetLevel())
			}
		}
		return ""
	}
	// Fall back to map extraction (for data that went through ProtoToMap)
	vulnMap := extractVulnMap(val)
	if len(vulnMap) == 0 {
		return ""
	}
	// Navigate: vulnerability.advisory.severity.level
	advisory, ok := vulnMap["advisory"].(map[string]any)
	if !ok {
		return ""
	}
	severity, ok := advisory["severity"].(map[string]any)
	if !ok {
		return ""
	}
	return severityLevelToString(severity["level"])
}

// evaluateSSVC derives SSVC decision from a proto Finding message.
func evaluateSSVC(val ref.Val) map[string]any {
	finding := extractFindingProto(val)
	if finding == nil {
		return map[string]any{
			"decision":  "track",
			"reasoning": "Unable to evaluate: not a valid Finding proto",
		}
	}

	input := ssvc.Input{
		VulnerabilityID: finding.GetAdvisoryId(),
	}

	// Derive exploitation status from KEV and EPSS
	if finding.GetInKev() {
		input.Exploitation = ssvc.ExploitationActive
	} else if finding.GetEpss() > 0.1 {
		input.Exploitation = ssvc.ExploitationPoC
	} else {
		input.Exploitation = ssvc.ExploitationNone
	}

	// Derive automatable from EPSS (high EPSS suggests automatable exploit)
	if finding.GetEpss() > 0.5 {
		input.Automatable = ssvc.AutomatableYes
	} else {
		input.Automatable = ssvc.AutomatableNo
	}

	// Derive technical impact from severity
	if advisory := finding.GetAdvisory(); advisory != nil {
		if severity := advisory.GetSeverity(); severity != nil {
			level := severity.GetLevel()
			if level == vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL ||
				level == vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH {
				input.TechnicalImpact = ssvc.TechnicalImpactTotal
			} else {
				input.TechnicalImpact = ssvc.TechnicalImpactPartial
			}
		}
	}

	// Evaluate using the deployer decision tree
	tree := ssvc.NewDeployerTree()
	result := tree.Decide(context.Background(), input)

	return result.ToMap()
}

// extractFindingProto attempts to extract a *vulnerabilityv1.Finding from a CEL value.
// Returns nil if the value is not a Finding proto.
func extractFindingProto(val ref.Val) *vulnerabilityv1.Finding {
	if val == nil {
		return nil
	}
	// Try direct proto message extraction
	if msg, ok := val.Value().(proto.Message); ok {
		if finding, ok := msg.(*vulnerabilityv1.Finding); ok {
			return finding
		}
	}
	// NOTE: We intentionally do NOT call ConvertToNative here.
	// When the input is a map (after ProtoToMap conversion), ConvertToNative can panic
	// with "reflect: call of reflect.Value.Set on zero Value". Instead, we return nil
	// and let callers fall back to map-based extraction.
	return nil
}

// extractVulnMap extracts a map from a CEL value.
func extractVulnMap(val ref.Val) map[string]any {
	if val == nil {
		return map[string]any{}
	}
	// Try traits.Mapper first (CEL map)
	if m, ok := val.(traits.Mapper); ok {
		result := map[string]any{}
		it := m.Iterator()
		for it.HasNext() == types.True {
			key := it.Next()
			if keyStr := toString(key); keyStr != "" {
				if v, found := m.Find(key); found {
					result[keyStr] = extractNativeValue(v)
				}
			}
		}
		return result
	}
	// Try native map
	if native, err := val.ConvertToNative(mapStringAnyType); err == nil {
		if m, ok := native.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

// extractNativeValue converts a CEL ref.Val to a native Go value.
func extractNativeValue(val ref.Val) any {
	if val == nil {
		return nil
	}
	return val.Value()
}

// getStringField safely extracts a string field from a map.
func getStringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getBoolField safely extracts a bool field from a map.
func getBoolField(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// extractCreatedBy extracts the created_by field from a history entry.
// Works with both map[string]any (native) and traits.Mapper (CEL) types.
func extractCreatedBy(entry ref.Val) string {
	// Try traits.Mapper first (CEL map)
	if entryMap, ok := entry.(traits.Mapper); ok {
		if cmdVal, found := entryMap.Find(types.String("created_by")); found {
			return toString(cmdVal)
		}
	}
	// Try native map
	if native, err := entry.ConvertToNative(mapStringAnyType); err == nil {
		if m, ok := native.(map[string]any); ok {
			if cmd, ok := m["created_by"].(string); ok {
				return cmd
			}
		}
	}
	return ""
}

// mapStringAnyType is used for type conversion
var mapStringAnyType = reflect.TypeFor[map[string]any]()

// parseImageRef parses a container image reference into components.
// Handles formats like:
//   - nginx (name only, implicit docker.io/library/)
//   - nginx:1.24 (name:tag)
//   - nginx@sha256:abc... (name@digest)
//   - gcr.io/project/app:v1 (registry/repo:tag)
//   - ghcr.io/owner/repo:tag (registry/owner/repo:tag)
func parseImageRef(ref string) map[string]any {
	result := map[string]any{
		"registry":   "",
		"repository": "",
		"name":       "",
		"tag":        "",
		"digest":     "",
		"reference":  ref,
	}

	ref = strings.TrimSpace(ref)
	if ref == "" {
		return result
	}

	// Strip scheme prefixes (oci://, docker-daemon://, etc.)
	if idx := strings.Index(ref, "://"); idx != -1 {
		ref = ref[idx+3:]
	}

	// Extract digest if present
	if idx := strings.LastIndex(ref, "@"); idx != -1 {
		result["digest"] = ref[idx+1:]
		ref = ref[:idx]
	}

	// Extract tag if present (but not part of a port like :5000)
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		// Check if this is a port (registry:port/repo) vs tag (repo:tag)
		afterColon := ref[idx+1:]
		if !strings.Contains(afterColon, "/") {
			result["tag"] = afterColon
			ref = ref[:idx]
		}
	}

	// Parse registry and repository
	parts := strings.Split(ref, "/")
	switch len(parts) {
	case 1:
		// Just name: nginx -> docker.io/library/nginx
		result["registry"] = "docker.io"
		result["repository"] = "library/" + parts[0]
		result["name"] = parts[0]
	case 2:
		// Could be user/repo (docker.io) or registry/repo
		if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
			// It's a registry
			result["registry"] = parts[0]
			result["repository"] = parts[1]
			result["name"] = parts[1]
		} else {
			// It's docker.io/user/repo
			result["registry"] = "docker.io"
			result["repository"] = ref
			result["name"] = parts[1]
		}
	default:
		// registry/path/to/repo
		result["registry"] = parts[0]
		result["repository"] = strings.Join(parts[1:], "/")
		result["name"] = parts[len(parts)-1]
	}

	return result
}

// extractBaseImage extracts the base image from a FROM command
func extractBaseImage(cmd string) string {
	// Look for "FROM " pattern
	cmdLower := strings.ToLower(cmd)
	if !strings.Contains(cmdLower, "from ") {
		return ""
	}

	// Extract the image reference after FROM
	// Handle: "FROM alpine:3.19" or "/bin/sh -c #(nop) FROM alpine:3.19"
	idx := strings.Index(cmdLower, "from ")
	if idx == -1 {
		return ""
	}

	rest := strings.TrimSpace(cmd[idx+5:])

	// Handle "FROM image AS alias"
	if asIdx := strings.Index(strings.ToLower(rest), " as "); asIdx != -1 {
		rest = rest[:asIdx]
	}

	// Handle platform: "FROM --platform=linux/amd64 image"
	if strings.HasPrefix(rest, "--") {
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			rest = strings.TrimSpace(rest[spaceIdx+1:])
		}
	}

	// Return first word (the image reference)
	if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
		rest = rest[:spaceIdx]
	}

	return strings.TrimSpace(rest)
}

// ===== Graph CEL Helper Functions =====
//
// These functions provide graph traversal and querying capabilities for
// dependency graph policies. They work with the graph variable binding
// at graph_report, graph_node, and graph_edge entrypoints.

// extractNodeFromMap safely extracts a node-like map from a CEL value.
func extractNodeFromMap(val ref.Val) map[string]any {
	if val == nil {
		return nil
	}
	// Try traits.Mapper (CEL map)
	if m, ok := val.(traits.Mapper); ok {
		result := map[string]any{}
		it := m.Iterator()
		for it.HasNext() == types.True {
			key := it.Next()
			if keyStr := toString(key); keyStr != "" {
				if v, found := m.Find(key); found {
					result[keyStr] = extractNativeValue(v)
				}
			}
		}
		return result
	}
	// Try native map
	if native, err := val.ConvertToNative(mapStringAnyType); err == nil {
		if m, ok := native.(map[string]any); ok {
			return m
		}
	}
	return nil
}

// graphMatchesPattern checks if a PURL or name matches a pattern.
// Supports:
//   - Exact match: "pkg:npm/lodash@4.17.21"
//   - Prefix match: "pkg:npm/lodash*" or "lodash*"
//   - Contains match: "*lodash*"
//   - Suffix match: "*@4.17.21"
func graphMatchesPattern(value, pattern string) bool {
	if pattern == "" {
		return false
	}
	value = strings.ToLower(value)
	pattern = strings.ToLower(pattern)

	// Handle wildcard patterns
	hasPrefix := strings.HasPrefix(pattern, "*")
	hasSuffix := strings.HasSuffix(pattern, "*")

	if hasPrefix && hasSuffix {
		// Contains match: *pattern*
		core := pattern[1 : len(pattern)-1]
		return strings.Contains(value, core)
	} else if hasPrefix {
		// Suffix match: *pattern
		core := pattern[1:]
		return strings.HasSuffix(value, core)
	} else if hasSuffix {
		// Prefix match: pattern*
		core := pattern[:len(pattern)-1]
		return strings.HasPrefix(value, core)
	}
	// Exact match
	return value == pattern
}

// extractStringList extracts a list of strings from a CEL value.
func extractStringList(val ref.Val) []string {
	if val == nil {
		return nil
	}
	// Try traits.Lister (CEL list)
	if lister, ok := val.(traits.Lister); ok {
		result := make([]string, 0)
		it := lister.Iterator()
		for it.HasNext() == types.True {
			elem := it.Next()
			if s := toString(elem); s != "" {
				result = append(result, s)
			}
		}
		return result
	}
	// Try native slice
	if native, err := val.ConvertToNative(reflect.TypeFor[[]any]()); err == nil {
		if slice, ok := native.([]any); ok {
			result := make([]string, 0, len(slice))
			for _, elem := range slice {
				if s, ok := elem.(string); ok {
					result = append(result, s)
				}
			}
			return result
		}
	}
	return nil
}

// scopeToString converts a proto scope enum value to a string.
func scopeToString(scope int32) string {
	switch scope {
	case 0:
		return "unspecified"
	case 1:
		return "runtime"
	case 2:
		return "dev"
	case 3:
		return "optional"
	case 4:
		return "build"
	case 5:
		return "test"
	default:
		return "unknown"
	}
}

// severityLevelToString converts a severity level to a string.
func severityLevelToString(level any) string {
	switch l := level.(type) {
	case int32:
		return severityIntToString(l)
	case int64:
		return severityIntToString(int32(l))
	case int:
		return severityIntToString(int32(l))
	case string:
		return strings.ToUpper(l)
	default:
		return ""
	}
}

// severityIntToString converts a severity level int to a string, reporting
// "UNKNOWN" for a number the SeverityLevel enum does not define.
func severityIntToString(level int32) string {
	if name, ok := severityLevels.nameFor(int(level)); ok {
		return name
	}
	return "UNKNOWN"
}

// severityLevelProtoToString converts a proto SeverityLevel enum to its bare
// name, falling back to UNSPECIFIED for a value this build does not know.
func severityLevelProtoToString(level vulnerabilityv1.SeverityLevel) string {
	if name, ok := severityLevels.nameFor(int(level)); ok {
		return name
	}
	return "UNSPECIFIED"
}

// extractImportStatus extracts the import_status field from a node.
// Returns the numeric value: 0=unspecified, 1=imported, 2=required, 3=declared.
func extractImportStatus(val ref.Val) int32 {
	node := extractNodeFromMap(val)
	if node == nil {
		return 0
	}
	// Try import_status field (snake_case from proto)
	if status, ok := node["import_status"]; ok {
		switch s := status.(type) {
		case int32:
			return s
		case int64:
			return int32(s)
		case int:
			return int32(s)
		}
	}
	// Try importStatus field (camelCase)
	if status, ok := node["importStatus"]; ok {
		switch s := status.(type) {
		case int32:
			return s
		case int64:
			return int32(s)
		case int:
			return int32(s)
		}
	}
	return 0
}

// importStatusToString converts an import status int to a string.
func importStatusToString(status int32) string {
	switch status {
	case 1:
		return "imported"
	case 2:
		return "required"
	case 3:
		return "declared"
	default:
		return "unknown"
	}
}
