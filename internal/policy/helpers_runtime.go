package policy

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/vulnerability/ssvc"
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
	}
}

// evaluateSSVC derives SSVC decision from vulnerability data.
func evaluateSSVC(val ref.Val) map[string]any {
	// Extract vulnerability data
	vuln := extractVulnMap(val)

	input := ssvc.Input{
		VulnerabilityID: getStringField(vuln, "id"),
	}

	// Derive exploitation status from KEV and EPSS
	if getBoolField(vuln, "inKEV") {
		input.Exploitation = ssvc.ExploitationActive
	} else if epss := getFloatField(vuln, "epss"); epss > 0.1 {
		input.Exploitation = ssvc.ExploitationPoC
	} else {
		input.Exploitation = ssvc.ExploitationNone
	}

	// Derive automatable from EPSS (high EPSS suggests automatable exploit)
	if epss := getFloatField(vuln, "epss"); epss > 0.5 {
		input.Automatable = ssvc.AutomatableYes
	} else {
		input.Automatable = ssvc.AutomatableNo
	}

	// Derive technical impact from severity
	severity := strings.ToUpper(getStringField(vuln, "severity"))
	if severity == "CRITICAL" || severity == "HIGH" {
		input.TechnicalImpact = ssvc.TechnicalImpactTotal
	} else {
		input.TechnicalImpact = ssvc.TechnicalImpactPartial
	}

	// Allow explicit overrides if provided
	if mp := getStringField(vuln, "mission_prevalence"); mp != "" {
		input.MissionPrevalence = ssvc.MissionPrevalence(mp)
	}
	if pwi := getStringField(vuln, "public_wellbeing_impact"); pwi != "" {
		input.PublicWellbeingImpact = ssvc.PublicWellbeingImpact(pwi)
	}

	// Evaluate using the deployer decision tree
	tree := ssvc.NewDeployerTree()
	result := tree.Decide(context.Background(), input)

	return result.ToMap()
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

// getFloatField safely extracts a float field from a map.
func getFloatField(m map[string]any, key string) float64 {
	if v, ok := m[key]; ok {
		switch f := v.(type) {
		case float64:
			return f
		case float32:
			return float64(f)
		case int64:
			return float64(f)
		case int:
			return float64(f)
		}
	}
	return 0.0
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
var mapStringAnyType = reflect.TypeOf(map[string]any{})

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
