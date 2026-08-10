package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
)

// Canonical ecosystem contract
//
// Inventory, graph resolution, and OSV all carry ecosystem display names: "Go",
// "PyPI", "GitHub Actions", "crates.io". Policies must not have to guess which
// spelling reached them, so every ecosystem value in a CEL payload is rewritten
// to its canonical token (lowercase, hyphenated: "go", "pypi",
// "github-actions") before evaluation. Display names stay untouched in the
// protos Deputy renders; only what policy sees is normalized.

// NormalizeEcosystem returns the canonical token policies compare against for
// an author- or scanner-supplied ecosystem name, resolving aliases and casing
// ("Go", "golang" -> "go"; "GitHub Actions" -> "github-actions"). Names Deputy
// does not recognize are still lowercased and hyphenated so comparisons stay
// stable. Use [IsAllowedEcosystem] first when the name must be a known one.
func NormalizeEcosystem(name string) string {
	return ecosystem.CanonicalOrRaw(name)
}

// IsAllowedEcosystem reports whether name resolves to an ecosystem Deputy
// knows, accepting any alias or casing. It is the load-time gate for the
// "ecosystems:" key of a structured policy bundle, mirroring
// [IsAllowedEntrypoint] and [IsAllowedCommand].
func IsAllowedEcosystem(name string) bool {
	return ecosystem.IsCanonical(name)
}

// AllowedEcosystems returns the sorted canonical ecosystem tokens a policy may
// name, for validation errors and authoring tools.
func AllowedEcosystems() []string {
	return ecosystem.CanonicalEcosystems()
}

// ProxyEntrypoint returns the artifact-request entrypoint for an ecosystem
// (e.g. "go" -> [EntrypointGoArtifactRequest]). The ecosystem name is
// canonicalized first so aliases and display casing resolve to the same
// entrypoint. It returns an empty Entrypoint when the ecosystem has no
// artifact-request entrypoint.
func ProxyEntrypoint(eco string) Entrypoint {
	token := NormalizeEcosystem(eco)
	if token == "" {
		return ""
	}
	ep := Entrypoint(token + "_artifact_request")
	if !ep.IsValid() {
		return ""
	}
	return ep
}

// validateEcosystems canonicalizes an author-supplied ecosystem list, rejecting
// unknown values and dropping duplicates that different aliases collapse into.
// Order is preserved so generated CEL guards stay stable for a given source.
func validateEcosystems(ecosystems []string) ([]string, error) {
	if len(ecosystems) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(ecosystems))
	seen := make(map[string]struct{}, len(ecosystems))
	for _, eco := range ecosystems {
		if !IsAllowedEcosystem(eco) {
			return nil, fmt.Errorf("invalid ecosystem %q (expected one of: %s)", eco, strings.Join(AllowedEcosystems(), ", "))
		}
		normalized := NormalizeEcosystem(eco)
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

// canonicalizeEcosystemPayload rewrites every ecosystem value in a CEL payload
// to its canonical token so a policy sees one spelling regardless of which
// scanner produced the data. It walks the payload in place, which is safe
// because callers hand it a payload freshly materialized from protos (see
// [ProtoToMap]) or already cloned.
//
// Three shapes carry ecosystems in Deputy's payloads:
//
//   - "ecosystem": a single name (pkg, request, node, change, component, ...)
//   - "ecosystems": a list of names (scan/diff/graph request options)
//   - "ecosystems": a map keyed by ecosystem (graph and SBOM stats counts)
func canonicalizeEcosystemPayload(payload map[string]any) {
	canonicalizeEcosystemValue(payload)
}

// canonicalizeEcosystemValue recursively canonicalizes ecosystem fields of any
// payload value, descending through maps and lists.
func canonicalizeEcosystemValue(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			switch key {
			case "ecosystem":
				if name, ok := child.(string); ok {
					v[key] = NormalizeEcosystem(name)
					continue
				}
			case "ecosystems":
				v[key] = canonicalizeEcosystemCollection(child)
				continue
			}
			canonicalizeEcosystemValue(child)
		}
	case []any:
		for _, elem := range v {
			canonicalizeEcosystemValue(elem)
		}
	}
}

// canonicalizeEcosystemCollection canonicalizes the ecosystem names held by an
// "ecosystems" field, which is either a list of names or a map keyed by name.
// Keys that collapse onto the same token have their counts summed so a
// display-cased and a canonical spelling of one ecosystem cannot be reported
// twice; non-numeric duplicates keep the value of the lowest raw key so the
// result does not depend on map iteration order.
func canonicalizeEcosystemCollection(value any) any {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			if name, ok := elem.(string); ok {
				out[i] = NormalizeEcosystem(name)
				continue
			}
			canonicalizeEcosystemValue(elem)
			out[i] = elem
		}
		return out
	case []string:
		out := make([]string, len(v))
		for i, name := range v {
			out[i] = NormalizeEcosystem(name)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, key := range slices.Sorted(maps.Keys(v)) {
			token := NormalizeEcosystem(key)
			child := v[key]
			canonicalizeEcosystemValue(child)
			if existing, dup := out[token]; dup {
				if sum, ok := addNumeric(existing, child); ok {
					out[token] = sum
				}
				continue
			}
			out[token] = child
		}
		return out
	default:
		canonicalizeEcosystemValue(value)
		return value
	}
}

// addNumeric adds two payload numbers, reporting false when either side is not
// numeric. Payload counts arrive as float64 or json.Number depending on whether
// [convertJSONNumbers] has run, so both are handled.
func addNumeric(a, b any) (any, bool) {
	af, aok := numericValue(a)
	bf, bok := numericValue(b)
	if !aok || !bok {
		return nil, false
	}
	return af + bf, true
}

// numericValue converts a payload number to float64, reporting false for
// values that are not numeric.
func numericValue(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
