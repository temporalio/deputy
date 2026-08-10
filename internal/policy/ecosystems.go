package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Canonical ecosystem contract
//
// Inventory, graph resolution, and OSV all carry ecosystem display names: "Go",
// "PyPI", "GitHub Actions", "crates.io". Policies must not have to guess which
// spelling reached them, so every ecosystem value in a CEL payload is rewritten
// to its canonical token (lowercase, hyphenated: "go", "pypi",
// "github-actions") before evaluation. Display names stay untouched in the
// protos Deputy renders; only what policy sees is normalized.

// UnknownVersion is the value Deputy puts in a policy payload when a request
// has no concrete version, such as a proxy metadata or index request. It is a
// sentinel rather than an empty string so a policy cannot treat a missing
// version as a match-all, and it is never run through version normalization.
const UnknownVersion = "<unknown>"

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
	for name, value := range payload {
		if !variableCarriesEcosystem(name) {
			continue
		}
		canonicalizeEcosystemValue(value)
	}
}

// freeFormStringMaps are payload fields whose keys and values are supplied by
// the caller rather than by a Deputy schema: JWT custom claims, container image
// labels, and policy annotations. An ecosystem-shaped key in one of those is
// somebody's data, not an ecosystem, and rewriting it would silently change
// what an exact-match rule compares against. The walk never descends into them.
var freeFormStringMaps = []string{"custom_claims", "labels", "annotations"}

// variableCarriesEcosystem reports whether a top-level policy variable may hold
// an ecosystem, so canonicalization stays on schema-defined paths. Variables
// with a proto-typed schema are answered from their descriptor, which keeps
// caller-controlled payloads such as jwt out of the walk without a hand-written
// exclusion list. Variables whose payload is untyped ("object" in the variable
// metadata, for example a scan report) are walked, since their shape is only
// known at runtime.
func variableCarriesEcosystem(name string) bool {
	meta, known := VariableInfo(name)
	if !known {
		return true
	}
	md, isProto := VariableMessageDescriptor(elementTypeName(meta.Type))
	if !isProto {
		return true
	}
	return messageCarriesEcosystem(md, map[protoreflect.FullName]bool{})
}

// elementTypeName unwraps the "list(T)" form used in variable metadata so a
// repeated variable resolves to the descriptor of its element type.
func elementTypeName(typeName string) string {
	if inner, ok := strings.CutPrefix(typeName, "list("); ok {
		return strings.TrimSuffix(inner, ")")
	}
	return typeName
}

// messageCarriesEcosystem reports whether a message, or anything reachable from
// it, declares an ecosystem field. The seen set makes recursive message graphs
// terminate.
func messageCarriesEcosystem(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) bool {
	if md == nil || seen[md.FullName()] {
		return false
	}
	seen[md.FullName()] = true
	fields := md.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		switch string(field.Name()) {
		case "ecosystem", "ecosystems":
			return true
		}
		if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
			if messageCarriesEcosystem(field.Message(), seen) {
				return true
			}
		}
	}
	return false
}

// canonicalizeEcosystemValue recursively canonicalizes ecosystem fields of any
// payload value, descending through maps and lists. A map's own ecosystem is
// resolved before its name and version fields, because the ecosystem selects
// which normalizer those fields get.
func canonicalizeEcosystemValue(value any) {
	switch v := value.(type) {
	case map[string]any:
		eco, ok := canonicalizeOwnEcosystem(v)
		if !ok {
			eco, ok = inheritedChangeEcosystem(v)
		}
		if ok {
			normalizeIdentityFields(v, eco)
		}
		for key, child := range v {
			switch {
			case key == "ecosystem":
				continue
			case key == "ecosystems":
				v[key] = canonicalizeEcosystemCollection(child)
				continue
			case slices.Contains(freeFormStringMaps, key):
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

// canonicalizeOwnEcosystem rewrites a map's own "ecosystem" field to its
// canonical token and returns the resolved ecosystem. ok is false when the map
// carries no ecosystem string.
func canonicalizeOwnEcosystem(m map[string]any) (eco ecosystem.Ecosystem, ok bool) {
	raw, isString := m["ecosystem"].(string)
	if !isString {
		return "", false
	}
	token := NormalizeEcosystem(raw)
	m["ecosystem"] = token
	if token == "" {
		return "", false
	}
	return ecosystem.Ecosystem(token), true
}

// inheritedChangeEcosystem resolves the ecosystem for a change shape, where the
// versions being compared sit next to a nested package rather than next to an
// ecosystem of their own (deputy.diff.v1.PackageChange and
// deputy.policy.v1.DependencyChange both look like this). It only applies to
// maps that actually hold change versions, so an unrelated payload that merely
// contains a package is left alone.
func inheritedChangeEcosystem(m map[string]any) (eco ecosystem.Ecosystem, ok bool) {
	if _, hasBase := m["base_version"]; !hasBase {
		if _, hasTarget := m["target_version"]; !hasTarget {
			return "", false
		}
	}
	for _, key := range []string{"package", "pkg"} {
		child, isMap := m[key].(map[string]any)
		if !isMap {
			continue
		}
		raw, isString := child["ecosystem"].(string)
		if !isString {
			continue
		}
		if token := NormalizeEcosystem(raw); token != "" {
			return ecosystem.Ecosystem(token), true
		}
	}
	return "", false
}

// packageNameKeys are the payload fields that hold a package name and so get
// the ecosystem's name normalization (PyPI names are case-insensitive, for
// example, so they are lowercased).
var packageNameKeys = []string{"name", "old_name"}

// packageVersionKeys are the payload fields that hold a single version string
// and so get the ecosystem's version normalization (Go versions gain the "v"
// prefix, so a policy can write "^v1\\." and match the diff path too).
var packageVersionKeys = []string{"version", "base_version", "target_version", "fixed_version"}

// normalizeIdentityFields applies the ecosystem's own name and version
// normalization to the identity fields of one payload object. Deputy already
// uses these normalizers when querying OSV and comparing packages; running them
// at the policy boundary is what makes a policy see the same identity the rest
// of the engine does.
func normalizeIdentityFields(m map[string]any, eco ecosystem.Ecosystem) {
	for _, key := range packageNameKeys {
		if name, ok := m[key].(string); ok && name != "" {
			m[key] = eco.NormalizeName(name)
		}
	}
	if !versionsAreConcrete(m) {
		return
	}
	for _, key := range packageVersionKeys {
		if version, ok := m[key].(string); ok {
			m[key] = normalizePayloadVersion(eco, version)
		}
	}
	if versions, ok := m["fixed_versions"].([]any); ok {
		for i, elem := range versions {
			if version, isString := elem.(string); isString {
				versions[i] = normalizePayloadVersion(eco, version)
			}
		}
	}
}

// versionsAreConcrete reports whether an object's version fields hold real
// versions. Proxy metadata and index requests carry [UnknownVersion] with
// has_version set to false; those must survive untouched so the documented
// sentinel stays comparable.
func versionsAreConcrete(m map[string]any) bool {
	hasVersion, present := m["has_version"].(bool)
	return !present || hasVersion
}

// normalizePayloadVersion applies the ecosystem's version normalization,
// leaving empty values and the unknown-version sentinel alone.
func normalizePayloadVersion(eco ecosystem.Ecosystem, version string) string {
	if version == "" || version == UnknownVersion {
		return version
	}
	return eco.NormalizeVersion(version)
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
