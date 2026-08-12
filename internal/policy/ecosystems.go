package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/proto/descriptorset"
	"github.com/temporalio/deputy/internal/purlx"
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
//
// A package URL is a fourth shape, and it answers a different question, so it
// gets a second pass. Rewriting an ecosystem or a name needs to know which
// ecosystem's rules apply, and only a schema that declares one can say; a
// package URL says so itself. See [canonicalizePackageReferences].
func canonicalizeEcosystemPayload(payload map[string]any) {
	for name, value := range payload {
		if variableCarriesEcosystem(name) {
			// Each top-level variable is its own object; nothing outside it
			// can name its ecosystem, so the walk starts with none inherited.
			canonicalizeEcosystemValue(value, "")
		}
		if !isCallerExtendedVariable(name) {
			payload[name] = canonicalizePackageReferences(value)
		}
	}
}

// isFreeFormMap reports whether a payload key holds opaque key/value data
// rather than a schema-described object: JWT custom claims, container image
// labels, target provenance, an advisory's source-specific metadata. An
// ecosystem- or version-shaped entry in one of those is somebody's data, not a
// package identity, and rewriting it would silently change what an exact-match
// rule compares against. The walk never descends into them.
//
// The set is derived from the proto descriptors, where those fields are
// declared as maps with scalar values, so a new free-form map is covered the
// day it is added instead of the day someone remembers to extend a list. The
// ecosystem-keyed count maps ("ecosystems") are also scalar maps, so callers
// must resolve that key before consulting this.
func isFreeFormMap(key string) bool {
	return descriptorset.IsScalarMapField(key)
}

// callerExtendedVariables names the top-level payload variables whose schema
// stops describing their payload before evaluation, with the reason it stops.
// [flattenJWTCustomClaims] promotes a token's custom_claims onto the jwt object,
// so any key there is a claim the token's issuer chose: a claim named
// "ecosystem" is somebody's data, and rewriting "Customer_Success" to
// "customer-success" silently stopped an exact-match deny rule from firing.
//
// Nothing else in a payload needs naming here. A nested free-form map is
// recognized from the descriptors by [isFreeFormMap], and a variable with no
// proto type is a schema-described report Deputy itself builds. The entry is
// keyed to the flattening it describes so a second flattener has one obvious
// place to declare itself.
var callerExtendedVariables = map[string]string{
	"jwt": "flattenJWTCustomClaims promotes issuer-chosen claims onto the jwt object",
}

// isCallerExtendedVariable reports whether a top-level policy variable carries
// keys its proto schema does not describe, which is the one case the
// canonicalization walk must stay out of entirely.
//
// Everything else is walked. Gating instead on "does this variable's schema
// mention an ecosystem" read as the safer rule and was not: graph edges name
// their endpoints by package URL and declare no ecosystem, so the gate kept the
// walk out of them and left "edge.to" spelling a package differently from the
// node it points at.
func isCallerExtendedVariable(name string) bool {
	_, extended := callerExtendedVariables[name]
	return extended
}

// variableCarriesEcosystem reports whether a top-level policy variable's schema
// declares an ecosystem anywhere in it, so a variable that arrives beside a
// package rather than inside one (env, target, jwt) can be told apart from one
// that carries package identities.
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
//
// An object names its ecosystem in one of four ways, tried from the most
// specific to the least: an "ecosystem" field of its own, a nested package that
// has one, its own package URL, or the ecosystem of the object that contains it.
//
// inherited is that last one. An object that does not identify an ecosystem at
// all belongs to the one that contains it: an advisory's fixed versions are
// versions of the finding's package, and the finding names the ecosystem
// through that package. An object with an ecosystem of its own overrides the
// inherited one for itself and everything below it.
func canonicalizeEcosystemValue(value any, inherited ecosystem.Ecosystem) {
	switch v := value.(type) {
	case map[string]any:
		eco, ok := canonicalizeOwnEcosystem(v)
		if !ok {
			eco, ok = nestedPackageEcosystem(v)
		}
		if !ok {
			eco, ok = packageURLEcosystem(v)
		}
		if !ok && inherited != "" {
			eco, ok = inherited, true
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
			case isFreeFormMap(key):
				continue
			}
			canonicalizeEcosystemValue(child, eco)
		}
	case []any:
		for _, elem := range v {
			canonicalizeEcosystemValue(elem, inherited)
		}
	}
}

// canonicalizePackageReferences rewrites the package URLs a payload carries as
// references to a package rather than as one package's own identity. Graph data
// is full of them: an edge names its endpoints by purl, the roots list names the
// direct dependencies by purl, and a finding's path is a chain of them. None of
// those objects declares an ecosystem, so the ecosystem walk never reaches them,
// and a node whose purl gained a "v" prefix stopped matching the roots entry and
// the edge that pointed at it. A rule as ordinary as "node.purl in roots" then
// reads two identities where there is one.
//
// This pass asks a different question from the ecosystem walk and so runs under
// a different rule. Rewriting an ecosystem, a name, or a version needs to know
// which ecosystem's rules apply, and only a schema that declares one can say. A
// package URL says so itself, so a reference needs no schema support at all,
// only a value that parses. What it does need is to stay off payload data
// Deputy did not put there, which is why it skips free-form maps and the
// variables a caller extends.
//
// The "purl" field is left to [normalizeIdentityFields]: it spells the identity
// of the object that carries it, and that object's own ecosystem decides how to
// fold it, which is the stricter rule. A package whose ecosystem is Cargo but
// whose purl is a pkg:github reference must come back untouched.
//
// It returns the value to store in place of the one it was given, because not
// every list can be rewritten through the reference it arrived by. A repeated
// proto field reaches the walk as []any, but a payload a caller assembled itself
// commonly carries []string: "deputy scan --input" injects the scanned SBOM's
// PURLs that way, and the graph entrypoints name the direct dependencies that way
// in "roots". Descending into map[string]any and []any alone skipped those lists
// whole, so a policy comparing a package against the list it belongs to read two
// spellings of one identity. A []string comes back as a new slice: the engine's
// payload clone is shallow and [convertProtosInMap] passes a scalar slice through
// by reference, so the list a caller still holds must not be rewritten under it.
//
// A typed string map (map[string]string) is deliberately not descended into. That
// is the shape caller- and source-supplied data arrives in, and the
// descriptor-derived [isFreeFormMap] skip cannot see inside a map keyed by an
// arbitrary string, so rewriting there would risk exactly the caller data this
// pass is careful to leave alone.
func canonicalizePackageReferences(value any) any {
	switch v := value.(type) {
	case string:
		return canonicalizePackageReference(v)
	case map[string]any:
		for key, child := range v {
			if isFreeFormMap(key) || slices.Contains(packagePURLKeys, key) {
				continue
			}
			v[key] = canonicalizePackageReferences(child)
		}
		return v
	case []any:
		for i, elem := range v {
			v[i] = canonicalizePackageReferences(elem)
		}
		return v
	case []string:
		out := make([]string, len(v))
		for i, raw := range v {
			out[i] = canonicalizePackageReference(raw)
		}
		return out
	default:
		return value
	}
}

// canonicalizePackageReference canonicalizes one package URL against the
// ecosystem the URL itself names. Resolving the ecosystem through
// [ecosystem.FromPURLType] is what makes this safe to apply to any string
// instead of to a list of field names that would go stale the next time a
// message grows one: a value is only rewritten when it parses as a package URL
// whose type a registration claims, and it is then folded by that ecosystem's
// own rules rather than by an inherited guess. Everything else, including a
// package URL of a type Deputy has no rules for, comes back byte for byte.
//
// Whether a string is a package URL is the parser's answer, not a prefix test's.
// The purl scheme is case-insensitive and [purlx.ParseLoose] also tolerates
// surrounding whitespace, so a byte-exact "pkg:" test called
// "PKG:golang/example.com/mod@1.2.3" prose while [canonicalizePURL] canonicalized
// the same string as an identity. A rule as ordinary as "node.purl in roots" was
// then false for no reason but the casing of a scheme.
func canonicalizePackageReference(raw string) string {
	parsed, err := purlx.ParseLoose(raw)
	if err != nil {
		return raw
	}
	eco, known := ecosystem.FromPURLType(parsed.Type)
	if !known {
		return raw
	}
	return canonicalizePURL(raw, eco)
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

// nestedPackageEcosystem resolves the ecosystem of an object that identifies
// its package through a nested one rather than through an ecosystem field of
// its own. A change carries the versions being compared next to the package
// they belong to (deputy.diff.v1.PackageChange, deputy.policy.v1.
// DependencyChange), and a finding carries its advisory next to the affected
// package (deputy.vulnerability.v1.Finding).
func nestedPackageEcosystem(m map[string]any) (eco ecosystem.Ecosystem, ok bool) {
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

// packageURLEcosystem resolves the ecosystem of an object that spells its own
// identity as a package URL and names no ecosystem anywhere: a remediation step
// is the case that needs it, since deputy.fix.v1.RemediationCommand carries the
// package it fixes, that package's URL, and the versions on both sides of the
// fix, and declares no ecosystem field at all. With nothing to resolve, identity
// normalization never ran for a fix plan, so a Go step reached policies as
// "1.44.0" beside a target version of "v1.44.1" and a deny written against the
// canonical identity did not fire.
//
// A package URL answers the question itself, which is what makes this safe
// without schema support ([canonicalizePackageReference] relies on the same
// property). Resolution goes through [ecosystem.FromPURLType], so a URL of a
// type no registration claims leaves the object unresolved rather than folded by
// a guessed ecosystem's rules.
//
// The PURL is deliberately not consulted before an ecosystem field: an object
// that declares one is stating which rules apply to it, and a package whose
// ecosystem is Cargo may legitimately carry a pkg:github reference as its URL.
func packageURLEcosystem(m map[string]any) (eco ecosystem.Ecosystem, ok bool) {
	for _, key := range packagePURLKeys {
		raw, isString := m[key].(string)
		if !isString || raw == "" {
			continue
		}
		parsed, err := purlx.ParseLoose(raw)
		if err != nil {
			continue
		}
		if eco, known := ecosystem.FromPURLType(parsed.Type); known {
			return eco, true
		}
	}
	return "", false
}

// packageNameKeys are the payload fields that hold a package name and so get
// the ecosystem's name normalization (PyPI names are case-insensitive, for
// example, so they are lowercased). Deputy's schemas spell the same identity
// several ways: a package or change calls it "name", a proxy request calls it
// "package" or "module", a container vulnerability change calls it
// "package_name". A policy that reads one alias must not see a different string
// than a policy that reads another, so all of them are normalized. A migration
// verdict names the module to move to in "target_module", which is the same
// identity a package fix spells "module".
// TestIdentityKeysCoverSchema derives the field list from the proto descriptors
// and fails when a message grows an unclassified one.
var packageNameKeys = []string{"name", "old_name", "package", "module", "package_name", "target_module"}

// packageVersionKeys are the payload fields that hold a single version string
// and so get the ecosystem's version normalization (Go versions gain the "v"
// prefix, so a policy can write "^v1\\." and match the diff path too). The
// repeated form, "fixed_versions", is normalized element by element in
// [normalizeIdentityFields].
//
// A version that sits beside another spelling of itself has to be here too, or
// the two compare unequal for a policy that reads both: an unverified fix
// verdict repeats its version in "claimed", an SBOM package change carries
// "previous_version" and "new_version", and a freshness signal carries
// "current_version" next to the "latest_version" it is behind.
var packageVersionKeys = []string{
	"version",
	"base_version",
	"target_version",
	"fixed_version",
	"claimed",
	"previous_version",
	"new_version",
	"current_version",
	"latest_version",
	"latest_prerelease",
}

// packagePURLKeys are the payload fields that hold a complete Package URL for
// the object's own package. A PURL spells the same identity the name and
// version fields carry, so it is canonicalized with them by
// [canonicalizePURL]: a policy that reads purl(pkg.purl) must not see a
// different package than one that reads pkg.name and pkg.version.
var packagePURLKeys = []string{"purl"}

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
	for _, key := range packagePURLKeys {
		if raw, ok := m[key].(string); ok && raw != "" {
			m[key] = canonicalizePURL(raw, eco)
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
	if versions, present := m[packageVersionListKey]; present {
		m[packageVersionListKey] = normalizeVersionList(versions, eco)
	}
}

// packageVersionListKey is the one repeated version field a payload object
// carries, an advisory's fixed versions. It is normalized element by element by
// [normalizeVersionList] rather than in the scalar loop above.
// TestIdentityKeysCoverSchema classifies it with the scalar version keys, so a
// second repeated version field cannot appear unclassified.
const packageVersionListKey = "fixed_versions"

// normalizeVersionList normalizes a repeated version field and returns a new
// value, leaving anything that is not a list of versions untouched.
//
// Both shapes a payload carries it in are handled. A proto's repeated field
// reaches the walk as []any, and a payload a caller assembled itself (the map
// surface, [Engine.EvaluateAllMap]) commonly carries []string. Only the first was
// normalized, so a hand-built payload gave a policy "1.44.1" in fixed_versions
// beside a "v1.44.0" in the version field next to it, and the canonical identity
// contract held for one of the two.
//
// The result is a fresh slice because the payload the walk rewrites is not
// wholly its own: the engine's clone is shallow, and while [convertProtosInMap]
// rebuilds every map[string]any and []any on the way in, a []string is a scalar
// slice it passes through by reference. Normalizing that in place would rewrite a
// slice the caller still holds, which is a worse bug than the one being fixed.
func normalizeVersionList(value any, eco ecosystem.Ecosystem) any {
	switch versions := value.(type) {
	case []any:
		out := make([]any, len(versions))
		for i, elem := range versions {
			out[i] = elem
			if version, isString := elem.(string); isString {
				out[i] = normalizePayloadVersion(eco, version)
			}
		}
		return out
	case []string:
		out := make([]string, len(versions))
		for i, version := range versions {
			out[i] = normalizePayloadVersion(eco, version)
		}
		return out
	default:
		return value
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

// canonicalizePURL rewrites the name and version components of a PURL with the
// same normalizers the object's name and version fields get, so both spellings
// of one identity agree. Everything else about the PURL, its namespace,
// qualifiers, and subpath, is carried through untouched.
//
// The PURL is only rewritten when it parses and when its type is the one the
// ecosystem projects to ([ecosystem.PURLType]), which is what keeps the wrong
// ecosystem's folding rules off a PURL that names something else: a package
// whose ecosystem is Cargo but whose PURL is a pkg:github reference is left
// exactly as it arrived, as is a PURL Deputy cannot parse. A PURL that is
// already canonical keeps its original string byte for byte, so re-encoding
// never becomes a rewrite of its own.
//
// What a policy reads is the string, so the decision to rewrite compares
// strings. Comparing parsed components instead was the subtle version of this
// bug: the purl library folds a pypi name itself while parsing, so the
// components of "pkg:pypi/Flask_SQLAlchemy@3.1.1" already read
// "flask-sqlalchemy", the comparison found nothing to do, and the string kept a
// spelling no other field in the payload used.
//
// Adopting the library's re-encoding is only safe where Deputy defines a fold
// of its own ([ecosystem.Ecosystem.NormalizesNames]), because there the library
// implements the same published rule. Everywhere else its parse is lossy in a
// direction Deputy rejects: it lowercases a golang namespace, and Go import
// paths are case-sensitive, so re-encoding a Go PURL that needed no
// canonicalization would replace this bug with the same bug in another
// ecosystem. Those keep their bytes unless canonicalization actually changed a
// component.
//
// A Go PURL that does get rewritten, because its version gained the prefix,
// comes back with the lowercase namespace the purl spec mandates for the golang
// type. No string is both a canonical PURL and a case-sensitive import path
// there, so the two spellings are reconciled by parsing rather than by
// inventing a PURL the spec does not describe.
func canonicalizePURL(raw string, eco ecosystem.Ecosystem) string {
	purlType := ecosystem.PURLType(eco)
	if purlType == "" {
		return raw
	}
	parsed, err := purlx.ParseLoose(raw)
	if err != nil || !strings.EqualFold(parsed.Type, purlType) {
		return raw
	}
	name := eco.NormalizeName(parsed.Name)
	version := normalizePayloadVersion(eco, parsed.Version)
	componentsChanged := name != parsed.Name || version != parsed.Version
	parsed.Name = name
	parsed.Version = version
	canonical := parsed.ToString()
	if canonical == raw {
		return raw
	}
	if componentsChanged || eco.NormalizesNames() {
		return canonical
	}
	return raw
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
			canonicalizeEcosystemValue(elem, "")
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
			canonicalizeEcosystemValue(child, "")
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
		canonicalizeEcosystemValue(value, "")
		return value
	}
}

// addNumeric adds two payload numbers, reporting false when either side is not
// numeric. Payload counts arrive as int64, float64, or json.Number depending on
// the source schema and on whether [convertJSONNumbers] has run, so all are
// handled.
//
// The sum keeps the numeric type of its inputs. Count maps are declared
// map<string, int32> (deputy.policy.v1.GraphStats, deputy.sbom.v1), so CEL sees
// an int for every key that needed no merge; widening a merged key to a double
// would make "stats.ecosystems[eco] + 1" fail with a missing double/int
// overload, and only for the ecosystems whose spellings happened to collide.
// Summing as float64 only when an input is already fractional keeps the
// opposite error, narrowing a genuine double to an int, off the table too.
func addNumeric(a, b any) (any, bool) {
	if ai, aok := integralValue(a); aok {
		if bi, bok := integralValue(b); bok {
			return ai + bi, true
		}
	}
	af, aok := numericValue(a)
	bf, bok := numericValue(b)
	if !aok || !bok {
		return nil, false
	}
	return af + bf, true
}

// integralValue converts a payload number to int64, reporting false for values
// that are not numeric and for ones that carry a fractional part or are already
// a floating-point value. A float64 is deliberately not integral even when it
// holds a whole number: it reached the payload as a double and has to stay one.
//
// The int64 sum in [addNumeric] cannot overflow for the payloads this serves,
// whose counts are declared int32.
func integralValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
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
