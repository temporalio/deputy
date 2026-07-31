package policy

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestEveryBindingVariableHasMetadata ensures the single metadata source stays
// complete: every variable declared by any BindingProfile must have explicit
// type and description metadata, so the API, MCP tool, and LSP never fall back
// to the generic "object" descriptor for a real, catalogued variable.
func TestEveryBindingVariableHasMetadata(t *testing.T) {
	seen := make(map[string]bool)
	for ep, prof := range BindingProfiles {
		for _, name := range slices.Concat(prof.Required, prof.Optional) {
			if seen[name] {
				continue
			}
			seen[name] = true
			meta, ok := VariableInfo(name)
			if !ok {
				t.Errorf("variable %q (used by entrypoint %q) has no metadata in variableMetadataByName", name, ep)
				continue
			}
			if meta.Type == "" || meta.Description == "" {
				t.Errorf("variable %q has incomplete metadata: %+v", name, meta)
			}
		}
	}
}

// TestVariableMetadataEntriesAreComplete guards the table itself against empty
// fields regardless of binding usage.
func TestVariableMetadataEntriesAreComplete(t *testing.T) {
	for name, meta := range variableMetadataByName {
		if meta.Type == "" || meta.Description == "" {
			t.Errorf("variable metadata for %q is incomplete: %+v", name, meta)
		}
	}
}

// protoTypeNamePattern matches the versioned-package proto type names used in
// variable metadata, e.g. "dependencyv1.Package" or "list(graphv1.Node)" after
// the list wrapper is stripped.
var protoTypeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*v\d+\.[A-Z]`)

// TestProtoTypedVariableMetadataResolves keeps variableMetadataByName and
// variableMessageTypes in sync in both directions: every metadata type that
// claims to be proto-backed must resolve to a registered descriptor (a type
// name that resolves nowhere renders as documentation for a type that does not
// exist, and LSP completions silently fall back to nothing), and every
// registered descriptor must be referenced by at least one variable so the map
// cannot accumulate dead entries. It also pins each key's message name to its
// descriptor to catch copy-paste mismatches.
func TestProtoTypedVariableMetadataResolves(t *testing.T) {
	referenced := make(map[string]bool)
	for name, meta := range variableMetadataByName {
		typ := meta.Type
		if inner, isList := strings.CutPrefix(typ, "list("); isList {
			typ = strings.TrimSuffix(inner, ")")
		}
		if !protoTypeNamePattern.MatchString(typ) {
			continue
		}
		referenced[typ] = true
		if _, ok := VariableMessageDescriptor(typ); !ok {
			t.Errorf("variable %q declares proto type %q with no descriptor in variableMessageTypes; register it or use a non-proto type name", name, typ)
		}
	}
	for key, md := range variableMessageTypes {
		if !referenced[key] {
			t.Errorf("variableMessageTypes entry %q is referenced by no variable metadata; remove it or add the variable", key)
		}
		wantName := key[strings.LastIndex(key, ".")+1:]
		if got := string(md.Name()); got != wantName {
			t.Errorf("variableMessageTypes[%q] maps to descriptor %q; key and message name must agree", key, got)
		}
	}
}

// TestVariableFieldCompletionsFromProto verifies completions come from proto
// descriptors (snake_case field names, the CEL contract) for proto-typed
// variables, including nested paths and list element types, and decline for
// object-typed variables so callers fall back to hand lists.
func TestVariableFieldCompletionsFromProto(t *testing.T) {
	fields, ok := VariableFieldCompletions("pkg")
	if !ok {
		t.Fatal("pkg should resolve via proto descriptors")
	}
	for _, want := range []string{"name", "version", "ecosystem", "purl", "direct", "manifest_refs"} {
		if !slices.Contains(fields, want) {
			t.Errorf("pkg completions missing proto field %q: %v", want, fields)
		}
	}

	// List-typed variables complete their element type.
	if fields, ok := VariableFieldCompletions("vulnerabilities"); !ok || !slices.Contains(fields, "advisory_id") {
		t.Errorf("vulnerabilities should complete Finding fields (snake_case), got ok=%v %v", ok, fields)
	}

	// The base variable resolves via proto and exposes its message fields.
	if fields, ok := VariableFieldCompletions("target"); !ok || !slices.Contains(fields, "effective_ref") {
		t.Errorf("target should complete Target fields, got ok=%v %v", ok, fields)
	}
	// Map-typed nested paths decline (a map has keys, not proto fields), so
	// hand-maintained conventional-key lists still apply.
	if _, ok := VariableFieldCompletions("target.provenance"); ok {
		t.Error("map-typed path should not resolve via proto")
	}

	// Object-typed variables decline, so hand-maintained lists still apply.
	if _, ok := VariableFieldCompletions("report"); ok {
		t.Error("object-typed variable should not resolve via proto")
	}
	if _, ok := VariableFieldCompletions("no-such-var"); ok {
		t.Error("unknown variable should not resolve")
	}
}
