package policy

import (
	"slices"
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
