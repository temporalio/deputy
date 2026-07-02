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
