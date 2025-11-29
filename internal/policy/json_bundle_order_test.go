package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Ensure JSON bundles (v1alpha1) are parsed deterministically and coexist with structured bundles.
func TestJSONBundleDeterministicOrder(t *testing.T) {
	tmp := t.TempDir()
	raw := Bundle{
		SchemaVersion: bundleSchemaVersion,
		Policies: []BundlePolicy{
			{Name: "p1", Source: `//! policy.name = "p1"
true ? [{"action":"warn"}] : []`},
		},
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jsonPath := filepath.Join(tmp, "bundle.json")
	if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
		t.Fatalf("write json bundle: %v", err)
	}

	// structured bundle (ordered vars) alongside raw CEL
	structuredPath := filepath.Join(tmp, "struct.yaml")
	structured := `apiVersion: policy.deputy.sh/v1alpha2
kind: PolicyBundle
policies:
  - name: structured
    vars:
      a: "1"
      b: "a + 1"
    rules:
      - action: deny
        when: b == 2
`
	if err := os.WriteFile(structuredPath, []byte(structured), 0o644); err != nil {
		t.Fatalf("write structured: %v", err)
	}
	rawCel := filepath.Join(tmp, "raw.cel")
	if err := os.WriteFile(rawCel, []byte(`true ? [{"action":"warn"}] : []`), 0o644); err != nil {
		t.Fatalf("write raw cel: %v", err)
	}

	sources, err := LoadSources([]string{jsonPath, structuredPath, rawCel})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	if len(sources) != 3 {
		t.Fatalf("expected 3 sources, got %d", len(sources))
	}
	for _, src := range sources {
		if err := Compile(src.Body, []string{"a", "b"}); err != nil {
			t.Fatalf("compile %s: %v", src.Name, err)
		}
	}
}
