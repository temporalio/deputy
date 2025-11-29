package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// Ensure raw CEL files still bypass structured bundle parsing.
func TestRawCELPassthrough(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "raw.cel")
	src := `//! policy.name = "raw"
true ? [{"action":"warn","reason":"raw"}] : []`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write raw cel: %v", err)
	}
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources raw: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
}
