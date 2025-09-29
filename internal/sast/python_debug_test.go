package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPythonDebugAnalysis(t *testing.T) {
	// Create a simple test file to debug the analysis process
	dir := t.TempDir()
	pythonContent := `
import os

def debug_function():
    user_input = input("Enter command: ")
    os.system(f"echo {user_input}")
    return user_input

def safe_function():
    return "hello world"

if __name__ == "__main__":
    debug_function()
`
	if err := os.WriteFile(filepath.Join(dir, "debug.py"), []byte(pythonContent), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{FS: os.DirFS(dir)}
	dialect := NewPythonDialect()

	units, err := dialect.DiscoverUnits(context.Background(), target)
	if err != nil {
		t.Fatalf("Failed to discover units: %v", err)
	}

	err = dialect.Prepare(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to prepare unit: %v", err)
	}

	irPkg, err := dialect.LowerToIR(context.Background(), units[0])
	if err != nil {
		t.Fatalf("Failed to lower to IR: %v", err)
	}

	t.Logf("Debug Analysis Results:")
	t.Logf("  Unit path: %s", units[0].Path)
	t.Logf("  Unit files: %v", units[0].Files)
	t.Logf("  Source length: %d bytes", len(units[0].Source))
	t.Logf("  Symbols generated: %d", len(irPkg.Symbols))
	t.Logf("  Entry points: %d", len(irPkg.Entrypoints))

	// Debug symbols
	t.Log("Symbols:")
	for i, symbol := range irPkg.Symbols {
		t.Logf("  [%d] %s: %s (kind: %s)", i, symbol.ID.String(), symbol.Display, symbol.Kind)
		if symbol.Attributes != nil {
			for key, value := range symbol.Attributes {
				t.Logf("    %s: %v", key, value)
			}
		}
	}

	// Debug entry points
	t.Log("Entry points:")
	for i, entrypoint := range irPkg.Entrypoints {
		t.Logf("  [%d] %s", i, entrypoint.String())
	}

	// Debug call edges
	snapshot := irPkg.Graph.Snapshot()
	t.Log("Call edges:")
	edgeCount := 0
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			edgeCount++
			t.Logf("  %s -> %s", edge.From.String(), edge.To.String())
			if edge.Attributes.Metadata != nil {
				for key, value := range edge.Attributes.Metadata {
					t.Logf("    %s: %v", key, value)
				}
			}
		}
	}
	t.Logf("Total call edges: %d", edgeCount)

	// Check for expected vulnerabilities
	cmdInjCount := countPythonVulnerabilities(irPkg, "command_injection")
	taintCount := countPythonVulnerabilities(irPkg, "taint_source")

	t.Logf("Vulnerabilities found:")
	t.Logf("  Command injection: %d", cmdInjCount)
	t.Logf("  Taint sources: %d", taintCount)

	// Verify basic expectations
	if len(irPkg.Symbols) == 0 {
		t.Error("Expected symbols to be generated")
	}

	if cmdInjCount == 0 {
		t.Error("Expected to find command injection vulnerability")
	}

	if taintCount == 0 {
		t.Error("Expected to find taint source")
	}
}