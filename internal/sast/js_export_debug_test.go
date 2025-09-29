package sast

import (
	"context"
	"os"
	"testing"
)

func TestJavaScriptExportDetection(t *testing.T) {
	dir := t.TempDir()
	testCode := `
class VulnerableController {
  testMethod() {
    console.log('test');
  }
}

class SafeController {
  safeMethod() {
    console.log('safe');
  }
}

module.exports = { VulnerableController, SafeController };
`
	
	testFile := dir + "/export_test.js"
	err := os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "test", Root: dir},
		FS:         os.DirFS(dir),
	}

	dialect := NewJavaScriptDialect()
	ctx := context.Background()
	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		t.Fatalf("discover units: %v", err)
	}

	unit := units[0]
	if err := dialect.Prepare(ctx, unit); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower to IR: %v", err)
	}

	// Debug: Print all symbols to see what's being detected
	snapshot := pkg.Graph.Snapshot()
	
	t.Logf("Found %d symbols:", len(snapshot.Symbols()))
	for _, symbol := range snapshot.Symbols() {
		t.Logf("  Symbol: %s (kind: %s)", symbol.ID.String(), symbol.Kind)
		if symbol.Attributes != nil {
			for key, value := range symbol.Attributes {
				if key == "exported" || key == "entry_point" {
					t.Logf("    %s: %v", key, value)
				}
			}
		}
	}
	
	// Count exported symbols
	exportedCount := 0
	for _, symbol := range snapshot.Symbols() {
		if attrs := symbol.Attributes; attrs != nil {
			if isExported, exists := attrs["exported"]; exists {
				if isExportedBool, ok := isExported.(bool); ok && isExportedBool {
					exportedCount++
					t.Logf("Found exported symbol: %s", symbol.ID.String())
				}
			}
		}
	}
	
	t.Logf("Total exported symbols: %d", exportedCount)
}