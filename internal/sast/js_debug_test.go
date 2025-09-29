package sast

import (
	"context"
	"os"
	"testing"
)

func TestJavaScriptDialectParsing(t *testing.T) {
	dir := t.TempDir()
	testCode := `
// Test function declarations
function testFunction() {
  console.log('test');
}

const arrowFunction = () => {
  return 'arrow';
};

// Test exports
export function exportedFunction() {
  return 'exported';
}

module.exports = { testFunction };

// Test calls
eval('dangerous code');
exec('ls -la');
Function('return 1 + 1')();
mysql.query('SELECT * FROM users');
`

	testFile := dir + "/debug_parsing.js"
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

	// Debug: Print all symbols and edges
	snapshot := pkg.Graph.Snapshot()

	t.Logf("Found %d symbols:", len(snapshot.Symbols()))
	for _, symbol := range snapshot.Symbols() {
		t.Logf("  Symbol: %s (kind: %s)", symbol.ID.String(), symbol.Kind)
		if symbol.Attributes != nil {
			for key, value := range symbol.Attributes {
				t.Logf("    %s: %v", key, value)
			}
		}
	}

	t.Logf("\nFound edges:")
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			t.Logf("  Edge: %s -> %s", edge.From.String(), edge.To.String())
			if edge.Attributes.Metadata != nil {
				for key, value := range edge.Attributes.Metadata {
					t.Logf("    %s: %v", key, value)
				}
			}
		}
	}
}
