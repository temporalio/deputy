package sast

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDebugSecurityRuleApplication(t *testing.T) {
	dir := t.TempDir()
	source := `class TestController
  def vulnerable_action
    system("echo test")
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "controller.rb"), []byte(source), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "test", Root: dir},
		FS:         os.DirFS(dir),
	}

	dialect := NewRubyDialect()
	ctx := context.Background()
	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		t.Fatalf("discover units: %v", err)
	}

	unit := units[0]
	if err := dialect.Prepare(ctx, unit); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	// Let's inspect the parsed AST
	data, ok := unit.AST.(*rubyUnit)
	if !ok {
		t.Fatalf("unexpected AST type")
	}

	fmt.Printf("Found %d methods in AST:\n", len(data.methods))
	for _, method := range data.methods {
		fmt.Printf("  Method: %s.%s (calls: %d)\n", method.receiver, method.name, len(method.calls))
		for _, call := range method.calls {
			fmt.Printf("    Call: %s.%s", call.receiver, call.name)
			if call.metadata != nil {
				fmt.Printf(" [metadata: %+v]", call.metadata)
			}
			fmt.Printf("\n")
		}
	}

	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower to IR: %v", err)
	}

	// Check if our security rules have been applied
	snapshot := pkg.Graph.Snapshot()
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if edge.To.Name == "system" {
				fmt.Printf("Found system call edge with metadata: %+v\n", edge.Attributes.Metadata)
			}
		}
	}
}