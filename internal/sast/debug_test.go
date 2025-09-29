package sast

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDebugRubySecurityRules(t *testing.T) {
	dir := t.TempDir()
	source := `class TestController
  def vulnerable_action
    user_input = params[:cmd]
    system("ls #{user_input}")
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

	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower to IR: %v", err)
	}

	// Debug output
	fmt.Printf("Found %d symbols:\n", len(pkg.Symbols))
	for _, symbol := range pkg.Symbols {
		fmt.Printf("  Symbol: %s (kind: %s)\n", symbol.ID.String(), symbol.Kind)
		if symbol.Attributes != nil {
			fmt.Printf("    Attributes: %+v\n", symbol.Attributes)
		}
	}

	snapshot := pkg.Graph.Snapshot()
	fmt.Printf("\nFound edges:\n")
	for _, symbol := range snapshot.Symbols() {
		edges := snapshot.OutgoingEdges(EdgeKindCall, symbol.ID)
		if len(edges) > 0 {
			fmt.Printf("  From %s:\n", symbol.ID.String())
			for _, edge := range edges {
				fmt.Printf("    -> %s (confidence: %s)\n", edge.To.String(), edge.Attributes.Confidence)
				if edge.Attributes.Metadata != nil {
					fmt.Printf("       Metadata: %+v\n", edge.Attributes.Metadata)
				}
			}
		}
	}
}