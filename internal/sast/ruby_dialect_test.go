package sast

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRubyDialectPipeline(t *testing.T) {
	dir := t.TempDir()
	source := `def main
  helper
end

def helper
  vulnerable
end

def vulnerable
end
`
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(source), 0o644); err != nil {
		t.Fatalf("write app.rb: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "ruby", Root: dir},
		FS:         os.DirFS(dir),
	}

	dialect := NewRubyDialect()
	if !dialect.Supports(target) {
		t.Fatal("expected ruby dialect to support target")
	}

	ctx := context.Background()
	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		t.Fatalf("discover units: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("expected 1 unit, got %d", len(units))
	}

	unit := units[0]
	if err := dialect.Prepare(ctx, unit); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(unit.Tokens) == 0 {
		t.Fatal("expected tokens to be produced")
	}

	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower to IR: %v", err)
	}
	if len(pkg.Symbols) < 3 {
		t.Fatalf("expected symbols for methods, got %d", len(pkg.Symbols))
	}

	var hasVulnerable bool
	for _, sym := range pkg.Symbols {
		if sym.ID.Name == "vulnerable" {
			hasVulnerable = true
			break
		}
	}
	if !hasVulnerable {
		t.Fatal("expected vulnerable method symbol present")
	}
	if len(pkg.Entrypoints) == 0 {
		t.Fatal("expected entrypoints to include main")
	}
}

func TestRubyEngineReachability(t *testing.T) {
	dir := t.TempDir()
	source := `def main
  helper
end

def helper
  vulnerable
end

def vulnerable
end
`
	if err := os.WriteFile(filepath.Join(dir, "app.rb"), []byte(source), 0o644); err != nil {
		t.Fatalf("write app.rb: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "ruby", Root: dir},
		FS:         os.DirFS(dir),
	}

	registry := NewSymbolRegistry()
	registry.Register(SymbolHint{
		Vulnerability: "RUBY-TEST",
		Dialect:       "ruby",
		Package:       ".",
		Name:          "vulnerable",
		Receiver:      "Object",
	})

	engine := NewEngine(WithDialect(NewRubyDialect()), WithSymbolRegistry(registry))
	report, err := engine.AnalyzeReachability(context.Background(), target, []string{"RUBY-TEST"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected single finding, got %d", len(report.Findings))
	}
	finding := report.Findings[0]
	if !finding.Reachable {
		t.Fatalf("expected vulnerable reachable")
	}
	if len(finding.Path) < 2 {
		t.Fatalf("expected path to include entrypoint and target, got %d", len(finding.Path))
	}

	registry.Register(SymbolHint{
		Vulnerability: "RUBY-UNREACHABLE",
		Dialect:       "ruby",
		Package:       ".",
		Name:          "ghost",
		Receiver:      "Object",
	})
	report, err = engine.AnalyzeReachability(context.Background(), target, []string{"RUBY-UNREACHABLE"})
	if err != nil {
		t.Fatalf("analyze second: %v", err)
	}
	if report.Findings[0].Reachable {
		t.Fatal("expected ghost to be unreachable")
	}
}

func TestRubyDSLHeuristics(t *testing.T) {
	dir := t.TempDir()
	code := `class PostsController
  def configure
    before_action :authenticate
  end

  def authenticate
  end

  def index
    authenticate
  end
end
`
	if err := os.WriteFile(filepath.Join(dir, "controller.rb"), []byte(code), 0o644); err != nil {
		t.Fatalf("write controller.rb: %v", err)
	}
	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "dsl", Root: dir},
		FS:         os.DirFS(dir),
	}
	dialect := NewRubyDialect()
	ctx := context.Background()
	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		t.Fatalf("discover units: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("expected 1 unit, got %d", len(units))
	}
	unit := units[0]
	if err := dialect.Prepare(ctx, unit); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	snapshot := pkg.Graph.Snapshot()
	configureID := SymbolID{Dialect: "ruby", Package: unit.Path, Name: "configure", Recv: "PostsController"}
	var hasCallback bool
	for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, configureID) {
		if edge.Attributes.Metadata != nil {
			if _, ok := edge.Attributes.Metadata["rails_callback"]; ok {
				hasCallback = true
				break
			}
		}
	}
	if !hasCallback {
		t.Fatalf("expected rails callback metadata on authenticate edges")
	}
}

func TestRubyIntegrationTemporal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}

	dir := t.TempDir()
	repoDir := filepath.Join(dir, "sdk-ruby")
	cmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/temporalio/sdk-ruby", repoDir)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		t.Skipf("git clone failed: %v", err)
	}

	target := &Target{
		Descriptor: TargetDescriptor{Kind: TargetKindRepository, Name: "sdk-ruby", Root: repoDir},
		FS:         os.DirFS(repoDir),
	}

	dialect := NewRubyDialect()
	if !dialect.Supports(target) {
		t.Fatal("expected ruby dialect to support temporal sdk")
	}

	ctx := context.Background()
	units, err := dialect.DiscoverUnits(ctx, target)
	if err != nil {
		t.Fatalf("discover units: %v", err)
	}
	if len(units) == 0 {
		t.Fatal("expected units for temporal sdk")
	}

	graph := NewGraph()
	totalSymbols := 0
	for _, unit := range units {
		if err := dialect.Prepare(ctx, unit); err != nil {
			t.Fatalf("prepare %s: %v", unit.Path, err)
		}
		pkg, err := dialect.LowerToIR(ctx, unit)
		if err != nil {
			t.Fatalf("lower %s: %v", unit.Path, err)
		}
		totalSymbols += len(pkg.Symbols)
		graph.Merge(pkg.Graph)
	}

	if totalSymbols < 500 {
		t.Fatalf("expected rich symbol set, got %d", totalSymbols)
	}

	snapshot := graph.Snapshot()
	wanted := "Temporalio::Workflow.start_child_workflow"
	found := false
	for _, sym := range snapshot.Symbols() {
		if sym.Display == wanted {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to discover symbol %s", wanted)
	}
}
