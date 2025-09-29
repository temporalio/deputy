package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Helper function to check for vulnerability metadata in graph
func checkVulnerabilityMetadata(pkg *IRPackage, vulnType string) (bool, map[string]any) {
	snapshot := pkg.Graph.Snapshot()
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if edge.Attributes.Metadata != nil {
				if vType, ok := edge.Attributes.Metadata["vulnerability_type"]; ok && vType == vulnType {
					return true, edge.Attributes.Metadata
				}
			}
		}
	}
	return false, nil
}

// Helper function to check for specific metadata keys
func checkMetadataKey(pkg *IRPackage, key string, expectedValue any) int {
	count := 0
	snapshot := pkg.Graph.Snapshot()
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if edge.Attributes.Metadata != nil {
				if value, ok := edge.Attributes.Metadata[key]; ok && value == expectedValue {
					count++
				}
			}
		}
		// Also check symbol attributes
		if symbol.Attributes != nil {
			if value, ok := symbol.Attributes[key]; ok && value == expectedValue {
				count++
			}
		}
	}
	return count
}

func TestRubySecurityRulesCommandInjection(t *testing.T) {
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

	// Check for command injection metadata
	found, metadata := checkVulnerabilityMetadata(pkg, "command_injection")
	if !found {
		t.Error("expected command injection vulnerability to be detected")
	} else {
		if severity, ok := metadata["severity"]; !ok || severity != "high" {
			t.Error("expected high severity for command injection")
		}
		if cwe, ok := metadata["cwe"]; !ok || cwe != "CWE-78" {
			t.Error("expected CWE-78 for command injection")
		}
	}
}

func TestRubySecurityRulesSqlInjection(t *testing.T) {
	dir := t.TempDir()
	source := `class UserController
  def search
    term = params[:search]
    User.where("name = '#{term}'")
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "user_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for SQL injection metadata
	found, metadata := checkVulnerabilityMetadata(pkg, "sql_injection")
	if !found {
		t.Error("expected SQL injection vulnerability to be detected")
	} else {
		if cwe, ok := metadata["cwe"]; !ok || cwe != "CWE-89" {
			t.Error("expected CWE-89 for SQL injection")
		}
	}
}

func TestRubySecurityRulesCodeInjection(t *testing.T) {
	dir := t.TempDir()
	source := `class EvalController
  def dangerous
    code = params[:code]
    eval(code)
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "eval_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for code injection metadata
	found, metadata := checkVulnerabilityMetadata(pkg, "code_injection")
	if !found {
		t.Error("expected code injection vulnerability to be detected")
	} else {
		if severity, ok := metadata["severity"]; !ok || severity != "critical" {
			t.Error("expected critical severity for code injection")
		}
		if cwe, ok := metadata["cwe"]; !ok || cwe != "CWE-94" {
			t.Error("expected CWE-94 for code injection")
		}
	}
}

func TestRubySecurityRulesXSS(t *testing.T) {
	dir := t.TempDir()
	source := `class HomeController
  def show
    content = params[:content]
    render html: "<div>#{content}</div>".html_safe
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "home_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for XSS metadata
	found, metadata := checkVulnerabilityMetadata(pkg, "xss")
	if !found {
		t.Error("expected XSS vulnerability to be detected")
	} else {
		if cwe, ok := metadata["cwe"]; !ok || cwe != "CWE-79" {
			t.Error("expected CWE-79 for XSS")
		}
	}
}

func TestRubySecurityRulesPathTraversal(t *testing.T) {
	dir := t.TempDir()
	source := `class FileController
  def read_file
    filename = params[:file]
    File.read(filename)
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "file_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for path traversal metadata
	found, metadata := checkVulnerabilityMetadata(pkg, "path_traversal")
	if !found {
		t.Error("expected path traversal vulnerability to be detected")
	} else {
		if cwe, ok := metadata["cwe"]; !ok || cwe != "CWE-22" {
			t.Error("expected CWE-22 for path traversal")
		}
	}
}

func TestRubySecurityRulesTaintSources(t *testing.T) {
	dir := t.TempDir()
	source := `class ApiController
  def process_data
    user_data = params[:data]
    cookies_data = cookies[:session]
    env_data = ENV['CONFIG']
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "api_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for taint source metadata
	taintSources := checkMetadataKey(pkg, "taint_source", true)
	if taintSources == 0 {
		t.Error("expected taint sources to be detected")
	}
}

func TestRubySecurityRulesSanitizers(t *testing.T) {
	dir := t.TempDir()
	source := `class SafeController
  def safe_output
    user_input = params[:input]
    escaped = html_escape(user_input)
    clean_sql = ActiveRecord::Base.sanitize_sql(user_input)
    safe_shell = Shellwords.escape(user_input)
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "safe_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for sanitizer metadata
	sanitizers := checkMetadataKey(pkg, "sanitizer", true)
	if sanitizers == 0 {
		t.Error("expected sanitizers to be detected")
	}
}

func TestRubySecurityRulesDeserialization(t *testing.T) {
	dir := t.TempDir()
	source := `class DeserializeController
  def unsafe_load
    data = params[:yaml_data]
    YAML.load(data)
    Marshal.load(data)
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "deserialize_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for deserialization vulnerability metadata
	found, metadata := checkVulnerabilityMetadata(pkg, "unsafe_deserialization")
	if !found {
		t.Error("expected unsafe deserialization vulnerability to be detected")
	} else {
		if severity, ok := metadata["severity"]; !ok || severity != "critical" {
			t.Error("expected critical severity for unsafe deserialization")
		}
		if cwe, ok := metadata["cwe"]; !ok || cwe != "CWE-502" {
			t.Error("expected CWE-502 for unsafe deserialization")
		}
	}
}

func TestRubySecurityRulesControllerDetection(t *testing.T) {
	dir := t.TempDir()
	source := `class UsersController < ApplicationController
  def show
    # Controller action
  end
end`

	if err := os.WriteFile(filepath.Join(dir, "users_controller.rb"), []byte(source), 0o644); err != nil {
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

	// Check for controller action metadata
	controllerActions := checkMetadataKey(pkg, "controller_action", true)
	entryPoints := checkMetadataKey(pkg, "entry_point", true)

	if controllerActions == 0 {
		t.Error("expected controller action to be detected")
	}
	if entryPoints == 0 {
		t.Error("expected entry points to be detected")
	}
}
