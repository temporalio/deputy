package sast

import (
	"context"
	"os"
	"testing"
)

func TestRubyComprehensiveSecurityAnalysis(t *testing.T) {
	testFile := "../../testdata/ruby/comprehensive_security_test.rb"

	// Create a temporary directory and copy the test file
	dir := t.TempDir()
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	testFileInDir := dir + "/comprehensive_security_test.rb"
	err = os.WriteFile(testFileInDir, content, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file to temp dir: %v", err)
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

	if len(units) == 0 {
		t.Fatalf("No units discovered")
	}

	unit := units[0]
	if err := dialect.Prepare(ctx, unit); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	pkg, err := dialect.LowerToIR(ctx, unit)
	if err != nil {
		t.Fatalf("lower to IR: %v", err)
	}

	// Count different types of vulnerabilities
	vulnCounts := map[string]int{
		"command_injection":      0,
		"sql_injection":          0,
		"xss":                    0,
		"path_traversal":         0,
		"code_injection":         0,
		"unsafe_deserialization": 0,
	}

	// Count taint sources
	taintSources := 0

	// Analyze the graph for vulnerabilities
	snapshot := pkg.Graph.Snapshot()
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if metadata := edge.Attributes.Metadata; metadata != nil {
				if vulnType, exists := metadata["vulnerability_type"]; exists {
					if vulnTypeStr, ok := vulnType.(string); ok {
						if count, found := vulnCounts[vulnTypeStr]; found {
							vulnCounts[vulnTypeStr] = count + 1
						}
					}
				}
				if isTaint, exists := metadata["taint_source"]; exists {
					if isTaintBool, ok := isTaint.(bool); ok && isTaintBool {
						taintSources++
					}
				}
			}
		}
	}

	// Verify we detected expected vulnerabilities
	expectedVulns := map[string]int{
		"command_injection":      2, // We should find at least 2 instances
		"sql_injection":          2, // We should find at least 2 instances
		"xss":                    2, // We should find at least 2 instances
		"path_traversal":         1, // We should find at least 1 instance
		"code_injection":         1, // We should find at least 1 instance
		"unsafe_deserialization": 1, // We should find at least 1 instance
	}

	for vulnType, expected := range expectedVulns {
		actual := vulnCounts[vulnType]
		if actual < expected {
			t.Errorf("Expected at least %d %s vulnerabilities, found %d", expected, vulnType, actual)
		}
	}

	// We should detect multiple taint sources (params, cookies, session, env)
	if taintSources < 3 {
		t.Errorf("Expected at least 3 taint sources, found %d", taintSources)
	}

	// Check that we identified controller actions properly
	controllerActions := 0
	for _, symbol := range snapshot.Symbols() {
		if attrs := symbol.Attributes; attrs != nil {
			if isController, exists := attrs["controller_action"]; exists {
				if isControllerBool, ok := isController.(bool); ok && isControllerBool {
					controllerActions++
				}
			}
		}
	}

	if controllerActions < 6 {
		t.Errorf("Expected at least 6 controller actions, found %d", controllerActions)
	}

	// Verify sanitizer detection
	sanitizers := 0
	for _, symbol := range snapshot.Symbols() {
		for _, edge := range snapshot.OutgoingEdges(EdgeKindCall, symbol.ID) {
			if metadata := edge.Attributes.Metadata; metadata != nil {
				if isSanitizer, exists := metadata["sanitizer"]; exists {
					if isSanitizerBool, ok := isSanitizer.(bool); ok && isSanitizerBool {
						sanitizers++
					}
				}
			}
		}
	}

	if sanitizers < 1 {
		t.Errorf("Expected at least 1 sanitizer, found %d", sanitizers)
	}

	t.Logf("Successfully detected vulnerabilities: %+v", vulnCounts)
	t.Logf("Detected %d taint sources, %d controller actions, %d sanitizers",
		taintSources, controllerActions, sanitizers)
}
