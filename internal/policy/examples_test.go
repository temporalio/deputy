package policy

import (
	"encoding/json"
	"testing"
)

func TestGenerateExample_AllEntrypoints(t *testing.T) {
	// Test that we can generate examples for all registered entrypoints
	for ep := range BindingProfiles {
		t.Run(string(ep), func(t *testing.T) {
			example, err := GenerateExample(ep, ExampleLevelTypical)
			if err != nil {
				t.Fatalf("GenerateExample(%s, typical): %v", ep, err)
			}

			if example.Entrypoint != ep {
				t.Errorf("entrypoint mismatch: got %s, want %s", example.Entrypoint, ep)
			}

			if example.JSON == "" {
				t.Error("JSON output is empty")
			}

			// Verify JSON is valid
			var parsed map[string]any
			if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
				t.Errorf("invalid JSON: %v", err)
			}

			// Verify required variables are present
			profile := GetBindingProfile(ep)
			for _, varName := range profile.Required {
				if _, ok := parsed[varName]; !ok {
					t.Errorf("required variable %q missing from output", varName)
				}
			}
		})
	}
}

func TestGenerateExample_Levels(t *testing.T) {
	ep := EntrypointScanVulnerability

	tests := []struct {
		level    ExampleLevel
		wantVars []string // variables that should be present
	}{
		{
			level:    ExampleLevelMinimal,
			wantVars: []string{"vulnerability", "pkg", "env"},
		},
		{
			level:    ExampleLevelTypical,
			wantVars: []string{"vulnerability", "pkg", "env"},
		},
		{
			level:    ExampleLevelComprehensive,
			wantVars: []string{"vulnerability", "pkg", "env", "target", "image", "image_info"},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			example, err := GenerateExample(ep, tt.level)
			if err != nil {
				t.Fatalf("GenerateExample: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			for _, varName := range tt.wantVars {
				if _, ok := parsed[varName]; !ok {
					t.Errorf("expected variable %q missing at level %s", varName, tt.level)
				}
			}
		})
	}
}

func TestGenerateExample_VulnerabilityStructure(t *testing.T) {
	example, err := GenerateExample(EntrypointScanVulnerability, ExampleLevelTypical)
	if err != nil {
		t.Fatalf("GenerateExample: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check vulnerability structure
	vuln, ok := parsed["vulnerability"].(map[string]any)
	if !ok {
		t.Fatal("vulnerability is not a map")
	}

	// Check advisory_id
	if _, ok := vuln["advisory_id"].(string); !ok {
		t.Error("vulnerability.advisory_id should be a string")
	}

	// Check advisory structure
	advisory, ok := vuln["advisory"].(map[string]any)
	if !ok {
		t.Fatal("vulnerability.advisory is not a map")
	}

	// Check severity uses numeric enum (critical = 4)
	severity, ok := advisory["severity"].(map[string]any)
	if !ok {
		t.Fatal("vulnerability.advisory.severity is not a map")
	}

	level, ok := severity["level"].(float64) // JSON numbers are float64
	if !ok {
		t.Error("severity.level should be a number (enum value)")
	}
	if level != 4 { // SEVERITY_LEVEL_CRITICAL = 4
		t.Errorf("severity.level = %v, want 4 (CRITICAL)", level)
	}

	// Check package structure
	pkg, ok := vuln["package"].(map[string]any)
	if !ok {
		t.Fatal("vulnerability.package is not a map")
	}

	if _, ok := pkg["name"].(string); !ok {
		t.Error("vulnerability.package.name should be a string")
	}
	if _, ok := pkg["ecosystem"].(string); !ok {
		t.Error("vulnerability.package.ecosystem should be a string")
	}
	if _, ok := pkg["direct"].(bool); !ok {
		t.Error("vulnerability.package.direct should be a bool")
	}
}

func TestGenerateExample_EnvStructure(t *testing.T) {
	tests := []struct {
		ep          Entrypoint
		wantCommand string
	}{
		{EntrypointScanVulnerability, "scan"},
		{EntrypointScanReport, "scan"},
		{EntrypointGoArtifactRequest, "proxy"},
		{EntrypointNpmArtifactRequest, "proxy"},
		{EntrypointDiffReport, "diff"},
		{EntrypointGraphReport, "graph"},
		{EntrypointSecretsReport, "secrets"},
		{EntrypointServiceScanRequest, "server"},
		{EntrypointSandboxExecution, "sandbox"},
		{EntrypointFixPlan, "fix"},
		{EntrypointTriageReport, "triage"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ep), func(t *testing.T) {
			example, err := GenerateExample(tt.ep, ExampleLevelMinimal)
			if err != nil {
				t.Fatalf("GenerateExample: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			env, ok := parsed["env"].(map[string]any)
			if !ok {
				t.Fatal("env is not a map")
			}

			command, _ := env["command"].(string)
			if command != tt.wantCommand {
				t.Errorf("env.command = %q, want %q", command, tt.wantCommand)
			}

			entrypoint, _ := env["entrypoint"].(string)
			if entrypoint != string(tt.ep) {
				t.Errorf("env.entrypoint = %q, want %q", entrypoint, tt.ep)
			}
		})
	}
}

func TestGenerateExample_ProxyRequest(t *testing.T) {
	tests := []struct {
		ep            Entrypoint
		wantEcosystem string
	}{
		{EntrypointGoArtifactRequest, "go"},
		{EntrypointNpmArtifactRequest, "npm"},
		{EntrypointPypiArtifactRequest, "pypi"},
		{EntrypointRubygemsArtifactRequest, "rubygems"},
		{EntrypointOCIArtifactRequest, "oci"},
	}

	for _, tt := range tests {
		t.Run(string(tt.ep), func(t *testing.T) {
			example, err := GenerateExample(tt.ep, ExampleLevelTypical)
			if err != nil {
				t.Fatalf("GenerateExample: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			req, ok := parsed["request"].(map[string]any)
			if !ok {
				t.Fatal("request is not a map")
			}

			ecosystem, _ := req["ecosystem"].(string)
			if ecosystem != tt.wantEcosystem {
				t.Errorf("request.ecosystem = %q, want %q", ecosystem, tt.wantEcosystem)
			}

			// All proxy requests should have package and version
			if _, ok := req["package"].(string); !ok {
				t.Error("request.package should be a string")
			}
			if _, ok := req["version"].(string); !ok {
				t.Error("request.version should be a string")
			}
		})
	}
}

func TestGenerateExample_ComprehensiveEnrichment(t *testing.T) {
	example, err := GenerateExample(EntrypointScanVulnerability, ExampleLevelComprehensive)
	if err != nil {
		t.Fatalf("GenerateExample: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	vuln, _ := parsed["vulnerability"].(map[string]any)

	// Check EPSS enrichment fields
	if _, ok := vuln["epss"]; !ok {
		t.Error("comprehensive example should include epss")
	}
	if _, ok := vuln["epss_percentile"]; !ok {
		t.Error("comprehensive example should include epss_percentile")
	}

	// Check KEV enrichment fields
	if _, ok := vuln["in_kev"]; !ok {
		t.Error("comprehensive example should include in_kev")
	}
	if _, ok := vuln["kev_date_added"]; !ok {
		t.Error("comprehensive example should include kev_date_added")
	}

	// Check graph fields
	if _, ok := vuln["path"]; !ok {
		t.Error("comprehensive example should include path")
	}
	if _, ok := vuln["depth"]; !ok {
		t.Error("comprehensive example should include depth")
	}
}

func TestGenerateExample_UnknownEntrypoint(t *testing.T) {
	_, err := GenerateExample(Entrypoint("unknown_entrypoint"), ExampleLevelTypical)
	if err == nil {
		t.Error("expected error for unknown entrypoint")
	}
}

func TestListEntrypoints(t *testing.T) {
	eps := ListEntrypoints()
	if len(eps) == 0 {
		t.Error("ListEntrypoints returned empty list")
	}

	// Check they're sorted
	for i := 1; i < len(eps); i++ {
		if string(eps[i-1]) >= string(eps[i]) {
			t.Errorf("entrypoints not sorted: %s >= %s", eps[i-1], eps[i])
		}
	}
}

func TestExampleCategories(t *testing.T) {
	if len(ExampleCategories) == 0 {
		t.Error("ExampleCategories is empty")
	}

	// Check all categories have entrypoints
	for _, cat := range ExampleCategories {
		if cat.Name == "" {
			t.Error("category has empty name")
		}
		if len(cat.Entrypoints) == 0 {
			t.Errorf("category %q has no entrypoints", cat.Name)
		}
	}

	// Check GetCategoryForEntrypoint
	cat := GetCategoryForEntrypoint(EntrypointScanVulnerability)
	if cat == nil {
		t.Error("GetCategoryForEntrypoint returned nil for scan_vulnerability")
	}
	if cat != nil && cat.Name != "scan" {
		t.Errorf("scan_vulnerability category = %q, want 'scan'", cat.Name)
	}
}

func TestGenerateExample_JSONRoundTrip(t *testing.T) {
	// Ensure generated JSON can be parsed and re-serialized identically
	for ep := range BindingProfiles {
		t.Run(string(ep), func(t *testing.T) {
			example, err := GenerateExample(ep, ExampleLevelTypical)
			if err != nil {
				t.Fatalf("GenerateExample: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(example.JSON), &parsed); err != nil {
				t.Fatalf("first unmarshal: %v", err)
			}

			// Re-marshal and unmarshal
			data, err := json.Marshal(parsed)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var reparsed map[string]any
			if err := json.Unmarshal(data, &reparsed); err != nil {
				t.Fatalf("second unmarshal: %v", err)
			}

			// Check key structure is preserved
			if len(parsed) != len(reparsed) {
				t.Errorf("key count changed: %d -> %d", len(parsed), len(reparsed))
			}
		})
	}
}
