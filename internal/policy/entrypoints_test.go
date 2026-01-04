package policy

import "testing"

func TestAllowedEntrypoints(t *testing.T) {
	for _, ep := range AllEntrypoints {
		if !ep.IsValid() {
			t.Fatalf("expected %s to be valid", ep)
		}
		if !IsAllowedEntrypoint(ep.String()) {
			t.Fatalf("expected %s to be allowed", ep)
		}
	}
	if IsAllowedEntrypoint("bogus_entrypoint") {
		t.Fatalf("expected bogus_entrypoint to be rejected")
	}
}

func TestEntrypointCategory(t *testing.T) {
	tests := []struct {
		ep       Entrypoint
		wantCat  string
	}{
		{EntrypointGoArtifactRequest, "proxy"},
		{EntrypointNpmArtifactRequest, "proxy"},
		{EntrypointScanReport, "scan"},
		{EntrypointScanVulnerability, "scan"},
		{EntrypointDiffReport, "diff"},
		{EntrypointContainerDiffReport, "container_diff"},
		{EntrypointSBOMReport, "sbom"},
		{EntrypointFixPlan, "fix"},
		{EntrypointTriageReport, "triage"},
		{EntrypointDockerfileReport, "dockerfile"},
	}
	for _, tt := range tests {
		if got := tt.ep.Category(); got != tt.wantCat {
			t.Errorf("%s.Category() = %q, want %q", tt.ep, got, tt.wantCat)
		}
	}

	// Ensure all entrypoints have a category
	for _, ep := range AllEntrypoints {
		if cat := ep.Category(); cat == "" {
			t.Errorf("%s has no category", ep)
		}
	}
}

func TestEntrypointIsValid(t *testing.T) {
	if Entrypoint("invalid_entrypoint").IsValid() {
		t.Error("expected invalid_entrypoint to not be valid")
	}
	if !EntrypointScanReport.IsValid() {
		t.Error("expected scan_report to be valid")
	}
}

func TestAllowedCommands(t *testing.T) {
	for _, cmd := range []string{"proxy", "scan", "diff", "sbom", "fix", "triage"} {
		if !IsAllowedCommand(cmd) {
			t.Fatalf("expected %s to be allowed", cmd)
		}
	}
	if IsAllowedCommand("unknown_cmd") {
		t.Fatalf("expected unknown_cmd to be rejected")
	}
}

func TestStructuredEntrypointValidation(t *testing.T) {
	yaml := `policies:
  - name: bad-entrypoint
    entrypoints: ["not_real"]
    rules:
      - action: deny
        when: true
`
	if _, ok, err := tryParseStructuredBundle([]byte(yaml), "inline"); err == nil || ok {
		t.Fatalf("expected error for invalid entrypoint")
	}

	yamlCmd := `policies:
  - name: bad-command
    commands: ["not_real"]
    rules:
      - action: deny
        when: true
`
	if _, ok, err := tryParseStructuredBundle([]byte(yamlCmd), "inline"); err == nil || ok {
		t.Fatalf("expected error for invalid command")
	}
}
