package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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
		ep      Entrypoint
		wantCat string
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
		{EntrypointSecretsReport, "secrets"},
		{EntrypointGraphReport, "graph"},
		{EntrypointServiceScanRequest, "server"},
		{EntrypointSandboxExecution, "sandbox"},
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

func TestCapabilitiesReferenceEntrypointCategories(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "reference", "capabilities.md")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", docPath, err)
	}

	byName := make(map[string]Entrypoint, len(AllEntrypoints))
	for _, ep := range AllEntrypoints {
		byName[ep.String()] = ep
	}
	seen := make(map[Entrypoint]bool, len(AllEntrypoints))

	for line := range strings.SplitSeq(string(data), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		ep, ok := byName[name]
		if !ok {
			continue
		}
		seen[ep] = true
		if got, want := strings.TrimSpace(cells[2]), ep.Category(); got != want {
			t.Fatalf("capabilities.md category for %s = %q, want %q", ep, got, want)
		}
	}

	for _, ep := range AllEntrypoints {
		if !seen[ep] {
			t.Fatalf("capabilities.md is missing policy entrypoint %s", ep)
		}
	}
}

func TestNormalizeCategory(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"scan", "scan"},
		{" Scan ", "scan"},
		{"container_diff", "container_diff"},
		{"container", "container_diff"},
		{"service", "server"},
		{"server", "server"},
		{"sandbox", "sandbox"},
		{"exec", "sandbox"},
		{" Exec ", "sandbox"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeCategory(tt.in); got != tt.want {
			t.Fatalf("NormalizeCategory(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"scan", "scan"},
		{" Scan ", "scan"},
		{"sandbox", "sandbox"},
		{"exec", "sandbox"},
		{" Exec ", "sandbox"},
		{"unknown", "unknown"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeCommand(tt.in); got != tt.want {
			t.Fatalf("NormalizeCommand(%q) = %q, want %q", tt.in, got, tt.want)
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
	for _, cmd := range []string{"proxy", "scan", "diff", "sbom", "fix", "triage", "secrets", "graph", "server", "sandbox", "exec"} {
		if !IsAllowedCommand(cmd) {
			t.Fatalf("expected %s to be allowed", cmd)
		}
	}
	if IsAllowedCommand("unknown_cmd") {
		t.Fatalf("expected unknown_cmd to be rejected")
	}
}

func TestCanonicalCommands(t *testing.T) {
	commands := CanonicalCommands()
	for _, want := range []string{"proxy", "scan", "diff", "sbom", "fix", "triage", "secrets", "graph", "server", "sandbox"} {
		if !slices.Contains(commands, want) {
			t.Fatalf("CanonicalCommands() = %v, want %q", commands, want)
		}
	}
	if slices.Contains(commands, "exec") {
		t.Fatalf("CanonicalCommands() = %v, should not include legacy exec alias", commands)
	}

	commands[0] = "mutated"
	if got := CanonicalCommands()[0]; got == "mutated" {
		t.Fatal("CanonicalCommands returned mutable backing storage")
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
