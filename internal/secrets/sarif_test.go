package secrets

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/sarif"
)

func TestSARIFReport_Generate(t *testing.T) {
	findings := []Finding{
		{
			Type:        TypeGitHubToken,
			Description: "GitHub Personal Access Token (classic)",
			File:        "config/secrets.go",
			Line:        42,
			Column:      15,
			Value:       "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			Redacted:    "[REDACTED:github_token:ghp_...]",
			Confidence:  0.99,
		},
		{
			Type:        TypeAWSAccessKey,
			Description: "AWS Access Key ID",
			File:        "main.go",
			Line:        10,
			Column:      1,
			Value:       "AKIAIOSFODNN7EXAMPLE",
			Redacted:    "[REDACTED:aws_access_key:AKIA...]",
			Confidence:  0.95,
			Validated:   true,
		},
	}

	opts := DefaultSARIFOptions()
	opts.ToolVersion = "1.2.3"
	report := NewSARIFReport(opts)
	sarifLog := report.Generate(findings)

	// Verify structure
	if sarifLog.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarifLog.Version)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarifLog.Runs))
	}

	run := sarifLog.Runs[0]

	// Verify tool info
	if run.Tool.Driver.Name != "Deputy" {
		t.Errorf("expected tool name 'Deputy', got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("expected tool version '1.2.3', got %s", run.Tool.Driver.Version)
	}

	// Verify rules
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules (one per unique secret type), got %d", len(run.Tool.Driver.Rules))
	}

	// Verify results
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	// Check first result (GitHub token)
	r0 := run.Results[0]
	if r0.RuleID != "secret/github_token" {
		t.Errorf("expected rule ID 'secret/github_token', got %s", r0.RuleID)
	}
	if r0.Level != "error" { // High confidence = error
		t.Errorf("expected level 'error' for high confidence, got %s", r0.Level)
	}
	if len(r0.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "config/secrets.go" {
		t.Errorf("unexpected URI: %s", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("expected line 42, got %d", r0.Locations[0].PhysicalLocation.Region.StartLine)
	}

	// Check second result (validated AWS key)
	r1 := run.Results[1]
	if r1.Level != "error" { // Validated = always error
		t.Errorf("expected level 'error' for validated secret, got %s", r1.Level)
	}
	if !strings.Contains(r1.Message.Text, "verified active") {
		t.Errorf("expected message to contain 'verified active', got %s", r1.Message.Text)
	}

	// Verify CWE taxonomy included
	if len(run.Taxonomies) != 1 {
		t.Errorf("expected 1 taxonomy (CWE), got %d", len(run.Taxonomies))
	}
	if run.Taxonomies[0].Name != "CWE" {
		t.Errorf("expected taxonomy name 'CWE', got %s", run.Taxonomies[0].Name)
	}
}

func TestSARIFReport_Write(t *testing.T) {
	findings := []Finding{
		{
			Type:       TypeHighEntropy,
			File:       "test.txt",
			Line:       1,
			Confidence: 0.65, // Low confidence
		},
	}

	report := NewSARIFReport(DefaultSARIFOptions())
	var buf strings.Builder
	err := report.Write(&buf, findings)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed sarif.Log
	if err := json.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	// Verify low confidence = note level
	if len(parsed.Runs) > 0 && len(parsed.Runs[0].Results) > 0 {
		if parsed.Runs[0].Results[0].Level != "note" {
			t.Errorf("expected level 'note' for low confidence, got %s", parsed.Runs[0].Results[0].Level)
		}
	}
}

func TestFindingsToSARIF(t *testing.T) {
	findings := []Finding{
		{
			Type:       TypePrivateKey,
			File:       "/abs/path/key.pem",
			Line:       1,
			Confidence: 0.99,
		},
	}

	jsonStr, err := FindingsToSARIF(findings, WithToolVersion("2.0.0"), WithBaseURI("/abs/path"))
	if err != nil {
		t.Fatalf("FindingsToSARIF failed: %v", err)
	}

	// Should have relative path after base URI stripping
	if !strings.Contains(jsonStr, `"uri": "key.pem"`) {
		t.Errorf("expected relative URI 'key.pem' in output, got: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"version": "2.0.0"`) {
		t.Errorf("expected version 2.0.0 in output")
	}
}

func TestSARIF_EmptyFindings(t *testing.T) {
	report := NewSARIFReport(DefaultSARIFOptions())
	sarifLog := report.Generate([]Finding{})

	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 run even with no findings")
	}
	if len(sarifLog.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarifLog.Runs[0].Results))
	}
	if len(sarifLog.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules when no findings, got %d", len(sarifLog.Runs[0].Tool.Driver.Rules))
	}
}

func TestSARIF_JSONSchema(t *testing.T) {
	findings := []Finding{
		{Type: TypeGitHubToken, File: "test.go", Line: 1, Confidence: 0.9},
	}

	jsonStr, err := FindingsToSARIF(findings)
	if err != nil {
		t.Fatal(err)
	}

	// Verify schema is included
	if !strings.Contains(jsonStr, `"$schema": "https://json.schemastore.org/sarif-2.1.0.json"`) {
		t.Error("SARIF schema URI not found in output")
	}
}
