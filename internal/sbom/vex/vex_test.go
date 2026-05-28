package vex

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestStatus(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusAffected, "affected"},
		{StatusNotAffected, "not_affected"},
		{StatusFixed, "fixed"},
		{StatusUnderInvestigation, "under_investigation"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.status)
		}
	}
}

func TestJustification(t *testing.T) {
	tests := []struct {
		j        Justification
		expected string
	}{
		{JustificationComponentNotPresent, "component_not_present"},
		{JustificationVulnerableCodeNotPresent, "vulnerable_code_not_present"},
		{JustificationVulnerableCodeNotInExecutePath, "vulnerable_code_not_in_execute_path"},
	}

	for _, tt := range tests {
		if string(tt.j) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.j)
		}
	}
}

func TestFromScanResult(t *testing.T) {
	result := scanning.Result{
		Target: inventory.Target{
			DisplayPath: "github.com/example/repo",
		},
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-1234",
				Dependency: dependency.ID{Name: "example.com/vulnerable", Ecosystem: "Go"},
				Version:    "v1.0.0",
				Direct:     true,
				Affected:   true,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"CVE-2024-1234": {
				Id:            "CVE-2024-1234",
				Summary:       "Test vulnerability",
				FixedVersions: []string{"v1.0.1"},
			},
		},
	}

	opts := DefaultOptions()
	doc := FromScanResult(result, opts)

	if doc == nil {
		t.Fatal("expected non-nil document")
	}

	if doc.Author != "deputy" {
		t.Errorf("expected author 'deputy', got %s", doc.Author)
	}

	if doc.Version != "0.2.0" {
		t.Errorf("expected version '0.2.0', got %s", doc.Version)
	}

	if len(doc.Statements) == 0 {
		t.Error("expected at least one statement")
	}
}

func TestFromScanResultEmpty(t *testing.T) {
	result := scanning.Result{
		Target: inventory.Target{
			DisplayPath: "empty-project",
		},
		Findings:   []vulnerability.Finding{},
		Advisories: map[string]*vulnerabilityv1.Advisory{},
	}

	doc := FromScanResult(result, DefaultOptions())

	if doc == nil {
		t.Fatal("expected non-nil document")
	}

	if len(doc.Statements) != 0 {
		t.Errorf("expected 0 statements for empty scan, got %d", len(doc.Statements))
	}
}

func TestWriteOpenVEX(t *testing.T) {
	doc := &Document{
		Context:     "https://openvex.dev/ns/v0.2.0",
		ID:          "test:vex:1",
		Author:      "test",
		Timestamp:   time.Now().UTC(),
		Version:     "0.2.0",
		ToolVersion: "0.0.0-test",
		Statements: []Statement{
			{
				VulnerabilityID: "CVE-2024-1234",
				Status:          StatusAffected,
				Products:        []string{"pkg:golang/example.com/test@v1.0.0"},
				Timestamp:       time.Now().UTC(),
			},
		},
	}

	var buf bytes.Buffer
	err := Write(&buf, doc, FormatOpenVEX)
	if err != nil {
		t.Fatalf("failed to write OpenVEX: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check required fields
	if parsed["@context"] == nil {
		t.Error("missing @context field")
	}
	if parsed["author"] != "test" {
		t.Errorf("expected author 'test', got %v", parsed["author"])
	}
}

func TestWriteCycloneDXVEX(t *testing.T) {
	doc := &Document{
		ID:          "test:vex:cdx",
		Author:      "test",
		Timestamp:   time.Now().UTC(),
		Version:     "0.2.0",
		ToolVersion: "0.0.0-test",
		Statements: []Statement{
			{
				VulnerabilityID: "CVE-2024-5678",
				Status:          StatusNotAffected,
				Justification:   JustificationVulnerableCodeNotInExecutePath,
				ImpactStatement: "The vulnerable code path is not reachable",
				Products:        []string{"pkg:npm/lodash@4.17.21"},
				Timestamp:       time.Now().UTC(),
			},
		},
	}

	var buf bytes.Buffer
	err := Write(&buf, doc, FormatCycloneDX)
	if err != nil {
		t.Fatalf("failed to write CycloneDX VEX: %v", err)
	}

	// Verify it's valid JSON
	var cdx CycloneDXVEX
	if err := json.Unmarshal(buf.Bytes(), &cdx); err != nil {
		t.Fatalf("output is not valid CycloneDX JSON: %v", err)
	}

	if cdx.BOMFormat != "CycloneDX" {
		t.Errorf("expected bomFormat 'CycloneDX', got %s", cdx.BOMFormat)
	}

	if cdx.SpecVersion != "1.5" {
		t.Errorf("expected specVersion '1.5', got %s", cdx.SpecVersion)
	}

	if len(cdx.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(cdx.Vulnerabilities))
	}

	vuln := cdx.Vulnerabilities[0]
	if vuln.ID != "CVE-2024-5678" {
		t.Errorf("expected ID 'CVE-2024-5678', got %s", vuln.ID)
	}

	if vuln.Analysis == nil {
		t.Fatal("expected analysis to be set")
	}

	if vuln.Analysis.State != "not_affected" {
		t.Errorf("expected state 'not_affected', got %s", vuln.Analysis.State)
	}
}

func TestMapStatusToCycloneDX(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusAffected, "exploitable"},
		{StatusNotAffected, "not_affected"},
		{StatusFixed, "resolved"},
		{StatusUnderInvestigation, "in_triage"},
	}

	for _, tt := range tests {
		got := mapStatusToCycloneDX(tt.status)
		if got != tt.expected {
			t.Errorf("mapStatusToCycloneDX(%s) = %s, want %s", tt.status, got, tt.expected)
		}
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.Author != "deputy" {
		t.Errorf("expected default author 'deputy', got %s", opts.Author)
	}

	if opts.AuthorRole != "scanner" {
		t.Errorf("expected default role 'scanner', got %s", opts.AuthorRole)
	}

	if !opts.IncludeAffected {
		t.Error("expected IncludeAffected to be true by default")
	}

	if !opts.IncludeFixed {
		t.Error("expected IncludeFixed to be true by default")
	}
}

func TestSetToolVersion(t *testing.T) {
	original := toolVersion
	defer func() { toolVersion = original }()

	SetToolVersion("1.2.3")
	if toolVersion != "1.2.3" {
		t.Errorf("expected toolVersion '1.2.3', got %s", toolVersion)
	}
}
