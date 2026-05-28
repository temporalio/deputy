package sarif

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/report"
)

func TestSchemaForVersion(t *testing.T) {
	tests := []struct {
		version    string
		wantSchema string
	}{
		{Version21, Schema21},
		{Version22, Schema22},
		{"2.1.0", Schema21},
		{"2.2.0", Schema22},
		{"unknown", DefaultSchema},
		{"3.0.0", DefaultSchema},
		{"", DefaultSchema},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := schemaForVersion(tt.version)
			if got != tt.wantSchema {
				t.Errorf("schemaForVersion(%q) = %q, want %q", tt.version, got, tt.wantSchema)
			}
		})
	}
}

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name        string
		opts        Options
		wantVersion string
		wantSchema  string
	}{
		{
			name:        "empty defaults to 2.1.0",
			opts:        Options{},
			wantVersion: Version21,
			wantSchema:  Schema21,
		},
		{
			name:        "explicit 2.1.0",
			opts:        Options{SARIFVersion: Version21},
			wantVersion: Version21,
			wantSchema:  Schema21,
		},
		{
			name:        "explicit 2.2.0",
			opts:        Options{SARIFVersion: Version22},
			wantVersion: Version22,
			wantSchema:  Schema22,
		},
		{
			name:        "unknown version uses default schema",
			opts:        Options{SARIFVersion: "unknown"},
			wantVersion: "unknown",
			wantSchema:  DefaultSchema,
		},
		{
			name:        "future version uses default schema",
			opts:        Options{SARIFVersion: "3.0.0"},
			wantVersion: "3.0.0",
			wantSchema:  DefaultSchema,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVersion, gotSchema := resolveVersion(tt.opts)
			if gotVersion != tt.wantVersion {
				t.Errorf("version = %q, want %q", gotVersion, tt.wantVersion)
			}
			if gotSchema != tt.wantSchema {
				t.Errorf("schema = %q, want %q", gotSchema, tt.wantSchema)
			}
		})
	}
}

func TestConvert_VersionSelection(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		wantVersion string
		wantSchema  string
	}{
		{"default", "", Version21, Schema21},
		{"2.1.0", Version21, Version21, Schema21},
		{"2.2.0", Version22, Version22, Schema22},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := Convert(nil, nil, Options{SARIFVersion: tt.version})
			if log.Version != tt.wantVersion {
				t.Errorf("Log.Version = %q, want %q", log.Version, tt.wantVersion)
			}
			if log.Schema != tt.wantSchema {
				t.Errorf("Log.Schema = %q, want %q", log.Schema, tt.wantSchema)
			}
		})
	}
}

func TestSchemaURLsValid(t *testing.T) {
	schemas := []struct {
		name   string
		schema string
	}{
		{"2.1.0", Schema21},
		{"2.2.0", Schema22},
	}

	for _, tt := range schemas {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasPrefix(tt.schema, "https://") {
				t.Errorf("Schema URL should use HTTPS: %q", tt.schema)
			}
			if !strings.HasSuffix(tt.schema, ".json") {
				t.Errorf("Schema URL should end in .json: %q", tt.schema)
			}
		})
	}
}

func TestSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		want     float64
	}{
		{"CRITICAL", 9.5},
		{"critical", 9.5},
		{"HIGH", 8.0},
		{"high", 8.0},
		{"MEDIUM", 5.5},
		{"medium", 5.5},
		{"MODERATE", 5.5},
		{"LOW", 2.0},
		{"low", 2.0},
		{"UNKNOWN", 0.0},
		{"", 0.0},
		{"invalid", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityToScore(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityToScore(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"UNKNOWN", "none"},
		{"", "none"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityToLevel(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityToLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestConvert_Empty(t *testing.T) {
	log := Convert(nil, nil, Options{})

	if log.Schema != DefaultSchema {
		t.Errorf("Schema = %q, want %q", log.Schema, DefaultSchema)
	}
	if log.Version != DefaultVersion {
		t.Errorf("Version = %q, want %q", log.Version, DefaultVersion)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "Deputy" {
		t.Errorf("Tool.Driver.Name = %q, want %q", log.Runs[0].Tool.Driver.Name, "Deputy")
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("len(Results) = %d, want 0", len(log.Runs[0].Results))
	}
}

func TestConvert_Vulnerabilities(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:            "CVE-2021-44228",
			Summary:       "Log4Shell vulnerability",
			Details:       "Remote code execution in Apache Log4j",
			CVE:           "CVE-2021-44228",
			Severity:      "CRITICAL",
			Package:       "org.apache.logging.log4j:log4j-core",
			Version:       "2.14.1",
			Ecosystem:     "Maven",
			PURL:          "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			IsDirect:      true,
			FixedVersions: []string{"2.15.0", "2.17.0"},
			References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			Locations:     []string{"pom.xml"},
		},
		{
			ID:       "GHSA-abcd-1234-efgh",
			Summary:  "XSS vulnerability in library",
			Severity: "MEDIUM",
			Package:  "lodash",
			Version:  "4.17.20",
		},
	}

	opts := Options{
		ToolVersion: "1.0.0",
		Repo:        "https://github.com/example/repo",
		Commit:      "abc123",
		Ref:         "main",
		Category:    "deputy-scan",
		StartTime:   time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		EndTime:     time.Date(2024, 1, 15, 10, 1, 0, 0, time.UTC),
	}

	log := Convert(vulns, nil, opts)

	// Check basic structure
	if len(log.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]

	// Check tool info
	if run.Tool.Driver.Version != "1.0.0" {
		t.Errorf("Tool.Driver.Version = %q, want %q", run.Tool.Driver.Version, "1.0.0")
	}

	// Check rules (should have 2, one for each vuln)
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(run.Tool.Driver.Rules))
	}

	// Check first rule (CVE-2021-44228)
	// Rule ID format is "DEP<4-digit>" per SARIF2009 (e.g., "DEP5172")
	rule0 := run.Tool.Driver.Rules[0]
	if !strings.HasPrefix(rule0.ID, "DEP") || len(rule0.ID) != 7 {
		t.Errorf("Rules[0].ID = %q, want DEP#### format (7 chars)", rule0.ID)
	}
	if rule0.Properties == nil || rule0.Properties.SecuritySeverity != 9.5 {
		t.Errorf("Rules[0].Properties.SecuritySeverity = %v, want 9.5", rule0.Properties.SecuritySeverity)
	}
	if rule0.DefaultConfig == nil || rule0.DefaultConfig.Level != "error" {
		t.Errorf("Rules[0].DefaultConfig.Level = %v, want error", rule0.DefaultConfig.Level)
	}

	// Check results (should have 2)
	if len(run.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(run.Results))
	}

	// Check first result
	// Rule ID format is "DEP<4-digit>" per SARIF2009 (e.g., "DEP5172")
	result0 := run.Results[0]
	if !strings.HasPrefix(result0.RuleID, "DEP") || len(result0.RuleID) != 7 {
		t.Errorf("Results[0].RuleID = %q, want DEP#### format (7 chars)", result0.RuleID)
	}
	if result0.Level != "error" {
		t.Errorf("Results[0].Level = %q, want %q", result0.Level, "error")
	}
	if len(result0.Locations) != 1 {
		t.Fatalf("len(Results[0].Locations) = %d, want 1", len(result0.Locations))
	}
	if result0.Locations[0].PhysicalLocation == nil {
		t.Error("Results[0].Locations[0].PhysicalLocation is nil")
	} else if result0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "pom.xml" {
		t.Errorf("Results[0].Locations[0].URI = %q, want %q",
			result0.Locations[0].PhysicalLocation.ArtifactLocation.URI, "pom.xml")
	}

	// Check fingerprints
	if result0.PartialFingerprints == nil {
		t.Error("Results[0].PartialFingerprints is nil")
	} else {
		if result0.PartialFingerprints["vulnerabilityId/v1"] != "CVE-2021-44228" {
			t.Errorf("fingerprint[vulnerabilityId/v1] = %q", result0.PartialFingerprints["vulnerabilityId/v1"])
		}
	}

	// Check version control
	if len(run.VersionControl) != 1 {
		t.Fatalf("len(VersionControl) = %d, want 1", len(run.VersionControl))
	}
	if run.VersionControl[0].RevisionID != "abc123" {
		t.Errorf("VersionControl[0].RevisionID = %q, want %q", run.VersionControl[0].RevisionID, "abc123")
	}

	// Check automation details
	if run.AutomationID == nil || run.AutomationID.ID != "deputy-scan" {
		t.Errorf("AutomationID.ID = %v, want deputy-scan", run.AutomationID)
	}
}

func TestConvert_PolicyFindings(t *testing.T) {
	policyFindings := []report.PolicyFinding{
		{
			Source:      "severity-guardrail",
			Action:      "deny",
			Reason:      "Critical vulnerability blocks merge",
			Remediation: "Upgrade affected packages",
		},
		{
			Source: "license-check",
			Action: "warn",
			Reason: "GPL license detected",
		},
		{
			Source: "approved-list",
			Action: "allow", // Should be skipped
			Reason: "Package is approved",
		},
	}

	log := Convert(nil, policyFindings, Options{})

	run := log.Runs[0]

	// Should have 2 rules (allow is skipped)
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(run.Tool.Driver.Rules))
	}

	// Check deny rule
	// Rule ID format is "DEP<4-digit>" per SARIF2009 (e.g., "DEP0278")
	rule0 := run.Tool.Driver.Rules[0]
	if !strings.HasPrefix(rule0.ID, "DEP") || len(rule0.ID) != 7 {
		t.Errorf("Rules[0].ID = %q, want DEP#### format (7 chars)", rule0.ID)
	}
	if rule0.DefaultConfig == nil || rule0.DefaultConfig.Level != "error" {
		t.Errorf("Rules[0].DefaultConfig.Level = %v, want error", rule0.DefaultConfig.Level)
	}

	// Check warn rule
	// Rule ID format is "DEP<4-digit>" per SARIF2009 (e.g., "DEP7288")
	rule1 := run.Tool.Driver.Rules[1]
	if !strings.HasPrefix(rule1.ID, "DEP") || len(rule1.ID) != 7 {
		t.Errorf("Rules[1].ID = %q, want DEP#### format (7 chars)", rule1.ID)
	}
	if rule1.DefaultConfig == nil || rule1.DefaultConfig.Level != "warning" {
		t.Errorf("Rules[1].DefaultConfig.Level = %v, want warning", rule1.DefaultConfig.Level)
	}

	// Should have 2 results
	if len(run.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(run.Results))
	}

	// Check deny result
	// Rule ID format is "DEP<4-digit>" per SARIF2009 (e.g., "DEP0278")
	result0 := run.Results[0]
	if !strings.HasPrefix(result0.RuleID, "DEP") || len(result0.RuleID) != 7 {
		t.Errorf("Results[0].RuleID = %q, want DEP#### format (7 chars)", result0.RuleID)
	}
	if result0.Level != "error" {
		t.Errorf("Results[0].Level = %q, want %q", result0.Level, "error")
	}

	// Check warn result
	result1 := run.Results[1]
	if result1.Level != "warning" {
		t.Errorf("Results[1].Level = %q, want %q", result1.Level, "warning")
	}
}

func TestConvert_MixedResults(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-0001",
			Summary:  "Test vulnerability",
			Severity: "HIGH",
			Package:  "test-pkg",
			Version:  "1.0.0",
		},
	}

	policyFindings := []report.PolicyFinding{
		{
			Source: "test-policy",
			Action: "deny",
			Reason: "Test reason",
		},
	}

	log := Convert(vulns, policyFindings, Options{})

	run := log.Runs[0]

	// Should have 2 rules and 2 results
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("len(Rules) = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("len(Results) = %d, want 2", len(run.Results))
	}
}

func TestConvert_JSON(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:            "CVE-2021-44228",
			Summary:       "Log4Shell",
			Severity:      "CRITICAL",
			Package:       "log4j",
			Version:       "2.14.1",
			FixedVersions: []string{"2.17.0"},
			Locations:     []string{"pom.xml"},
		},
	}

	log := Convert(vulns, nil, Options{
		ToolVersion: "1.0.0",
		Category:    "deputy-test",
	})

	// Verify it serializes to valid JSON
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Verify we can unmarshal it back
	var decoded Log
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Basic sanity checks
	if decoded.Schema != DefaultSchema {
		t.Errorf("decoded.Schema = %q, want %q", decoded.Schema, DefaultSchema)
	}
	if len(decoded.Runs) != 1 {
		t.Errorf("len(decoded.Runs) = %d, want 1", len(decoded.Runs))
	}
	if len(decoded.Runs[0].Results) != 1 {
		t.Errorf("len(decoded.Runs[0].Results) = %d, want 1", len(decoded.Runs[0].Results))
	}
}

func TestNormalizeURI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"./pom.xml", "pom.xml"},
		{"pom.xml", "pom.xml"},
		{"/absolute/path.xml", "absolute/path.xml"},
		{"src/main/java/App.java", "src/main/java/App.java"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeURI(tt.input)
			if got != tt.want {
				t.Errorf("normalizeURI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is..."},
		{"", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestConvert_NoLocations(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-0001",
			Summary:  "Test vulnerability",
			Severity: "HIGH",
			Package:  "test-pkg",
			Version:  "1.0.0",
			PURL:     "pkg:npm/test-pkg@1.0.0",
			// No Locations
		},
	}

	log := Convert(vulns, nil, Options{})

	result := log.Runs[0].Results[0]

	// Should have at least one location with logical location
	if len(result.Locations) == 0 {
		t.Fatal("expected at least one location")
	}

	// Should have logical location
	if len(result.Locations[0].LogicalLocations) == 0 {
		t.Fatal("expected logical location")
	}

	loc := result.Locations[0].LogicalLocations[0]
	if loc.Name != "test-pkg" {
		t.Errorf("LogicalLocation.Name = %q, want %q", loc.Name, "test-pkg")
	}
	if loc.FullyQualifiedName != "pkg:npm/test-pkg@1.0.0" {
		t.Errorf("LogicalLocation.FullyQualifiedName = %q", loc.FullyQualifiedName)
	}
	if loc.Kind != "package" {
		t.Errorf("LogicalLocation.Kind = %q, want %q", loc.Kind, "package")
	}
}

func TestSupportedVersions(t *testing.T) {
	versions := SupportedVersions()
	if len(versions) != 2 {
		t.Errorf("SupportedVersions() returned %d versions, want 2", len(versions))
	}
	// Verify expected versions are present
	found21, found22 := false, false
	for _, v := range versions {
		if v == Version21 {
			found21 = true
		}
		if v == Version22 {
			found22 = true
		}
	}
	if !found21 {
		t.Error("SupportedVersions() missing Version21")
	}
	if !found22 {
		t.Error("SupportedVersions() missing Version22")
	}
}

func TestIsVersionSupported(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{Version21, true},
		{Version22, true},
		{"2.1.0", true},
		{"2.2.0", true},
		{"2.0.0", false},
		{"3.0.0", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := IsVersionSupported(tt.version)
			if got != tt.want {
				t.Errorf("IsVersionSupported(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{
			name: "valid time",
			t:    time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
			want: "2024-01-15T10:30:45Z",
		},
		{
			name: "zero time",
			t:    time.Time{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTime(tt.t)
			if got != tt.want {
				t.Errorf("formatTime() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConvert_InvocationTimes(t *testing.T) {
	startTime := time.Date(2024, 6, 15, 9, 0, 0, 0, time.UTC)
	endTime := time.Date(2024, 6, 15, 9, 5, 30, 0, time.UTC)

	log := Convert(nil, nil, Options{
		StartTime:        startTime,
		EndTime:          endTime,
		WorkingDirectory: "/home/user/project",
	})

	if len(log.Runs) == 0 || len(log.Runs[0].Invocations) == 0 {
		t.Fatal("expected invocations")
	}

	inv := log.Runs[0].Invocations[0]
	if inv.StartTimeUTC != "2024-06-15T09:00:00Z" {
		t.Errorf("StartTimeUTC = %q, want %q", inv.StartTimeUTC, "2024-06-15T09:00:00Z")
	}
	if inv.EndTimeUTC != "2024-06-15T09:05:30Z" {
		t.Errorf("EndTimeUTC = %q, want %q", inv.EndTimeUTC, "2024-06-15T09:05:30Z")
	}
	if inv.WorkingDirectory == nil || inv.WorkingDirectory.URI != "/home/user/project" {
		t.Errorf("WorkingDirectory = %v, want /home/user/project", inv.WorkingDirectory)
	}
}

func TestConvert_DuplicateVulnerabilities(t *testing.T) {
	// Same vulnerability ID appearing in different packages should share a rule
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-1234",
			Summary:  "Test vulnerability",
			Severity: "HIGH",
			Package:  "pkg-a",
			Version:  "1.0.0",
		},
		{
			ID:       "CVE-2024-1234", // Same CVE
			Summary:  "Test vulnerability",
			Severity: "HIGH",
			Package:  "pkg-b",
			Version:  "2.0.0",
		},
	}

	log := Convert(vulns, nil, Options{})

	run := log.Runs[0]

	// Should have 1 rule (deduplicated by ID)
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("len(Rules) = %d, want 1 (dedup by ID)", len(run.Tool.Driver.Rules))
	}

	// Should have 2 results (one per occurrence)
	if len(run.Results) != 2 {
		t.Errorf("len(Results) = %d, want 2", len(run.Results))
	}

	// Both results should reference the same rule
	if run.Results[0].RuleID != run.Results[1].RuleID {
		t.Errorf("Results should share RuleID")
	}
	if run.Results[0].RuleIndex != run.Results[1].RuleIndex {
		t.Errorf("Results should share RuleIndex")
	}
}

func TestConvert_PolicyFindingWithCode(t *testing.T) {
	policyFindings := []report.PolicyFinding{
		{
			Source: "my-policy",
			Action: "deny",
			Reason: "Test reason",
			Code:   "POLICY_001",
		},
	}

	log := Convert(nil, policyFindings, Options{})

	result := log.Runs[0].Results[0]

	// Check code is in fingerprints
	if result.PartialFingerprints["policyCode/v1"] != "POLICY_001" {
		t.Errorf("policyCode fingerprint = %q, want %q",
			result.PartialFingerprints["policyCode/v1"], "POLICY_001")
	}
}

func TestConvert_VulnerabilityWithEmptySummary(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-5678",
			Summary:  "", // Empty summary
			Severity: "MEDIUM",
			Package:  "test-pkg",
			Version:  "1.0.0",
		},
	}

	log := Convert(vulns, nil, Options{})

	rule := log.Runs[0].Tool.Driver.Rules[0]

	// Should generate a default summary
	if rule.ShortDescription == nil || rule.ShortDescription.Text == "" {
		t.Error("Expected generated short description")
	}
	if !strings.Contains(rule.ShortDescription.Text, "CVE-2024-5678") {
		t.Errorf("Short description should contain vuln ID: %q", rule.ShortDescription.Text)
	}
}

func TestConvert_PolicyFindingEmptyMessage(t *testing.T) {
	policyFindings := []report.PolicyFinding{
		{
			Source:  "test-policy",
			Action:  "warn",
			Reason:  "",
			Message: "",
		},
	}

	log := Convert(nil, policyFindings, Options{})

	result := log.Runs[0].Results[0]

	// Should generate a default message
	if result.Message.Text == "" {
		t.Error("Expected generated message")
	}
	if !strings.Contains(result.Message.Text, "test-policy") {
		t.Errorf("Message should contain policy source: %q", result.Message.Text)
	}
}

func TestConvert_RuleIndexConsistency(t *testing.T) {
	// Verify that ruleId and ruleIndex always reference the same rule
	// Per SARIF §3.27.5-6, when both are present they MUST match
	vulns := []report.Vulnerability{
		{ID: "CVE-A", Package: "pkg1", Severity: "HIGH"},
		{ID: "CVE-B", Package: "pkg2", Severity: "MEDIUM"},
		{ID: "CVE-A", Package: "pkg3", Severity: "HIGH"}, // Duplicate CVE
		{ID: "CVE-C", Package: "pkg4", Severity: "LOW"},
		{ID: "CVE-B", Package: "pkg5", Severity: "MEDIUM"}, // Duplicate CVE
	}

	log := Convert(vulns, nil, Options{})
	run := log.Runs[0]

	// Build rule ID to index map from the rules array
	ruleIDToIndex := make(map[string]int)
	for i, rule := range run.Tool.Driver.Rules {
		ruleIDToIndex[rule.ID] = i
	}

	// Verify each result's ruleIndex matches the position of its ruleId
	for i, result := range run.Results {
		expectedIndex, ok := ruleIDToIndex[result.RuleID]
		if !ok {
			t.Errorf("Result[%d].RuleID %q not found in rules array", i, result.RuleID)
			continue
		}
		if result.RuleIndex != expectedIndex {
			t.Errorf("Result[%d]: RuleIndex=%d but RuleID %q is at index %d",
				i, result.RuleIndex, result.RuleID, expectedIndex)
		}
	}

	// Verify rule deduplication: should have 3 unique rules (CVE-A, CVE-B, CVE-C)
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("Expected 3 unique rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Verify 5 results (one per vulnerability occurrence)
	if len(run.Results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(run.Results))
	}
}

func TestConvert_MixedRuleIndexConsistency(t *testing.T) {
	// Test with both vulnerabilities and policy findings
	vulns := []report.Vulnerability{
		{ID: "CVE-2024-001", Package: "pkg-a", Severity: "HIGH"},
		{ID: "CVE-2024-002", Package: "pkg-b", Severity: "MEDIUM"},
	}

	policyFindings := []report.PolicyFinding{
		{Source: "license-check", Action: "warn", Reason: "GPL detected"},
		{Source: "severity-gate", Action: "deny", Reason: "Critical blocked"},
		{Source: "license-check", Action: "warn", Reason: "LGPL detected"}, // Duplicate policy
	}

	log := Convert(vulns, policyFindings, Options{})
	run := log.Runs[0]

	// Should have 4 unique rules: 2 CVEs + 2 unique policies
	if len(run.Tool.Driver.Rules) != 4 {
		t.Errorf("Expected 4 unique rules, got %d", len(run.Tool.Driver.Rules))
	}

	// Should have 5 results: 2 vulns + 3 policy findings
	if len(run.Results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(run.Results))
	}

	// Verify all results have consistent ruleId/ruleIndex
	ruleIDToIndex := make(map[string]int)
	for i, rule := range run.Tool.Driver.Rules {
		ruleIDToIndex[rule.ID] = i
	}

	for i, result := range run.Results {
		expectedIndex := ruleIDToIndex[result.RuleID]
		if result.RuleIndex != expectedIndex {
			t.Errorf("Result[%d]: inconsistent rule reference - RuleID=%q (index %d), RuleIndex=%d",
				i, result.RuleID, expectedIndex, result.RuleIndex)
		}
	}
}

func TestGitHubLimits(t *testing.T) {
	// Verify our constants match GitHub's documented limits
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
	if MaxRuleNameLength != 255 {
		t.Errorf("MaxRuleNameLength = %d, GitHub requires 255", MaxRuleNameLength)
	}
	if MaxShortDescriptionLength != 1024 {
		t.Errorf("MaxShortDescriptionLength = %d, GitHub requires 1024", MaxShortDescriptionLength)
	}
	if MaxFullDescriptionLength != 1024 {
		t.Errorf("MaxFullDescriptionLength = %d, GitHub requires 1024", MaxFullDescriptionLength)
	}
}

func TestConvert_LongRuleName(t *testing.T) {
	// Create a vulnerability with a very long ID
	longID := strings.Repeat("A", 300) // Exceeds 255 char limit
	vulns := []report.Vulnerability{
		{
			ID:       longID,
			Package:  "test-pkg",
			Severity: "HIGH",
		},
	}

	log := Convert(vulns, nil, Options{})
	rule := log.Runs[0].Tool.Driver.Rules[0]

	// Rule ID should be in DEP#### format per SARIF2009 (7 chars total)
	// The original ID is preserved in the Name field
	if !strings.HasPrefix(rule.ID, "DEP") || len(rule.ID) != 7 {
		t.Errorf("Rule ID = %q, want DEP#### format (7 chars)", rule.ID)
	}

	// Rule Name should be truncated to MaxRuleNameLength
	if len(rule.Name) > MaxRuleNameLength {
		t.Errorf("Rule Name length %d exceeds limit %d", len(rule.Name), MaxRuleNameLength)
	}
}

func TestSchemaURL_GitHubCompatible(t *testing.T) {
	// GitHub Code Scanning requires the schemastore URL
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
	expectedSchema := "https://json.schemastore.org/sarif-2.1.0.json"
	if Schema21 != expectedSchema {
		t.Errorf("Schema21 = %q, GitHub requires %q", Schema21, expectedSchema)
	}
	if DefaultSchema != expectedSchema {
		t.Errorf("DefaultSchema = %q, GitHub requires %q", DefaultSchema, expectedSchema)
	}
}

func TestConvert_LocationsHaveStartLine(t *testing.T) {
	// GitHub Code Scanning requires region.startLine for proper display
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-1234",
			Package:   "test-pkg",
			Severity:  "HIGH",
			Locations: []string{"go.mod", "go.sum"},
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	if len(result.Locations) != 2 {
		t.Fatalf("Expected 2 locations, got %d", len(result.Locations))
	}

	for i, loc := range result.Locations {
		if loc.PhysicalLocation == nil {
			t.Errorf("Location[%d].PhysicalLocation is nil", i)
			continue
		}
		if loc.PhysicalLocation.Region == nil {
			t.Errorf("Location[%d].PhysicalLocation.Region is nil (startLine required)", i)
			continue
		}
		if loc.PhysicalLocation.Region.StartLine < 1 {
			t.Errorf("Location[%d].Region.StartLine = %d, want >= 1", i, loc.PhysicalLocation.Region.StartLine)
		}
	}
}

func TestConvert_PrimaryLocationLineHash(t *testing.T) {
	// GitHub strongly recommends primaryLocationLineHash for stable alert tracking
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-1234",
			Package:   "test-pkg",
			Severity:  "HIGH",
			Locations: []string{"go.mod"},
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	hash, ok := result.PartialFingerprints["primaryLocationLineHash"]
	if !ok {
		t.Fatal("Missing primaryLocationLineHash fingerprint")
	}
	if hash == "" {
		t.Error("primaryLocationLineHash is empty")
	}
	// Hash should be stable for same inputs
	log2 := Convert(vulns, nil, Options{})
	hash2 := log2.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	if hash != hash2 {
		t.Errorf("primaryLocationLineHash not stable: %q != %q", hash, hash2)
	}
}

func TestConvert_PolicyFindingHasPrimaryLocationLineHash(t *testing.T) {
	policyFindings := []report.PolicyFinding{
		{
			Source: "test-policy",
			Action: "deny",
			Reason: "Test reason",
		},
	}

	log := Convert(nil, policyFindings, Options{})
	result := log.Runs[0].Results[0]

	hash, ok := result.PartialFingerprints["primaryLocationLineHash"]
	if !ok {
		t.Fatal("Missing primaryLocationLineHash fingerprint for policy finding")
	}
	if hash == "" {
		t.Error("primaryLocationLineHash is empty")
	}
}

func TestHashFingerprint_Stable(t *testing.T) {
	// Fingerprint should be deterministic
	h1 := HashFingerprint("CVE-2024-1234", "lodash", "package.json")
	h2 := HashFingerprint("CVE-2024-1234", "lodash", "package.json")
	if h1 != h2 {
		t.Errorf("hashFingerprint not deterministic: %q != %q", h1, h2)
	}

	// Different inputs should produce different hashes
	h3 := HashFingerprint("CVE-2024-5678", "lodash", "package.json")
	if h1 == h3 {
		t.Error("Different inputs should produce different hashes")
	}
}

func TestConvert_FullDescriptionTruncation(t *testing.T) {
	// Full description should be truncated to 1024 chars (GitHub limit)
	longDetails := strings.Repeat("x", 2000)
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-1234",
			Details:  longDetails,
			Package:  "test-pkg",
			Severity: "HIGH",
		},
	}

	log := Convert(vulns, nil, Options{})
	rule := log.Runs[0].Tool.Driver.Rules[0]

	if rule.FullDescription == nil {
		t.Fatal("FullDescription is nil")
	}
	if len(rule.FullDescription.Text) > MaxFullDescriptionLength {
		t.Errorf("FullDescription.Text length %d exceeds limit %d",
			len(rule.FullDescription.Text), MaxFullDescriptionLength)
	}
}

func TestConvert_RelatedLocations(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-1234",
			Package:   "test-pkg",
			Severity:  "HIGH",
			Locations: []string{"go.mod"},
			AffectedImports: []vulnerabilityv1.AffectedImport{
				{Path: "github.com/test/pkg/internal", Symbols: []string{"Foo", "Bar"}},
				{Path: "github.com/test/pkg/util"},
			},
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	if len(result.RelatedLocations) != 2 {
		t.Fatalf("Expected 2 related locations, got %d", len(result.RelatedLocations))
	}

	// First related location should include symbols
	loc := result.RelatedLocations[0]
	if len(loc.LogicalLocations) == 0 {
		t.Fatal("Expected logical location in related location")
	}
	if !strings.Contains(loc.LogicalLocations[0].Name, "Foo") {
		t.Errorf("Expected related location name to contain symbols, got %q", loc.LogicalLocations[0].Name)
	}
	if loc.LogicalLocations[0].Kind != "module" {
		t.Errorf("Expected kind 'module', got %q", loc.LogicalLocations[0].Kind)
	}

	// Second related location without symbols
	loc2 := result.RelatedLocations[1]
	if loc2.LogicalLocations[0].Name != "github.com/test/pkg/util" {
		t.Errorf("Expected path as name, got %q", loc2.LogicalLocations[0].Name)
	}
}

func TestConvert_CodeFlows(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-1234",
			Package:   "test-pkg",
			Version:   "1.0.0",
			Severity:  "HIGH",
			Locations: []string{"go.mod"},
			AffectedImports: []vulnerabilityv1.AffectedImport{
				{Path: "github.com/test/pkg/internal", Symbols: []string{"Vulnerable"}},
			},
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	if len(result.CodeFlows) != 1 {
		t.Fatalf("Expected 1 code flow, got %d", len(result.CodeFlows))
	}

	cf := result.CodeFlows[0]
	if cf.Message == nil || cf.Message.Text == "" {
		t.Error("Code flow should have a message")
	}

	if len(cf.ThreadFlows) != 1 {
		t.Fatalf("Expected 1 thread flow, got %d", len(cf.ThreadFlows))
	}

	tf := cf.ThreadFlows[0]
	if tf.ID != "dependency-chain" {
		t.Errorf("Expected thread flow ID 'dependency-chain', got %q", tf.ID)
	}

	// Should have 2 locations: manifest + 1 affected import
	if len(tf.Locations) != 2 {
		t.Fatalf("Expected 2 thread flow locations, got %d", len(tf.Locations))
	}

	// First location is the manifest
	loc0 := tf.Locations[0]
	if loc0.NestingLevel != 0 {
		t.Errorf("First location nesting level should be 0, got %d", loc0.NestingLevel)
	}
	if loc0.Importance != "essential" {
		t.Errorf("First location importance should be 'essential', got %q", loc0.Importance)
	}
	if loc0.Location.PhysicalLocation == nil {
		t.Error("First location should have physical location")
	}

	// Second location is the affected import
	loc1 := tf.Locations[1]
	if loc1.NestingLevel != 1 {
		t.Errorf("Second location nesting level should be 1, got %d", loc1.NestingLevel)
	}
	if loc1.Location.Message == nil || !strings.Contains(loc1.Location.Message.Text, "Vulnerable") {
		t.Errorf("Second location message should mention vulnerable symbols")
	}
}

func TestConvert_CodeFlows_NoAffectedImports(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-1234",
			Package:   "test-pkg",
			Severity:  "HIGH",
			Locations: []string{"go.mod"},
			// No AffectedImports
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	// Should have no code flows when there are no affected imports
	if len(result.CodeFlows) != 0 {
		t.Errorf("Expected 0 code flows without affected imports, got %d", len(result.CodeFlows))
	}
}

func TestConvert_Fixes(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:            "CVE-2024-1234",
			Package:       "test-pkg",
			Version:       "1.0.0",
			Severity:      "HIGH",
			Locations:     []string{"go.mod"},
			FixedVersions: []string{"1.0.1", "2.0.0"},
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	if len(result.Fixes) != 1 {
		t.Fatalf("Expected 1 fix, got %d", len(result.Fixes))
	}

	fix := result.Fixes[0]
	if !strings.Contains(fix.Description.Text, "1.0.1") {
		t.Errorf("Fix description should mention fixed version, got %q", fix.Description.Text)
	}
	if !strings.Contains(fix.Description.Text, "Upgrade") {
		t.Errorf("Fix description should say 'Upgrade', got %q", fix.Description.Text)
	}
}

func TestConvert_Fixes_NoFixedVersions(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-1234",
			Package:   "test-pkg",
			Version:   "1.0.0",
			Severity:  "HIGH",
			Locations: []string{"go.mod"},
			// No FixedVersions
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	// Should have no fixes when there are no fixed versions
	if len(result.Fixes) != 0 {
		t.Errorf("Expected 0 fixes without fixed versions, got %d", len(result.Fixes))
	}
}

func TestConvert_Fixes_NoLocations(t *testing.T) {
	vulns := []report.Vulnerability{
		{
			ID:            "CVE-2024-1234",
			Package:       "test-pkg",
			Version:       "1.0.0",
			Severity:      "HIGH",
			FixedVersions: []string{"1.0.1"},
			// No Locations
		},
	}

	log := Convert(vulns, nil, Options{})
	result := log.Runs[0].Results[0]

	// Should have no fixes without locations (can't apply fix without knowing where)
	if len(result.Fixes) != 0 {
		t.Errorf("Expected 0 fixes without locations, got %d", len(result.Fixes))
	}
}

func TestTaxonomyTypes(t *testing.T) {
	// Test that taxonomy-related types are properly structured
	taxonomy := ToolComponent{
		Name:           "CWE",
		GUID:           "cwe-guid-123",
		Version:        "4.13",
		InformationURI: "https://cwe.mitre.org/",
		Organization:   "MITRE",
		Taxa: []ReportingDesc{
			{
				ID:   "CWE-79",
				Name: "Improper Neutralization of Input During Web Page Generation",
				ShortDescription: &Message{
					Text: "Cross-site Scripting (XSS)",
				},
			},
		},
	}

	if taxonomy.Name != "CWE" {
		t.Errorf("Expected taxonomy name 'CWE', got %q", taxonomy.Name)
	}
	if len(taxonomy.Taxa) != 1 {
		t.Fatalf("Expected 1 taxa, got %d", len(taxonomy.Taxa))
	}
	if taxonomy.Taxa[0].ID != "CWE-79" {
		t.Errorf("Expected taxa ID 'CWE-79', got %q", taxonomy.Taxa[0].ID)
	}
}

func TestReportingDescRelationship(t *testing.T) {
	// Test relationship structure for linking rules to taxonomies
	rel := ReportingDescRelationship{
		Target: ReportingDescRef{
			ID:    "CWE-79",
			Index: 0,
			ToolComponent: &ToolComponentRef{
				Name:  "CWE",
				Index: 0,
			},
		},
		Kinds: []string{"superset"},
	}

	if rel.Target.ID != "CWE-79" {
		t.Errorf("Expected target ID 'CWE-79', got %q", rel.Target.ID)
	}
	if rel.Target.ToolComponent == nil {
		t.Fatal("Expected tool component reference")
	}
	if rel.Target.ToolComponent.Name != "CWE" {
		t.Errorf("Expected tool component name 'CWE', got %q", rel.Target.ToolComponent.Name)
	}
	if len(rel.Kinds) != 1 || rel.Kinds[0] != "superset" {
		t.Errorf("Expected kinds ['superset'], got %v", rel.Kinds)
	}
}

func TestRunTaxonomies(t *testing.T) {
	// Test that Run properly includes taxonomies
	run := Run{
		Tool: Tool{
			Driver: ToolComponent{
				Name: "Deputy",
			},
		},
		Taxonomies: []ToolComponent{
			{
				Name:           "CWE",
				Version:        "4.13",
				InformationURI: "https://cwe.mitre.org/",
			},
		},
	}

	if len(run.Taxonomies) != 1 {
		t.Fatalf("Expected 1 taxonomy, got %d", len(run.Taxonomies))
	}
	if run.Taxonomies[0].Name != "CWE" {
		t.Errorf("Expected taxonomy name 'CWE', got %q", run.Taxonomies[0].Name)
	}
}

func TestLocationMessage(t *testing.T) {
	// Test that Location properly includes Message field
	loc := Location{
		PhysicalLocation: &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "go.mod"},
		},
		Message: &Message{
			Text: "Dependency declared here",
		},
	}

	if loc.Message == nil {
		t.Fatal("Expected message in location")
	}
	if loc.Message.Text != "Dependency declared here" {
		t.Errorf("Expected message text, got %q", loc.Message.Text)
	}
}

func TestThreadFlowLocation(t *testing.T) {
	// Test ThreadFlowLocation structure
	tfl := ThreadFlowLocation{
		Location: Location{
			PhysicalLocation: &PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: "go.mod"},
			},
		},
		NestingLevel:   0,
		ExecutionOrder: 1,
		Importance:     "essential",
	}

	if tfl.NestingLevel != 0 {
		t.Errorf("Expected nesting level 0, got %d", tfl.NestingLevel)
	}
	if tfl.ExecutionOrder != 1 {
		t.Errorf("Expected execution order 1, got %d", tfl.ExecutionOrder)
	}
	if tfl.Importance != "essential" {
		t.Errorf("Expected importance 'essential', got %q", tfl.Importance)
	}
}
