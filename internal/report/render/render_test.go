package render

import (
	"bytes"
	"strings"
	"testing"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/remediation"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestDisplayVulnerabilitiesWithHeader(t *testing.T) {
	t.Parallel()

	t.Run("no vulnerabilities", func(t *testing.T) {
		var buf bytes.Buffer
		DisplayVulnerabilitiesWithHeader(&buf, scan.Result{}, "Custom Header:")
		out := buf.String()
		if !strings.Contains(out, "No vulnerabilities found") {
			t.Errorf("expected 'No vulnerabilities found', got: %s", out)
		}
	})

}

func TestVulnerabilityList(t *testing.T) {
	t.Parallel()

	t.Run("empty list", func(t *testing.T) {
		var buf bytes.Buffer
		VulnerabilityList(&buf, nil, VulnerabilityDisplayOptions{})
		if buf.Len() != 0 {
			t.Errorf("expected empty output for empty list, got: %s", buf.String())
		}
	})

	t.Run("sorts by severity", func(t *testing.T) {
		cons := []vulnerability.Consolidated{
			{PrimaryID: "CVE-LOW", Package: "pkg", Version: "1.0.0", Severity: "LOW"},
			{PrimaryID: "CVE-CRIT", Package: "pkg", Version: "1.0.0", Severity: "CRITICAL"},
			{PrimaryID: "CVE-HIGH", Package: "pkg", Version: "1.0.0", Severity: "HIGH"},
		}
		var buf bytes.Buffer
		VulnerabilityList(&buf, cons, VulnerabilityDisplayOptions{})
		out := buf.String()

		// Critical should appear before High, High before Low
		critIdx := strings.Index(out, "CVE-CRIT")
		highIdx := strings.Index(out, "CVE-HIGH")
		lowIdx := strings.Index(out, "CVE-LOW")

		if critIdx == -1 || highIdx == -1 || lowIdx == -1 {
			t.Fatalf("expected all CVEs in output, got: %s", out)
		}
		if critIdx > highIdx || highIdx > lowIdx {
			t.Errorf("expected severity ordering CRIT < HIGH < LOW, got: crit=%d, high=%d, low=%d", critIdx, highIdx, lowIdx)
		}
	})

	t.Run("shows direct vs indirect", func(t *testing.T) {
		consDirect := []vulnerability.Consolidated{
			{PrimaryID: "CVE-1", Package: "direct-pkg", Version: "1.0.0", IsDirect: true},
		}
		consIndirect := []vulnerability.Consolidated{
			{PrimaryID: "CVE-2", Package: "indirect-pkg", Version: "1.0.0", IsDirect: false},
		}

		var bufDirect bytes.Buffer
		VulnerabilityList(&bufDirect, consDirect, VulnerabilityDisplayOptions{})
		if !strings.Contains(bufDirect.String(), "[direct]") {
			t.Errorf("expected [direct] marker for direct dependency")
		}

		var bufIndirect bytes.Buffer
		VulnerabilityList(&bufIndirect, consIndirect, VulnerabilityDisplayOptions{})
		if !strings.Contains(bufIndirect.String(), "[indirect]") {
			t.Errorf("expected [indirect] marker for indirect dependency")
		}
	})

	t.Run("shows fixed version", func(t *testing.T) {
		cons := []vulnerability.Consolidated{
			{
				PrimaryID:     "CVE-1",
				Package:       "pkg",
				Version:       "1.0.0",
				FixedVersions: []string{"1.1.0", "2.0.0"},
			},
		}
		var buf bytes.Buffer
		VulnerabilityList(&buf, cons, VulnerabilityDisplayOptions{})
		// Should show upgrade arrow for fix
		if !strings.Contains(buf.String(), "↑") {
			t.Errorf("expected upgrade arrow for fixed version")
		}
	})

	t.Run("shows layer details", func(t *testing.T) {
		cons := []vulnerability.Consolidated{
			{
				PrimaryID: "CVE-1",
				Package:   "pkg",
				Version:   "1.0.0",
				LayerDetails: &containerv1.LayerDetails{
					Index:       5,
					InBaseImage: true,
				},
			},
		}
		var buf bytes.Buffer
		VulnerabilityList(&buf, cons, VulnerabilityDisplayOptions{})
		out := buf.String()
		if !strings.Contains(out, "BASE") {
			t.Errorf("expected BASE tag for base image layer")
		}
		if !strings.Contains(out, "layer 5") {
			t.Errorf("expected layer index")
		}
	})

	t.Run("shows symbols when enabled", func(t *testing.T) {
		cons := []vulnerability.Consolidated{
			{
				PrimaryID: "CVE-1",
				Package:   "pkg",
				Version:   "1.0.0",
				AffectedImports: []vulnerabilityv1.AffectedImport{
					{Path: "pkg/vulnerable", Symbols: []string{"UnsafeFunc"}},
				},
			},
		}

		// Without ShowSymbols
		var bufOff bytes.Buffer
		VulnerabilityList(&bufOff, cons, VulnerabilityDisplayOptions{ShowSymbols: false})
		if strings.Contains(bufOff.String(), "Symbol hints") {
			t.Errorf("expected no symbol hints when ShowSymbols=false")
		}

		// With ShowSymbols
		var bufOn bytes.Buffer
		VulnerabilityList(&bufOn, cons, VulnerabilityDisplayOptions{ShowSymbols: true})
		if !strings.Contains(bufOn.String(), "Symbol hints") {
			t.Errorf("expected symbol hints when ShowSymbols=true")
		}
	})
}

func TestFormatLayerTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ld     *containerv1.LayerDetails
		expect string
	}{
		{"nil", nil, ""},
		{"layer 0", &containerv1.LayerDetails{Index: 0}, "[layer 0]"},
		{"layer 5", &containerv1.LayerDetails{Index: 5}, "[layer 5]"},
		{"base image layer 0", &containerv1.LayerDetails{Index: 0, InBaseImage: true}, "[BASE layer 0]"},
		{"base image layer 3", &containerv1.LayerDetails{Index: 3, InBaseImage: true}, "[BASE layer 3]"},
		{"app layer", &containerv1.LayerDetails{Index: 12, InBaseImage: false}, "[layer 12]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatLayerTag(tt.ld)
			if got != tt.expect {
				t.Errorf("formatLayerTag() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestRemediationCommands(t *testing.T) {
	t.Parallel()

	t.Run("empty commands", func(t *testing.T) {
		var buf bytes.Buffer
		RemediationCommands(&buf, nil, "  ", "    ")
		if buf.Len() != 0 {
			t.Errorf("expected empty output for empty commands, got: %s", buf.String())
		}
	})

	t.Run("groups by path", func(t *testing.T) {
		commands := []remediation.Command{
			{Path: "frontend/package.json", Command: "npm update lodash"},
			{Path: "frontend/package.json", Command: "npm update react"},
			{Path: "backend/go.mod", Command: "go get pkg@v1.2.0"},
		}
		var buf bytes.Buffer
		RemediationCommands(&buf, commands, "  ", "    ")
		out := buf.String()
		if !strings.Contains(out, "frontend/package.json") {
			t.Errorf("expected path grouping")
		}
		if !strings.Contains(out, "backend/go.mod") {
			t.Errorf("expected second path group")
		}
	})

	t.Run("groups by manager when no path", func(t *testing.T) {
		commands := []remediation.Command{
			{Manager: "npm", Command: "npm update lodash"},
			{Manager: "go", Command: "go get pkg@v1.0.0"},
		}
		var buf bytes.Buffer
		RemediationCommands(&buf, commands, "  ", "    ")
		out := buf.String()
		if !strings.Contains(out, "npm") {
			t.Errorf("expected npm manager group")
		}
		if !strings.Contains(out, "go") {
			t.Errorf("expected go manager group")
		}
	})

	t.Run("shows go mod tidy with special symbol", func(t *testing.T) {
		commands := []remediation.Command{
			{Manager: "go", Command: "go mod tidy"},
		}
		var buf bytes.Buffer
		RemediationCommands(&buf, commands, "  ", "    ")
		out := buf.String()
		if !strings.Contains(out, "↻") {
			t.Errorf("expected refresh symbol for go mod tidy")
		}
	})

	t.Run("shows hints and groups in suffix", func(t *testing.T) {
		commands := []remediation.Command{
			{Manager: "npm", Command: "npm update lodash", Groups: []string{"devDependencies"}, Hint: "security fix"},
		}
		var buf bytes.Buffer
		RemediationCommands(&buf, commands, "  ", "    ")
		out := buf.String()
		if !strings.Contains(out, "devDependencies") {
			t.Errorf("expected groups in output")
		}
		if !strings.Contains(out, "security fix") {
			t.Errorf("expected hint in output")
		}
	})
}

func TestGroupRemediationCommands(t *testing.T) {
	t.Parallel()

	commands := []remediation.Command{
		{Path: "go.mod", Command: "go get a"},
		{Path: "go.mod", Command: "go get b"},
		{Manager: "npm", Command: "npm update x"},
		{Command: "other command"}, // No path or manager
	}

	order, grouped, isPath := groupRemediationCommands(commands)

	if len(order) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(order))
	}
	if order[0] != "go.mod" || order[1] != "npm" || order[2] != "other" {
		t.Errorf("unexpected order: %v", order)
	}
	if len(grouped["go.mod"]) != 2 {
		t.Errorf("expected 2 commands in go.mod group")
	}
	if !isPath["go.mod"] {
		t.Errorf("expected go.mod to be marked as path")
	}
	if isPath["npm"] {
		t.Errorf("expected npm to NOT be marked as path")
	}
}

func TestTriageSummary(t *testing.T) {
	t.Parallel()

	t.Run("no vulnerabilities", func(t *testing.T) {
		triageReport := report.TriageReport{
			Target:      report.Target{Repo: "test/repo"},
			TopPackages: nil,
		}
		var buf bytes.Buffer
		TriageSummary(&buf, triageReport, false)
		out := buf.String()
		if !strings.Contains(out, "No fixable vulnerabilities") {
			t.Errorf("expected no vulnerabilities message, got: %s", out)
		}
	})

	t.Run("with packages", func(t *testing.T) {
		triageReport := report.TriageReport{
			Target:            report.Target{Repo: "test/repo", Ref: "main"},
			PackagesWithVulns: 2,
			Stats:             vulnerabilityv1.Stats{Total: 3},
			TopPackages: []report.TriagePackageSummary{
				{
					Package:            "lodash",
					Version:            "4.17.20",
					Severity:           "HIGH",
					VulnerabilityCount: 2,
					FixVersion:         "4.17.21",
					Summary:            "Prototype pollution vulnerability",
					SeverityCounts:     map[string]int{"HIGH": 2},
				},
			},
		}
		var buf bytes.Buffer
		TriageSummary(&buf, triageReport, false)
		out := buf.String()
		if !strings.Contains(out, "lodash") {
			t.Errorf("expected package name in output")
		}
		if !strings.Contains(out, "4.17.20") {
			t.Errorf("expected version in output")
		}
		if !strings.Contains(out, "↑") {
			t.Errorf("expected fix version indicator")
		}
	})

	t.Run("shows db info when enabled", func(t *testing.T) {
		triageReport := report.TriageReport{
			Target:            report.Target{Repo: "test/repo"},
			PackagesWithVulns: 1,
			TopPackages: []report.TriagePackageSummary{
				{
					Package:          "pkg",
					Version:          "1.0.0",
					DatabaseSpecific: map[string]string{"review_status": "REVIEWED"},
				},
			},
		}

		// Without showDBInfo
		var bufOff bytes.Buffer
		TriageSummary(&bufOff, triageReport, false)
		if strings.Contains(bufOff.String(), "Database info") {
			t.Errorf("expected no db info when disabled")
		}

		// With showDBInfo
		var bufOn bytes.Buffer
		TriageSummary(&bufOn, triageReport, true)
		if !strings.Contains(bufOn.String(), "Database info") {
			t.Errorf("expected db info when enabled")
		}
	})
}

func TestFormatImportSummaries(t *testing.T) {
	t.Parallel()

	t.Run("empty imports", func(t *testing.T) {
		lines := FormatImportSummaries(nil, 3, 4)
		if lines != nil {
			t.Errorf("expected nil for empty imports")
		}
	})

	t.Run("path only", func(t *testing.T) {
		imps := []vulnerabilityv1.AffectedImport{
			{Path: "pkg/vuln"},
		}
		lines := FormatImportSummaries(imps, 3, 4)
		if len(lines) != 1 || lines[0] != "pkg/vuln" {
			t.Errorf("expected path only, got: %v", lines)
		}
	})

	t.Run("path with symbols", func(t *testing.T) {
		imps := []vulnerabilityv1.AffectedImport{
			{Path: "pkg/vuln", Symbols: []string{"Func1", "Func2"}},
		}
		lines := FormatImportSummaries(imps, 3, 4)
		if len(lines) != 1 {
			t.Fatalf("expected 1 line, got %d", len(lines))
		}
		if !strings.Contains(lines[0], "Func1") || !strings.Contains(lines[0], "Func2") {
			t.Errorf("expected symbols in output, got: %s", lines[0])
		}
	})

	t.Run("truncates paths", func(t *testing.T) {
		imps := []vulnerabilityv1.AffectedImport{
			{Path: "pkg1"},
			{Path: "pkg2"},
			{Path: "pkg3"},
			{Path: "pkg4"},
			{Path: "pkg5"},
		}
		lines := FormatImportSummaries(imps, 2, 4)
		if len(lines) != 3 { // 2 paths + 1 truncation message
			t.Fatalf("expected 3 lines, got %d", len(lines))
		}
		if !strings.Contains(lines[2], "3 more import paths") {
			t.Errorf("expected truncation message, got: %s", lines[2])
		}
	})

	t.Run("truncates symbols", func(t *testing.T) {
		imps := []vulnerabilityv1.AffectedImport{
			{Path: "pkg", Symbols: []string{"S1", "S2", "S3", "S4", "S5", "S6"}},
		}
		lines := FormatImportSummaries(imps, 3, 2)
		if len(lines) != 1 {
			t.Fatalf("expected 1 line, got %d", len(lines))
		}
		if !strings.Contains(lines[0], "...") {
			t.Errorf("expected truncation indicator, got: %s", lines[0])
		}
	})

	t.Run("skips empty paths", func(t *testing.T) {
		imps := []vulnerabilityv1.AffectedImport{
			{Path: ""},
			{Path: "  "},
			{Path: "valid"},
		}
		lines := FormatImportSummaries(imps, 3, 4)
		if len(lines) != 1 {
			t.Fatalf("expected 1 line (skipping empty), got %d", len(lines))
		}
		if lines[0] != "valid" {
			t.Errorf("expected 'valid', got: %s", lines[0])
		}
	})
}

func TestFormatSeverityCounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		counts map[string]int
		expect string
	}{
		{"empty", nil, ""},
		{"empty map", map[string]int{}, ""},
		{"critical only", map[string]int{"CRITICAL": 2}, "2 CRIT"},
		{"high only", map[string]int{"HIGH": 3}, "3 HIGH"},
		{"medium only", map[string]int{"MED": 1}, "1 MED"},
		{"low only", map[string]int{"LOW": 5}, "5 LOW"},
		{"multiple", map[string]int{"HIGH": 2, "MED": 3}, "2 HIGH, 3 MED"},
		{"ordering", map[string]int{"LOW": 1, "CRITICAL": 1, "HIGH": 1}, "1 CRIT, 1 HIGH, 1 LOW"},
		{"unknown", map[string]int{"UNKNOWN": 2}, "2 ?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatSeverityCounts(tt.counts)
			if got != tt.expect {
				t.Errorf("formatSeverityCounts() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestFormatDatabaseSpecificInfo(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		lines := FormatDatabaseSpecificInfo(nil, 3)
		if lines != nil {
			t.Errorf("expected nil for empty db")
		}
	})

	t.Run("single entry", func(t *testing.T) {
		db := map[string]string{"status": "reviewed"}
		lines := FormatDatabaseSpecificInfo(db, 3)
		if len(lines) != 1 {
			t.Fatalf("expected 1 line, got %d", len(lines))
		}
		if lines[0] != "status: reviewed" {
			t.Errorf("unexpected line: %s", lines[0])
		}
	})

	t.Run("sorted keys", func(t *testing.T) {
		db := map[string]string{"z": "last", "a": "first", "m": "middle"}
		lines := FormatDatabaseSpecificInfo(db, 10)
		if len(lines) != 3 {
			t.Fatalf("expected 3 lines, got %d", len(lines))
		}
		if !strings.HasPrefix(lines[0], "a:") {
			t.Errorf("expected sorted order, first was: %s", lines[0])
		}
	})

	t.Run("truncates", func(t *testing.T) {
		db := map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"}
		lines := FormatDatabaseSpecificInfo(db, 2)
		if len(lines) != 3 { // 2 entries + truncation
			t.Fatalf("expected 3 lines, got %d", len(lines))
		}
		if !strings.Contains(lines[2], "3 more entries") {
			t.Errorf("expected truncation message, got: %s", lines[2])
		}
	})

	t.Run("no limit", func(t *testing.T) {
		db := map[string]string{"a": "1", "b": "2", "c": "3"}
		lines := FormatDatabaseSpecificInfo(db, 0)
		if len(lines) != 3 {
			t.Errorf("expected all entries with 0 limit, got %d", len(lines))
		}
	})
}

func TestVulnerabilitySummaryAndActions(t *testing.T) {
	t.Parallel()

	t.Run("no vulnerabilities", func(t *testing.T) {
		var buf bytes.Buffer
		VulnerabilitySummaryAndActions(&buf, nil, vulnerabilityv1.Stats{})
		out := buf.String()
		if !strings.Contains(out, "No vulnerabilities found") {
			t.Errorf("expected no vulns message, got: %s", out)
		}
	})

	t.Run("shows critical/high count", func(t *testing.T) {
		cons := []vulnerability.Consolidated{
			{PrimaryID: "CVE-1", Severity: "CRITICAL"},
			{PrimaryID: "CVE-2", Severity: "HIGH"},
			{PrimaryID: "CVE-3", Severity: "HIGH"},
		}
		stats := vulnerabilityv1.Stats{Total: 3, Critical: 1, High: 2}
		var buf bytes.Buffer
		VulnerabilitySummaryAndActions(&buf, cons, stats)
		out := buf.String()
		if !strings.Contains(out, "require immediate attention") {
			t.Errorf("expected immediate attention message")
		}
	})

	t.Run("shows fix available count", func(t *testing.T) {
		cons := []vulnerability.Consolidated{
			{PrimaryID: "CVE-1", FixedVersions: []string{"1.0.1"}},
			{PrimaryID: "CVE-2", FixedVersions: []string{"2.0.0"}},
		}
		stats := vulnerabilityv1.Stats{Total: 2}
		var buf bytes.Buffer
		VulnerabilitySummaryAndActions(&buf, cons, stats)
		out := buf.String()
		if !strings.Contains(out, "can be fixed by upgrading") {
			t.Errorf("expected upgrade message, got: %s", out)
		}
	})
}
