package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestRenderVulnText(t *testing.T) {
	t.Run("renders basic vulnerability", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2021-44228",
			Summary: "Log4j remote code execution",
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
		}

		renderVulnText(out, vuln, false)
		output := out.String()

		if !strings.Contains(output, "CVE-2021-44228") {
			t.Error("output should contain vulnerability ID")
		}
		if !strings.Contains(output, "Log4j remote code execution") {
			t.Error("output should contain summary")
		}
		if !strings.Contains(output, "GHSA-jfh8-c2jp-5v3q") {
			t.Error("output should contain alias")
		}
	})

	t.Run("renders affected packages", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "TEST-001",
			Summary: "Test vulnerability",
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{
						Name:      "lodash",
						Ecosystem: "npm",
					},
					Ranges: []osvschema.Range{
						{
							Events: []osvschema.Event{
								{Introduced: "0"},
								{Fixed: "4.17.21"},
							},
						},
					},
				},
			},
		}

		renderVulnText(out, vuln, false)
		output := out.String()

		if !strings.Contains(output, "lodash") {
			t.Error("output should contain package name")
		}
		if !strings.Contains(output, "npm") {
			t.Error("output should contain ecosystem")
		}
		if !strings.Contains(output, "4.17.21") {
			t.Error("output should contain fixed version")
		}
	})

	t.Run("handles nil vulnerability", func(t *testing.T) {
		out := &bytes.Buffer{}
		renderVulnText(out, nil, false)
		if out.Len() != 0 {
			t.Error("expected no output for nil vulnerability")
		}
	})

	t.Run("handles nil writer", func(t *testing.T) {
		vuln := &osvschema.Vulnerability{ID: "TEST-001"}
		// Should not panic
		renderVulnText(nil, vuln, false)
	})

	t.Run("verbose includes details and references", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "TEST-002",
			Summary: "Test vulnerability",
			Details: "This is a detailed description of the vulnerability.",
			References: []osvschema.Reference{
				{URL: "https://example.com/advisory"},
			},
		}

		renderVulnText(out, vuln, true)
		output := out.String()

		if !strings.Contains(output, "detailed description") {
			t.Error("verbose output should contain details")
		}
		if !strings.Contains(output, "https://example.com/advisory") {
			t.Error("verbose output should contain references")
		}
	})
}

func TestRenderVulnJSON(t *testing.T) {
	t.Run("renders valid JSON", func(t *testing.T) {
		out := &bytes.Buffer{}
		vuln := &osvschema.Vulnerability{
			ID:      "CVE-2021-44228",
			Summary: "Log4j remote code execution",
			Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
			Affected: []osvschema.Affected{
				{
					Package: osvschema.Package{
						Name:      "org.apache.logging.log4j:log4j-core",
						Ecosystem: "Maven",
					},
					Ranges: []osvschema.Range{
						{
							Events: []osvschema.Event{
								{Fixed: "2.15.0"},
							},
						},
					},
				},
			},
		}

		renderVulnJSON(out, vuln)
		output := out.String()

		// Check JSON contains expected fields
		if !strings.Contains(output, `"id": "CVE-2021-44228"`) {
			t.Error("JSON should contain id")
		}
		if !strings.Contains(output, `"summary": "Log4j remote code execution"`) {
			t.Error("JSON should contain summary")
		}
		if !strings.Contains(output, `"aliases"`) {
			t.Error("JSON should contain aliases")
		}
		if !strings.Contains(output, `"affected"`) {
			t.Error("JSON should contain affected")
		}
		if !strings.Contains(output, `"fixed_versions"`) {
			t.Error("JSON should contain fixed_versions")
		}
	})
}

func TestExtractVulnSeverity(t *testing.T) {
	t.Run("extracts CVSS severity", func(t *testing.T) {
		vuln := &osvschema.Vulnerability{
			Severity: []osvschema.Severity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
			},
		}

		sev := extractVulnSeverity(vuln)
		// CVSS 10.0 should be CRITICAL
		if sev.Level != vulnerability.SeverityCritical {
			t.Errorf("expected CRITICAL, got %v", sev.Level)
		}
	})

	t.Run("extracts GHSA severity from database_specific", func(t *testing.T) {
		vuln := &osvschema.Vulnerability{
			DatabaseSpecific: map[string]any{
				"severity": "HIGH",
			},
		}

		sev := extractVulnSeverity(vuln)
		if sev.Level != vulnerability.SeverityHigh {
			t.Errorf("expected HIGH, got %v", sev.Level)
		}
	})

	t.Run("handles nil vulnerability", func(t *testing.T) {
		sev := extractVulnSeverity(nil)
		if sev.Level != vulnerability.SeverityUnknown {
			t.Errorf("expected Unknown, got %v", sev.Level)
		}
	})
}

func TestWrapDetailsText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		contains []string
	}{
		{
			name:     "short text unchanged",
			text:     "Short text",
			width:    80,
			contains: []string{"Short text"},
		},
		{
			name:     "long text wrapped",
			text:     "This is a very long line that should be wrapped at the specified width boundary",
			width:    40,
			contains: []string{"This is a very long line", "wrapped"},
		},
		{
			name:     "preserves paragraphs",
			text:     "First paragraph.\n\nSecond paragraph.",
			width:    80,
			contains: []string{"First paragraph.", "Second paragraph."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wrapDetailsText(tt.text, tt.width)
			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("result %q should contain %q", result, want)
				}
			}
		})
	}
}

func TestSeverityStyleFor(t *testing.T) {
	// Just verify it doesn't panic for each severity level
	levels := []vulnerability.SeverityLevel{
		vulnerability.SeverityCritical,
		vulnerability.SeverityHigh,
		vulnerability.SeverityMedium,
		vulnerability.SeverityLow,
		vulnerability.SeverityUnknown,
	}

	for _, level := range levels {
		style := severityStyleFor(level)
		// Style should be non-nil (lipgloss returns empty style, not nil)
		_ = style.Render("test")
	}
}

func TestRenderVulnText_WithDates(t *testing.T) {
	out := &bytes.Buffer{}
	published := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	modified := time.Date(2022, 1, 15, 0, 0, 0, 0, time.UTC)

	vuln := &osvschema.Vulnerability{
		ID:        "TEST-003",
		Summary:   "Test vulnerability",
		Published: published,
		Modified:  modified,
	}

	renderVulnText(out, vuln, false)
	output := out.String()

	if !strings.Contains(output, "2021-12-10") {
		t.Error("output should contain published date")
	}
	if !strings.Contains(output, "2022-01-15") {
		t.Error("output should contain modified date")
	}
}
