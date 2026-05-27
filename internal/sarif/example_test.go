package sarif_test

import (
	"encoding/json"
	"fmt"
	"time"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/report"
	"github.com/temporalio/deputy/internal/sarif"
)

// Example_basic demonstrates basic SARIF conversion from Deputy scan results.
func Example_basic() {
	vulns := []report.Vulnerability{
		{
			ID:            "CVE-2021-44228",
			Summary:       "Remote code execution in Apache Log4j",
			Severity:      "CRITICAL",
			Package:       "org.apache.logging.log4j:log4j-core",
			Version:       "2.14.1",
			FixedVersions: []string{"2.17.0"},
			Locations:     []string{"pom.xml"},
		},
	}

	log := sarif.Convert(vulns, nil, sarif.Options{
		ToolVersion: "1.0.0",
	})

	data, _ := json.MarshalIndent(log, "", "  ")
	fmt.Println(string(data[:100]) + "...")
	// Output shows SARIF JSON structure
}

// ExampleConvert demonstrates converting vulnerabilities to SARIF format.
func ExampleConvert() {
	vulns := []report.Vulnerability{
		{
			ID:       "GHSA-abcd-1234-efgh",
			Summary:  "XSS vulnerability in lodash",
			Severity: "MEDIUM",
			Package:  "lodash",
			Version:  "4.17.20",
		},
	}

	log := sarif.Convert(vulns, nil, sarif.Options{})

	fmt.Printf("SARIF Version: %s\n", log.Version)
	fmt.Printf("Number of runs: %d\n", len(log.Runs))
	fmt.Printf("Number of results: %d\n", len(log.Runs[0].Results))
	// Output:
	// SARIF Version: 2.1.0
	// Number of runs: 1
	// Number of results: 1
}

// ExampleConvert_withOptions demonstrates using conversion options.
func ExampleConvert_withOptions() {
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-1234",
			Summary:  "Test vulnerability",
			Severity: "HIGH",
			Package:  "test-pkg",
			Version:  "1.0.0",
		},
	}

	log := sarif.Convert(vulns, nil, sarif.Options{
		ToolVersion:      "2.5.0",
		Repo:             "https://github.com/example/repo",
		Commit:           "abc123def456",
		Ref:              "main",
		Category:         "deputy-security-scan",
		WorkingDirectory: "/home/user/project",
		StartTime:        time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC),
		EndTime:          time.Date(2024, 6, 15, 10, 5, 0, 0, time.UTC),
	})

	run := log.Runs[0]
	fmt.Printf("Tool version: %s\n", run.Tool.Driver.Version)
	fmt.Printf("Category: %s\n", run.AutomationID.ID)
	fmt.Printf("Commit: %s\n", run.VersionControl[0].RevisionID)
	// Output:
	// Tool version: 2.5.0
	// Category: deputy-security-scan
	// Commit: abc123def456
}

// ExampleConvert_policyFindings demonstrates converting policy findings.
func ExampleConvert_policyFindings() {
	policyFindings := []report.PolicyFinding{
		{
			Source:      "severity-gate",
			Action:      "deny",
			Reason:      "Critical vulnerability blocks deployment",
			Remediation: "Upgrade affected packages to patched versions",
		},
		{
			Source: "license-check",
			Action: "warn",
			Reason: "GPL license detected in dependency",
		},
	}

	log := sarif.Convert(nil, policyFindings, sarif.Options{})

	// Rule IDs are formatted as "DEP<number>/<original-id>" per SARIF2009
	for _, result := range log.Runs[0].Results {
		fmt.Printf("Level: %s\n", result.Level)
	}
	// Output:
	// Level: error
	// Level: warning
}

// ExampleConvert_mixedResults demonstrates converting both vulnerabilities and policy findings.
func ExampleConvert_mixedResults() {
	vulns := []report.Vulnerability{
		{
			ID:       "CVE-2024-5678",
			Severity: "HIGH",
			Package:  "example-pkg",
			Version:  "2.0.0",
		},
	}

	policyFindings := []report.PolicyFinding{
		{
			Source: "compliance-check",
			Action: "deny",
			Reason: "Package not in allowlist",
		},
	}

	log := sarif.Convert(vulns, policyFindings, sarif.Options{})

	fmt.Printf("Total rules: %d\n", len(log.Runs[0].Tool.Driver.Rules))
	fmt.Printf("Total results: %d\n", len(log.Runs[0].Results))
	// Output:
	// Total rules: 2
	// Total results: 2
}

// ExampleConvert_withCodeFlows demonstrates code flows for dependency chains.
func ExampleConvert_withCodeFlows() {
	vulns := []report.Vulnerability{
		{
			ID:        "CVE-2024-9999",
			Severity:  "CRITICAL",
			Package:   "vulnerable-pkg",
			Version:   "1.0.0",
			Locations: []string{"go.mod"},
			AffectedImports: []vulnerabilityv1.AffectedImport{
				{Path: "vulnerable-pkg/internal", Symbols: []string{"UnsafeFunc"}},
			},
		},
	}

	log := sarif.Convert(vulns, nil, sarif.Options{})
	result := log.Runs[0].Results[0]

	fmt.Printf("Has code flows: %t\n", len(result.CodeFlows) > 0)
	if len(result.CodeFlows) > 0 {
		fmt.Printf("Thread flow locations: %d\n", len(result.CodeFlows[0].ThreadFlows[0].Locations))
	}
	// Output:
	// Has code flows: true
	// Thread flow locations: 2
}

// ExampleSeverityToScore demonstrates severity to CVSS score conversion.
func ExampleSeverityToScore() {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	for _, sev := range severities {
		score := sarif.SeverityToScore(sev)
		fmt.Printf("%s -> %.1f\n", sev, score)
	}
	// Output:
	// CRITICAL -> 9.5
	// HIGH -> 8.0
	// MEDIUM -> 5.5
	// LOW -> 2.0
	// UNKNOWN -> 0.0
}

// ExampleSeverityToLevel demonstrates severity to SARIF level conversion.
func ExampleSeverityToLevel() {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, sev := range severities {
		level := sarif.SeverityToLevel(sev)
		fmt.Printf("%s -> %s\n", sev, level)
	}
	// Output:
	// CRITICAL -> error
	// HIGH -> error
	// MEDIUM -> warning
	// LOW -> note
}

// ExampleSupportedVersions demonstrates listing supported SARIF versions.
func ExampleSupportedVersions() {
	versions := sarif.SupportedVersions()
	fmt.Printf("Supported versions: %v\n", versions)
	// Output:
	// Supported versions: [2.1.0 2.2.0]
}

// ExampleIsVersionSupported demonstrates checking version support.
func ExampleIsVersionSupported() {
	fmt.Printf("2.1.0 supported: %t\n", sarif.IsVersionSupported("2.1.0"))
	fmt.Printf("2.2.0 supported: %t\n", sarif.IsVersionSupported("2.2.0"))
	fmt.Printf("3.0.0 supported: %t\n", sarif.IsVersionSupported("3.0.0"))
	// Output:
	// 2.1.0 supported: true
	// 2.2.0 supported: true
	// 3.0.0 supported: false
}

// ExampleConvert_version22 demonstrates using SARIF 2.2.0.
func ExampleConvert_version22() {
	log := sarif.Convert(nil, nil, sarif.Options{
		SARIFVersion: sarif.Version22,
	})

	fmt.Printf("Version: %s\n", log.Version)
	fmt.Printf("Schema contains '2.2': %t\n", log.Schema != sarif.Schema21)
	// Output:
	// Version: 2.2.0
	// Schema contains '2.2': true
}
