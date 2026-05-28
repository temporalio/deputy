// Package vex provides Vulnerability Exploitability eXchange (VEX) document generation.
//
// VEX is a standard for communicating the exploitability status of vulnerabilities
// in software products. This package generates VEX documents from Deputy scan results,
// allowing security teams to understand the actual risk of vulnerabilities in their
// software supply chain.
//
// # Integration with Deputy Policies (CEL)
//
// VEX generation integrates with Deputy's CEL policy engine. Policies can emit
// VEX-specific actions that inform the status of vulnerabilities:
//
//	policies:
//	  - name: mark-not-exploitable
//	    entrypoints: ["scan_vulnerability"]
//	    rules:
//	      - action: vex
//	        when: |
//	          vulnerability.id == "CVE-2024-1234" &&
//	          !pkg.imports_affected_code
//	        vex:
//	          status: "not_affected"
//	          justification: "vulnerable_code_not_in_execute_path"
//	          impact_statement: "The vulnerable function is never called"
//
// Supported VEX policy actions:
//   - status: affected | not_affected | fixed | under_investigation
//   - justification: (required for not_affected) component_not_present |
//     vulnerable_code_not_present | vulnerable_code_not_in_execute_path |
//     vulnerable_code_cannot_be_controlled_by_adversary | inline_mitigations_already_exist
//   - impact_statement: free-form text explaining the assessment
//
// When generating VEX, policy results override default "affected" status.
//
// Supported output formats:
//   - CycloneDX VEX (embedded in CycloneDX BOM)
//   - OpenVEX (standalone JSON)
//
// Reference:
//   - https://cyclonedx.org/capabilities/vex/
//   - https://github.com/openvex/spec
package vex

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// toolVersion is the Deputy version used in VEX documents.
// Set via SetToolVersion during init or from version package.
var toolVersion = "0.0.0-dev"

// SetToolVersion sets the tool version reported in VEX documents.
func SetToolVersion(v string) {
	toolVersion = v
}

// Status represents the VEX status of a vulnerability.
type Status string

const (
	// StatusAffected indicates the product is affected by the vulnerability.
	StatusAffected Status = "affected"

	// StatusNotAffected indicates the product is not affected by the vulnerability.
	StatusNotAffected Status = "not_affected"

	// StatusFixed indicates the vulnerability has been fixed.
	StatusFixed Status = "fixed"

	// StatusUnderInvestigation indicates the status is being investigated.
	StatusUnderInvestigation Status = "under_investigation"
)

// Justification provides the reason for a not_affected status.
type Justification string

const (
	// JustificationComponentNotPresent means the vulnerable component is not present.
	JustificationComponentNotPresent Justification = "component_not_present"

	// JustificationVulnerableCodeNotPresent means the vulnerable code is not present.
	JustificationVulnerableCodeNotPresent Justification = "vulnerable_code_not_present"

	// JustificationVulnerableCodeNotInExecutePath means the code is present but not reachable.
	JustificationVulnerableCodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"

	// JustificationVulnerableCodeCannotBeControlledByAdversary means the code cannot be exploited.
	JustificationVulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"

	// JustificationInlineMitigationsAlreadyExist means mitigations are in place.
	JustificationInlineMitigationsAlreadyExist Justification = "inline_mitigations_already_exist"
)

// Statement represents a single VEX statement about a vulnerability.
type Statement struct {
	// VulnerabilityID is the primary vulnerability identifier (e.g., CVE-2024-1234).
	VulnerabilityID string `json:"vulnerability_id"`

	// Aliases are additional identifiers for the same vulnerability.
	Aliases []string `json:"aliases,omitempty"`

	// Status indicates the exploitability status.
	Status Status `json:"status"`

	// Justification explains why status is not_affected (required when status is not_affected).
	Justification Justification `json:"justification,omitempty"`

	// ImpactStatement provides details about why the product is or isn't affected.
	ImpactStatement string `json:"impact_statement,omitempty"`

	// ActionStatement describes actions to take (for affected status).
	ActionStatement string `json:"action_statement,omitempty"`

	// Products lists affected product identifiers (PURLs).
	Products []string `json:"products"`

	// Subcomponents lists the specific vulnerable components within the products.
	Subcomponents []string `json:"subcomponents,omitempty"`

	// Timestamp is when this statement was created.
	Timestamp time.Time `json:"timestamp"`
}

// Document represents a VEX document.
type Document struct {
	// Context provides JSON-LD context (for OpenVEX).
	Context string `json:"@context,omitempty"`

	// ID is a unique identifier for this VEX document.
	ID string `json:"@id,omitempty"`

	// Author identifies who created this VEX document.
	Author string `json:"author"`

	// AuthorRole describes the author's role.
	AuthorRole string `json:"author_role,omitempty"`

	// Timestamp is when the document was created.
	Timestamp time.Time `json:"timestamp"`

	// Version of the VEX specification.
	Version string `json:"version"`

	// ToolVersion identifies the tool that generated this document.
	ToolVersion string `json:"tool_version,omitempty"`

	// Statements contains the VEX statements.
	Statements []Statement `json:"statements"`
}

// Options configures VEX document generation.
type Options struct {
	// Author identifies who is creating the VEX document.
	Author string

	// AuthorRole describes the author's role (e.g., "security-team").
	AuthorRole string

	// DocumentID is a unique identifier for this VEX document.
	// If empty, one will be generated.
	DocumentID string

	// IncludeAffected includes statements for affected vulnerabilities.
	IncludeAffected bool

	// IncludeNotAffected includes statements for vulnerabilities determined
	// to not affect the product.
	IncludeNotAffected bool

	// IncludeFixed includes statements for vulnerabilities that have been fixed.
	IncludeFixed bool
}

// DefaultOptions returns sensible default options for VEX generation.
func DefaultOptions() Options {
	return Options{
		Author:          "deputy",
		AuthorRole:      "scanner",
		IncludeAffected: true,
		IncludeFixed:    true,
	}
}

// FromScanResult generates a VEX document from a scan result.
func FromScanResult(result scanning.Result, opts Options) *Document {
	if opts.Author == "" {
		opts.Author = "deputy"
	}

	doc := &Document{
		Context:     "https://openvex.dev/ns/v0.2.0",
		ID:          opts.DocumentID,
		Author:      opts.Author,
		AuthorRole:  opts.AuthorRole,
		Timestamp:   time.Now().UTC(),
		Version:     "0.2.0",
		ToolVersion: toolVersion,
		Statements:  make([]Statement, 0),
	}

	if doc.ID == "" {
		doc.ID = fmt.Sprintf("deputy:vex:%s:%d", result.Target.DisplayPath, doc.Timestamp.Unix())
	}

	// Consolidate findings for VEX statements
	consolidated := vulnerability.ConsolidateAll(result.Findings, result.Advisories)

	for _, cv := range consolidated.Vulnerabilities {
		stmt := statementFromConsolidated(cv, opts)
		if stmt != nil {
			doc.Statements = append(doc.Statements, *stmt)
		}
	}

	return doc
}

// statementFromConsolidated creates a VEX statement from a consolidated vulnerability.
func statementFromConsolidated(cv vulnerability.Consolidated, opts Options) *Statement {
	// Determine status
	var status Status
	hasfix := len(cv.FixedVersions) > 0

	// For now, all findings from a scan are "affected" unless they have a fix
	// In the future, this could integrate with suppression rules or manual assessments
	if hasfix {
		status = StatusAffected
	} else {
		status = StatusAffected
	}

	// Filter based on options
	switch status {
	case StatusAffected:
		if !opts.IncludeAffected {
			return nil
		}
	case StatusNotAffected:
		if !opts.IncludeNotAffected {
			return nil
		}
	case StatusFixed:
		if !opts.IncludeFixed {
			return nil
		}
	}

	stmt := &Statement{
		VulnerabilityID: cv.PrimaryID,
		Aliases:         cv.SecondaryIDs,
		Status:          status,
		Products:        []string{cv.PURL},
		Timestamp:       time.Now().UTC(),
	}

	// Add action statement for affected vulnerabilities
	if status == StatusAffected && hasfix {
		bestFix := vulnerability.FindBestFixedVersion(cv.FixedVersions, cv.Version)
		if bestFix != "" {
			stmt.ActionStatement = fmt.Sprintf("Upgrade %s from %s to %s", cv.Package, cv.Version, bestFix)
		}
	}

	// Add impact statement from vulnerability details
	if cv.Summary != "" {
		stmt.ImpactStatement = cv.Summary
	}

	return stmt
}

// Format specifies the output format for VEX documents.
type Format string

const (
	// FormatOpenVEX outputs OpenVEX JSON format.
	FormatOpenVEX Format = "openvex"

	// FormatCycloneDX outputs CycloneDX VEX format.
	FormatCycloneDX Format = "cyclonedx"
)

// Write serializes a VEX document to the given writer.
func Write(w io.Writer, doc *Document, format Format) error {
	switch format {
	case FormatOpenVEX, "":
		return writeOpenVEX(w, doc)
	case FormatCycloneDX:
		return writeCycloneDXVEX(w, doc)
	default:
		return fmt.Errorf("unsupported VEX format: %s", format)
	}
}

func writeOpenVEX(w io.Writer, doc *Document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// CycloneDXVulnerability represents a vulnerability in CycloneDX format.
type CycloneDXVulnerability struct {
	BOMRef      string                   `json:"bom-ref,omitempty"`
	ID          string                   `json:"id"`
	Source      *CycloneDXSource         `json:"source,omitempty"`
	Description string                   `json:"description,omitempty"`
	Analysis    *CycloneDXAnalysis       `json:"analysis,omitempty"`
	Affects     []CycloneDXAffects       `json:"affects,omitempty"`
	Ratings     []CycloneDXRating        `json:"ratings,omitempty"`
}

// CycloneDXSource identifies the source of vulnerability data.
type CycloneDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXAnalysis contains VEX analysis information.
type CycloneDXAnalysis struct {
	State         string `json:"state,omitempty"`
	Justification string `json:"justification,omitempty"`
	Response      string `json:"response,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// CycloneDXAffects identifies affected components.
type CycloneDXAffects struct {
	Ref string `json:"ref"`
}

// CycloneDXRating contains severity rating.
type CycloneDXRating struct {
	Severity string `json:"severity,omitempty"`
}

// CycloneDXVEX is the top-level CycloneDX VEX document structure.
type CycloneDXVEX struct {
	BOMFormat       string                   `json:"bomFormat"`
	SpecVersion     string                   `json:"specVersion"`
	Version         int                      `json:"version"`
	Metadata        map[string]any           `json:"metadata,omitempty"`
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities"`
}

func writeCycloneDXVEX(w io.Writer, doc *Document) error {
	cdx := CycloneDXVEX{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: map[string]any{
			"timestamp": doc.Timestamp.Format(time.RFC3339),
			"tools": []map[string]string{
				{
					"vendor":  "deputy",
					"name":    "deputy",
					"version": doc.ToolVersion,
				},
			},
		},
		Vulnerabilities: make([]CycloneDXVulnerability, 0, len(doc.Statements)),
	}

	for _, stmt := range doc.Statements {
		vuln := CycloneDXVulnerability{
			BOMRef:      fmt.Sprintf("vuln-%s", strings.ReplaceAll(stmt.VulnerabilityID, ":", "-")),
			ID:          stmt.VulnerabilityID,
			Description: stmt.ImpactStatement,
		}

		// Map VEX status to CycloneDX analysis state
		vuln.Analysis = &CycloneDXAnalysis{
			State:  mapStatusToCycloneDX(stmt.Status),
			Detail: stmt.ActionStatement,
		}
		if stmt.Justification != "" {
			vuln.Analysis.Justification = string(stmt.Justification)
		}

		// Add source
		if strings.HasPrefix(stmt.VulnerabilityID, "CVE-") {
			vuln.Source = &CycloneDXSource{
				Name: "NVD",
				URL:  "https://nvd.nist.gov/vuln/detail/" + stmt.VulnerabilityID,
			}
		} else if strings.HasPrefix(stmt.VulnerabilityID, "GHSA-") {
			vuln.Source = &CycloneDXSource{
				Name: "GitHub Advisory",
				URL:  "https://github.com/advisories/" + stmt.VulnerabilityID,
			}
		}

		// Add affects
		for _, prod := range stmt.Products {
			vuln.Affects = append(vuln.Affects, CycloneDXAffects{Ref: prod})
		}

		cdx.Vulnerabilities = append(cdx.Vulnerabilities, vuln)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(cdx)
}

func mapStatusToCycloneDX(status Status) string {
	switch status {
	case StatusAffected:
		return "exploitable"
	case StatusNotAffected:
		return "not_affected"
	case StatusFixed:
		return "resolved"
	case StatusUnderInvestigation:
		return "in_triage"
	default:
		return string(status)
	}
}
