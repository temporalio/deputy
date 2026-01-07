// Package sarif provides SARIF output format support for Deputy scan results.
//
// SARIF (Static Analysis Results Interchange Format) is an OASIS standard for
// sharing static analysis results, widely used by GitHub Code Scanning.
//
// # Supported Versions
//
// This package supports SARIF 2.1.0 (default) and 2.2.0. Use the version
// constants ([Version21], [Version22]) with [Options.SARIFVersion].
//
// # Specification References
//
// SARIF 2.1.0 (OASIS Standard):
//   - Full specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
//   - §3.13 sarifLog object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317448
//   - §3.14 run object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317484
//   - §3.18 tool object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317529
//   - §3.19 toolComponent object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317533
//   - §3.27 result object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317638
//   - §3.28 location object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317670
//   - §3.49 reportingDescriptor object: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317836
//
// SARIF 2.2 (In Development):
//   - Specification: https://github.com/oasis-tcs/sarif-spec/tree/main/sarif-2.2
//
// # GitHub Code Scanning Integration
//
// GitHub Code Scanning accepts SARIF files and displays results in the Security tab.
// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
//
// GitHub uses the "security-severity" property to determine alert severity:
//   - 9.0-10.0: Critical
//   - 7.0-8.9: High
//   - 4.0-6.9: Medium
//   - 0.1-3.9: Low
//
// # Usage
//
//	log := sarif.Convert(vulns, policyFindings, sarif.Options{
//	    ToolVersion: "1.0.0",
//	})
//	data, _ := json.MarshalIndent(log, "", "  ")
package sarif

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/vulnerability"
)

// SARIF version and schema constants.
//
// The SARIF specification is managed by OASIS. Version 2.1.0 is the current
// stable standard; 2.2 is in development.
//
// See: https://github.com/oasis-tcs/sarif-spec
const (
	// Version21 is SARIF 2.1.0, the current stable OASIS standard (2020).
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
	Version21 = "2.1.0"

	// Schema21 is the JSON schema URI for SARIF 2.1.0.
	// GitHub Code Scanning requires this specific schema URL.
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
	Schema21 = "https://json.schemastore.org/sarif-2.1.0.json"

	// Version22 is SARIF 2.2, currently in development.
	// Note: GitHub Code Scanning only supports SARIF 2.1.0 as of 2024.
	// See: https://github.com/oasis-tcs/sarif-spec/tree/main/sarif-2.2
	Version22 = "2.2.0"

	// Schema22 is the JSON schema URI for SARIF 2.2.
	// See: https://github.com/oasis-tcs/sarif-spec/tree/main/sarif-2.2
	Schema22 = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/refs/heads/main/sarif-2.2/schema/sarif.json"

	// DefaultVersion is the default SARIF version (2.1.0, the stable standard).
	DefaultVersion = Version21

	// DefaultSchema is the default JSON schema URI.
	DefaultSchema = Schema21
)

// GitHub Code Scanning limits for SARIF fields.
// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
const (
	// MaxRuleNameLength is the maximum length for rule names in GitHub Code Scanning.
	MaxRuleNameLength = 255
	// MaxShortDescriptionLength is the maximum length for short descriptions.
	MaxShortDescriptionLength = 1024
	// MaxFullDescriptionLength is the maximum length for full descriptions.
	// GitHub documents this as 1024 characters.
	MaxFullDescriptionLength = 1024
)

// schemaForVersion returns the schema URI for a given SARIF version.
// Returns DefaultSchema for unrecognized versions.
func schemaForVersion(version string) string {
	switch version {
	case Version21:
		return Schema21
	case Version22:
		return Schema22
	default:
		return DefaultSchema
	}
}

// SupportedVersions returns the list of SARIF versions supported by this package.
func SupportedVersions() []string {
	return []string{Version21, Version22}
}

// IsVersionSupported returns true if the given version string is a supported SARIF version.
func IsVersionSupported(version string) bool {
	switch version {
	case Version21, Version22:
		return true
	default:
		return false
	}
}

// Log is the root SARIF object (sarifLog) containing all analysis runs.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317448
type Log struct {
	// Schema is the URI of the JSON schema to which this log conforms.
	Schema string `json:"$schema"`
	// Version is the SARIF format version of this log file.
	Version string `json:"version"`
	// Runs contains the set of runs contained in this log file.
	Runs []Run `json:"runs"`
}

// Run represents a single invocation of an analysis tool.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317484
type Run struct {
	// Tool describes the analysis tool that was run.
	Tool Tool `json:"tool"`
	// Results contains the set of results contained in an analysis run.
	Results []Result `json:"results,omitempty"`
	// Invocations contains configurations of the tool's invocation(s).
	Invocations []Invocation `json:"invocations,omitempty"`
	// Artifacts contains the set of artifacts relevant to the run.
	Artifacts []Artifact `json:"artifacts,omitempty"`
	// VersionControl contains version control information for the files analyzed.
	VersionControl []VersionControl `json:"versionControlProvenance,omitempty"`
	// AutomationID identifies this run for result management systems.
	AutomationID *RunAutomation `json:"automationDetails,omitempty"`
	// OriginalURIBase contains original base URIs for artifact locations.
	OriginalURIBase map[string]URI `json:"originalUriBaseIds,omitempty"`
	// Taxonomies describes external taxonomies (e.g., CWE) used to categorize results.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317497
	Taxonomies []ToolComponent `json:"taxonomies,omitempty"`
}

// RunAutomation provides a unique identifier for this analysis run.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317523
type RunAutomation struct {
	// ID is a hierarchical string that uniquely identifies this run's automation category.
	ID string `json:"id,omitempty"`
}

// URI represents a base URI for artifact locations.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317431
type URI struct {
	URI string `json:"uri,omitempty"`
}

// Tool describes the analysis tool that produced the results.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317529
type Tool struct {
	// Driver is the primary tool component (the tool itself).
	Driver ToolComponent `json:"driver"`
}

// ToolComponent describes a tool component (driver or extension).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317533
type ToolComponent struct {
	// Name is a human-readable name for the tool component.
	Name string `json:"name"`
	// GUID is a unique identifier for the tool component (RFC 4122).
	GUID string `json:"guid,omitempty"`
	// Version is the tool component's version, in whatever format it natively provides.
	Version string `json:"version,omitempty"`
	// SemanticVersion is the tool component's version in Semantic Versioning format.
	SemanticVersion string `json:"semanticVersion,omitempty"`
	// InformationURI is the absolute URI at which information about this tool can be found.
	InformationURI string `json:"informationUri,omitempty"`
	// DownloadURI is the URI at which the tool component can be downloaded.
	DownloadURI string `json:"downloadUri,omitempty"`
	// Rules contains an array of reportingDescriptor objects defining rules.
	Rules []ReportingDesc `json:"rules,omitempty"`
	// Taxa contains an array of reportingDescriptor objects defining taxonomy categories.
	// Used for taxonomies like CWE.
	Taxa []ReportingDesc `json:"taxa,omitempty"`
	// Organization is the name of the company or organization that produced the tool.
	Organization string `json:"organization,omitempty"`
	// FullName is the tool component's full name including version information.
	FullName string `json:"fullName,omitempty"`
	// ShortDesc is a brief description of the tool component.
	ShortDesc *Message `json:"shortDescription,omitempty"`
	// FullDesc is a comprehensive description of the tool component.
	FullDesc *Message `json:"fullDescription,omitempty"`
	// ReleaseDateUTC is the release date of the tool component.
	ReleaseDateUTC string `json:"releaseDateUtc,omitempty"`
	// Properties contains key/value pairs with additional information.
	Properties *PropertyBag `json:"properties,omitempty"`
}

// ReportingDesc describes a rule or notification (reportingDescriptor object).
//
// Rules are defined in tool.driver.rules and referenced by [Result] objects via
// their ID. Each rule should appear exactly once in the rules array; multiple
// results can reference the same rule.
//
// For GitHub Code Scanning, the following fields are significant:
//   - ID: Required, used for alert tracking across runs
//   - Name: Optional, max 255 chars, displayed for filtering (omitted to avoid SARIF2012 issues)
//   - ShortDescription: Required, max 1024 chars
//   - Properties.security-severity: Used for severity display (0.0-10.0)
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317836
// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
type ReportingDesc struct {
	// ID is a stable, opaque identifier for the reporting item.
	// This must be unique within the tool and stable across runs.
	ID string `json:"id"`
	// Name is an optional identifier that is understandable to an end user.
	// We omit this field to avoid SARIF2012 PascalCase validation issues.
	Name string `json:"name,omitempty"`
	// ShortDescription is a concise description of the reporting item.
	ShortDescription *Message `json:"shortDescription,omitempty"`
	// FullDescription is a description of the reporting item.
	FullDescription *Message `json:"fullDescription,omitempty"`
	// MessageStrings contains message templates with placeholders for result messages.
	// Keys are message IDs referenced by result.message.id, values contain templates
	// with placeholders like {0}, {1} that get replaced with result.message.arguments.
	MessageStrings map[string]MultiformatMessageString `json:"messageStrings,omitempty"`
	// HelpURI is a URI where the primary documentation for the reporting item can be found.
	HelpURI string `json:"helpUri,omitempty"`
	// Help provides the primary documentation for the reporting item.
	Help *Message `json:"help,omitempty"`
	// DefaultConfig contains default reporting configuration information.
	DefaultConfig *RuleConfig `json:"defaultConfiguration,omitempty"`
	// Relationships describes relationships to taxonomy categories (e.g., CWE).
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317861
	Relationships []ReportingDescRelationship `json:"relationships,omitempty"`
	// Properties contains key/value pairs with additional information.
	Properties *PropertyBag `json:"properties,omitempty"`
}

// MultiformatMessageString contains a message template in multiple formats.
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317468
type MultiformatMessageString struct {
	// Text is the plain text message template with placeholders like {0}, {1}.
	Text string `json:"text"`
	// Markdown is the Markdown message template with placeholders.
	Markdown string `json:"markdown,omitempty"`
}

// ReportingDescRelationship describes a relationship between a rule and a taxonomy category.
// Used to link vulnerability rules to CWE entries.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317861
type ReportingDescRelationship struct {
	// Target identifies the taxonomy category.
	Target ReportingDescRef `json:"target"`
	// Kinds describes the nature of the relationship.
	// Common values: "superset", "subset", "equal", "disjoint", "relevant"
	Kinds []string `json:"kinds,omitempty"`
}

// ReportingDescRef identifies a reportingDescriptor in a specific toolComponent.
// Used in relationships to reference taxonomy categories.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317865
type ReportingDescRef struct {
	// ID is the reporting descriptor's ID.
	ID string `json:"id"`
	// Index is the index of the descriptor in the rules/taxa array.
	Index int `json:"index,omitempty"`
	// GUID is a unique identifier if the tool uses GUIDs.
	GUID string `json:"guid,omitempty"`
	// ToolComponent identifies which tool component contains the descriptor.
	ToolComponent *ToolComponentRef `json:"toolComponent,omitempty"`
}

// ToolComponentRef identifies a specific tool component.
// Used in relationships to reference taxonomies.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317871
type ToolComponentRef struct {
	// Name is the tool component's name.
	Name string `json:"name,omitempty"`
	// Index is the index in the run.taxonomies array.
	Index int `json:"index"`
	// GUID is the tool component's GUID.
	GUID string `json:"guid,omitempty"`
}

// RuleConfig holds default configuration for a rule (reportingConfiguration object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317852
type RuleConfig struct {
	// Level specifies the failure level for results from this rule.
	// Values: "none", "note", "warning", "error" (default: "warning")
	Level string `json:"level,omitempty"`
}

// Result represents a single finding from the analysis (result object).
//
// Results reference rules defined in tool.driver.rules. A result specifies
// the rule that was violated and instance-specific details (location, message).
// Multiple results can reference the same rule when the same issue occurs
// in different locations or packages.
//
// This implementation provides both RuleID and RuleIndex for maximum compatibility:
//   - RuleID: Human-readable, enables stable alert tracking across runs
//   - RuleIndex: Efficient lookup into the rules array
//
// Per SARIF §3.27.5-6, when both are present they MUST reference the same rule.
//
// # Dependency Scanning Extensions
//
// For dependency vulnerabilities, this implementation uses:
//   - CodeFlows: To show transitive dependency chains (how a vulnerable package was introduced)
//   - RelatedLocations: To show affected imports/symbols and other manifest files
//   - Fixes: To suggest version upgrades with specific replacement text
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317638
type Result struct {
	// RuleID is the stable identifier of the rule that was evaluated.
	// References ReportingDesc.ID in tool.driver.rules.
	RuleID string `json:"ruleId"`
	// RuleIndex is the index within the tool component's rules array.
	// When present with RuleID, must reference the same rule.
	RuleIndex int `json:"ruleIndex,omitempty"`
	// Level is the severity level of the result: "none", "note", "warning", "error".
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317648
	Level string `json:"level,omitempty"`
	// Message describes the result.
	Message Message `json:"message"`
	// Locations contains the set of locations where the result was detected.
	Locations []Location `json:"locations,omitempty"`
	// RelatedLocations provides additional context (e.g., affected imports, other manifests).
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317669
	RelatedLocations []Location `json:"relatedLocations,omitempty"`
	// CodeFlows describes paths through the code (used here for dependency chains).
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317740
	CodeFlows []CodeFlow `json:"codeFlows,omitempty"`
	// Fixes contains potential fixes for the problem indicated by the result.
	Fixes []Fix `json:"fixes,omitempty"`
	// PartialFingerprints contains strings used for result matching between runs.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317662
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	// Properties contains key/value pairs with additional information.
	Properties *PropertyBag `json:"properties,omitempty"`
}

// CodeFlow describes a sequence of code locations that represent a path.
// For dependency scanning, this represents the dependency chain from the
// application to the vulnerable transitive dependency.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317740
type CodeFlow struct {
	// Message describes what this code flow represents.
	Message *Message `json:"message,omitempty"`
	// ThreadFlows contains the threads that comprise this code flow.
	// For dependency chains, typically one thread showing the import path.
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

// ThreadFlow describes a sequence of locations within a single thread.
// For dependency scanning, each location represents a step in the dependency chain.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317744
type ThreadFlow struct {
	// ID identifies this thread flow within the containing code flow.
	ID string `json:"id,omitempty"`
	// Message describes what this thread flow represents.
	Message *Message `json:"message,omitempty"`
	// Locations contains the sequence of locations comprising the thread flow.
	Locations []ThreadFlowLocation `json:"locations"`
}

// ThreadFlowLocation represents a single step in a thread flow.
// For dependency chains, each step shows a dependency in the chain.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317745
type ThreadFlowLocation struct {
	// Location specifies the code location for this step.
	Location Location `json:"location"`
	// NestingLevel indicates the call stack depth (0 = top-level).
	// For dependency chains: 0 = manifest, 1 = direct dep, 2+ = transitive.
	NestingLevel int `json:"nestingLevel,omitempty"`
	// ExecutionOrder indicates the order within the thread flow.
	ExecutionOrder int `json:"executionOrder,omitempty"`
	// Importance indicates whether this location is essential to understanding.
	// Values: "important", "essential", "unimportant"
	Importance string `json:"importance,omitempty"`
}

// Message contains human-readable text (message object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317459
type Message struct {
	// Text is a plain text message string.
	Text string `json:"text,omitempty"`
	// Markdown is a Markdown message string.
	Markdown string `json:"markdown,omitempty"`
	// ID references a message string defined in the rule's messageStrings.
	// When present, arguments should also be provided for placeholder substitution.
	ID string `json:"id,omitempty"`
	// Arguments are values to substitute into the message template.
	Arguments []string `json:"arguments,omitempty"`
}

// Location describes where a result was found (location object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317670
type Location struct {
	// ID is a non-negative integer unique to this location within the result.
	ID int `json:"id,omitempty"`
	// PhysicalLocation identifies the file and region where the result was found.
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	// LogicalLocations contains logical locations such as package or function names.
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	// Message describes this location (used in code flows and related locations).
	Message *Message `json:"message,omitempty"`
}

// PhysicalLocation identifies a file and region (physicalLocation object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317678
type PhysicalLocation struct {
	// ArtifactLocation identifies the artifact (file) containing the location.
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	// Region identifies the relevant portion of the artifact.
	Region *Region `json:"region,omitempty"`
	// ContextRegion provides surrounding context for the region.
	// Typically a few lines before and after the region for display purposes.
	ContextRegion *Region `json:"contextRegion,omitempty"`
}

// ArtifactLocation identifies an artifact (file) (artifactLocation object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317427
type ArtifactLocation struct {
	// URI is the location of the artifact, possibly relative to a base.
	URI string `json:"uri"`
	// URIBaseID is a key into run.originalUriBaseIds for resolving relative URIs.
	URIBaseID string `json:"uriBaseId,omitempty"`
	// Index is the offset from the beginning of the artifacts array.
	Index int `json:"index,omitempty"`
}

// Region identifies a portion of an artifact (region object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317685
type Region struct {
	// StartLine is the 1-based line number of the first character in the region.
	StartLine int `json:"startLine,omitempty"`
	// StartColumn is the 1-based column number of the first character in the region.
	StartColumn int `json:"startColumn,omitempty"`
	// EndLine is the 1-based line number of the last character in the region.
	EndLine int `json:"endLine,omitempty"`
	// EndColumn is the 1-based column number of the character following the region.
	EndColumn int `json:"endColumn,omitempty"`
	// Snippet contains the text of the region.
	Snippet *ArtifactContent `json:"snippet,omitempty"`
}

// ArtifactContent represents the content of an artifact (artifactContent object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317422
type ArtifactContent struct {
	// Text is the UTF-8 encoded content of the artifact.
	Text string `json:"text,omitempty"`
	// Rendered is a message containing a rendered view of the content.
	Rendered *Message `json:"rendered,omitempty"`
}

// LogicalLocation describes a logical location such as a package or function (logicalLocation object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317719
type LogicalLocation struct {
	// Name is the identifier of the logical location (e.g., function name).
	Name string `json:"name,omitempty"`
	// FullyQualifiedName is the fully qualified name of the logical location.
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	// Kind indicates the type of logical location: "function", "member", "module", "namespace", "package", etc.
	Kind string `json:"kind,omitempty"`
}

// Fix describes a proposed fix for a result (fix object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317746
type Fix struct {
	// Description is a message describing the proposed fix.
	Description Message `json:"description"`
	// Changes contains the changes required to effect the fix.
	Changes []ArtifactChange `json:"artifactChanges,omitempty"`
}

// ArtifactChange describes changes to an artifact (artifactChange object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317752
type ArtifactChange struct {
	// ArtifactLocation identifies the artifact to be changed.
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	// Replacements contains the sequence of replacements within the artifact.
	Replacements []Replacement `json:"replacements,omitempty"`
}

// Replacement describes a text replacement (replacement object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317757
type Replacement struct {
	// DeletedRegion is the region to delete before insertion.
	DeletedRegion Region `json:"deletedRegion"`
	// InsertedContent contains the content to insert.
	InsertedContent InsertedContent `json:"insertedContent,omitempty"`
}

// InsertedContent describes content to insert (artifactContent object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317422
type InsertedContent struct {
	// Text is the UTF-8 encoded content to insert.
	Text string `json:"text,omitempty"`
}

// Artifact describes a file analyzed (artifact object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317611
type Artifact struct {
	// Location identifies the artifact's location.
	Location ArtifactLocation `json:"location"`
	// MimeType is the artifact's MIME type.
	MimeType string `json:"mimeType,omitempty"`
	// Roles contains the roles the artifact plays in the analysis.
	Roles []string `json:"roles,omitempty"`
}

// Invocation describes a single invocation of the tool (invocation object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317567
type Invocation struct {
	// ExecutionSuccessful indicates whether the tool's execution completed successfully.
	ExecutionSuccessful bool `json:"executionSuccessful"`
	// CommandLine is the command line used to invoke the tool.
	CommandLine string `json:"commandLine,omitempty"`
	// StartTimeUTC is the UTC date and time at which the invocation started.
	StartTimeUTC string `json:"startTimeUtc,omitempty"`
	// EndTimeUTC is the UTC date and time at which the invocation ended.
	EndTimeUTC string `json:"endTimeUtc,omitempty"`
	// WorkingDirectory is the working directory for the invocation.
	WorkingDirectory *URI `json:"workingDirectory,omitempty"`
	// ExitCode is the process exit code.
	ExitCode int `json:"exitCode,omitempty"`
	// Properties contains key/value pairs with additional information.
	Properties *struct{} `json:"properties,omitempty"`
}

// VersionControl describes version control information (versionControlDetails object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317602
type VersionControl struct {
	// RepositoryURI is the absolute URI of the repository.
	RepositoryURI string `json:"repositoryUri,omitempty"`
	// RevisionID is a string that uniquely identifies the revision (e.g., commit hash).
	RevisionID string `json:"revisionId,omitempty"`
	// Branch is the name of the branch containing the revision.
	Branch string `json:"branch,omitempty"`
	// MappedTo specifies the location in the local file system to which the root
	// of the repository was mapped at the time of the analysis.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317610
	MappedTo *ArtifactLocation `json:"mappedTo,omitempty"`
}

// PropertyBag holds arbitrary key-value properties (propertyBag object).
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317448
//
// This implementation includes GitHub Code Scanning specific properties:
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#result-object
type PropertyBag struct {
	// SecuritySeverity is a score (0.0-10.0) for GitHub security tab integration.
	// GitHub uses this to determine alert severity in the Security tab.
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#reportingdescriptor-object
	SecuritySeverity float64 `json:"security-severity,omitempty"`
	// Tags are strings used for categorization.
	Tags []string `json:"tags,omitempty"`
	// Precision indicates result accuracy: "very-high", "high", "medium", "low".
	Precision string `json:"precision,omitempty"`
	// ProblemSeverity is the severity for display purposes.
	ProblemSeverity string `json:"problem.severity,omitempty"`
	// FixedVersions lists versions that contain a fix for the vulnerability.
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// Ecosystem is the package ecosystem (e.g., "npm", "go", "pypi").
	Ecosystem string `json:"ecosystem,omitempty"`
	// Package is the name of the affected package.
	Package string `json:"package,omitempty"`
	// Version is the affected package version.
	Version string `json:"version,omitempty"`
	// PURL is the Package URL for the affected component.
	// See: https://github.com/package-url/purl-spec
	PURL string `json:"purl,omitempty"`
	// IsDirect indicates if this is a direct (vs transitive) dependency.
	IsDirect bool `json:"isDirect,omitempty"`
	// CVE is the CVE identifier if available.
	CVE string `json:"cve,omitempty"`
	// Aliases are alternative identifiers (e.g., GHSA, GO-).
	Aliases []string `json:"aliases,omitempty"`
}

// SeverityToScore converts a Deputy severity string to a SARIF security-severity score.
// Uses CVSS v3.x score ranges as reference:
//   - CRITICAL: 9.0-10.0 (returns 9.5)
//   - HIGH: 7.0-8.9 (returns 8.0)
//   - MEDIUM: 4.0-6.9 (returns 5.5)
//   - LOW: 0.1-3.9 (returns 2.0)
//   - UNKNOWN: 0.0
func SeverityToScore(severity string) float64 {
	level := vulnerability.ParseSeverityLevel(severity)
	switch level {
	case vulnerability.SeverityCritical:
		return 9.5
	case vulnerability.SeverityHigh:
		return 8.0
	case vulnerability.SeverityMedium:
		return 5.5
	case vulnerability.SeverityLow:
		return 2.0
	default:
		return 0.0
	}
}

// SeverityToLevel converts a Deputy severity string to a SARIF level.
// SARIF levels: "error", "warning", "note", "none"
func SeverityToLevel(severity string) string {
	level := vulnerability.ParseSeverityLevel(severity)
	switch level {
	case vulnerability.SeverityCritical, vulnerability.SeverityHigh:
		return "error"
	case vulnerability.SeverityMedium:
		return "warning"
	case vulnerability.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// Options configures SARIF output generation.
type Options struct {
	// SARIFVersion specifies the SARIF version to use.
	// Defaults to [DefaultVersion] (2.1.0) if empty or unrecognized.
	// Use [SupportedVersions] to list available versions, or [IsVersionSupported]
	// to check if a specific version is supported.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317450
	SARIFVersion string

	// ToolVersion is the Deputy version string.
	// This appears in tool.driver.version.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317538
	ToolVersion string

	// Repo is the repository URL or path that was scanned.
	// Used in versionControlProvenance.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317602
	Repo string

	// Ref is the git reference (branch/tag) that was scanned.
	// Used in versionControlProvenance.branch.
	Ref string

	// Commit is the git commit hash.
	// Used in versionControlProvenance.revisionId.
	Commit string

	// Category is a unique identifier for this analysis run.
	// GitHub uses this to distinguish different analysis configurations.
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning#providing-data-to-track-code-scanning-alerts-across-runs
	Category string

	// WorkingDirectory is the base path for artifact URIs.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317579
	WorkingDirectory string

	// StartTime is when the scan started.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317580
	StartTime time.Time

	// EndTime is when the scan completed.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317581
	EndTime time.Time
}

// resolveVersion returns the SARIF version and schema to use based on options.
// Uses the version registry to look up schema URIs, falling back to defaults
// for unrecognized versions.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317450
func resolveVersion(opts Options) (version, schema string) {
	v := opts.SARIFVersion
	if v == "" {
		v = DefaultVersion
	}
	return v, schemaForVersion(v)
}

// Convert transforms Deputy scan results to SARIF format.
// Uses SARIF 2.1.0 by default; set Options.SARIFVersion to use a different version.
//
// # Rule and Result Handling
//
// Rules are defined once in tool.driver.rules and referenced by results.
// This follows SARIF best practices (§3.49 reportingDescriptor):
//
//   - Rules are deduplicated by ID (e.g., "CVE-2021-44228", "policy/my-rule")
//   - Each unique vulnerability or policy source creates exactly one rule
//   - Multiple occurrences of the same vulnerability create multiple results
//     that reference the shared rule
//
// Results include both ruleId and ruleIndex for maximum compatibility:
//   - ruleId: Human-readable, stable identifier for the rule
//   - ruleIndex: Index into tool.driver.rules array for efficient lookup
//
// Per SARIF §3.27.5-6, when both are present they MUST reference the same rule,
// which this implementation guarantees by construction.
//
// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317638
func Convert(vulns []report.Vulnerability, policyFindings []report.PolicyFinding, opts Options) *Log {
	version, schema := resolveVersion(opts)
	rules := make([]ReportingDesc, 0, len(vulns)+len(policyFindings))
	results := make([]Result, 0, len(vulns)+len(policyFindings))
	ruleIndex := make(map[string]int)

	// Process vulnerabilities
	for _, v := range vulns {
		// Format rule ID and name with tool prefix for SARIF compliance
		ruleID := formatRuleID(v.ID)
		ruleName := formatRuleName(v.ID)

		// Add rule if not already present
		if _, exists := ruleIndex[ruleID]; !exists {
			ruleIndex[ruleID] = len(rules)
			rule := vulnerabilityToRule(v, ruleID, ruleName)
			rules = append(rules, rule)
		}

		// Create result
		result := vulnerabilityToResult(v, ruleID, ruleIndex[ruleID])
		results = append(results, result)
	}

	// Process policy findings
	for _, pf := range policyFindings {
		// Skip "allow" actions - they're not findings
		if strings.EqualFold(pf.Action, "allow") {
			continue
		}

		// Format rule ID and name with tool prefix for SARIF compliance
		originalID := fmt.Sprintf("policy/%s", pf.Source)
		ruleID := formatRuleID(originalID)
		ruleName := formatRuleName(originalID)

		// Add rule if not already present
		if _, exists := ruleIndex[ruleID]; !exists {
			ruleIndex[ruleID] = len(rules)
			rule := policyFindingToRule(pf, ruleID, ruleName)
			rules = append(rules, rule)
		}

		// Create result
		result := policyFindingToResult(pf, ruleID, ruleIndex[ruleID])
		results = append(results, result)
	}

	// Build the tool component
	// Include fullName for Azure DevOps compatibility (ADO1018)
	fullName := "Deputy"
	if opts.ToolVersion != "" {
		fullName = fmt.Sprintf("Deputy %s", opts.ToolVersion)
	}
	driver := ToolComponent{
		Name:           "Deputy",
		FullName:       fullName,
		Version:        opts.ToolVersion,
		InformationURI: "https://github.com/picatz/deputy",
		Organization:   "picatz",
		Rules:          rules,
		ShortDesc: &Message{
			Text: "Software supply chain security scanner",
		},
		FullDesc: &Message{
			Text: "Deputy scans dependencies for vulnerabilities, generates SBOMs, and enforces security policies using the OSV database.",
		},
	}

	// Build invocation
	invocations := []Invocation{
		{
			ExecutionSuccessful: true,
			StartTimeUTC:        formatTime(opts.StartTime),
			EndTimeUTC:          formatTime(opts.EndTime),
		},
	}
	if opts.WorkingDirectory != "" {
		invocations[0].WorkingDirectory = &URI{URI: opts.WorkingDirectory}
	}

	// Build version control provenance
	var vcs []VersionControl
	var originalURIBases map[string]URI
	if opts.Repo != "" || opts.Commit != "" {
		vc := VersionControl{
			RepositoryURI: opts.Repo,
			RevisionID:    opts.Commit,
			Branch:        opts.Ref,
			// MappedTo links artifact locations to the repository root
			MappedTo: &ArtifactLocation{
				URIBaseID: "%SRCROOT%",
			},
		}
		vcs = append(vcs, vc)
		// Define the base URI for %SRCROOT%
		originalURIBases = map[string]URI{
			"%SRCROOT%": {URI: ""},
		}
	}

	// Build automation details for run identification.
	// Always provide automationDetails for Azure DevOps compatibility (ADO1014).
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317523
	automationID := opts.Category
	if automationID == "" {
		automationID = "deputy-scan"
	}
	automation := &RunAutomation{
		ID: automationID,
	}

	run := Run{
		Tool: Tool{
			Driver: driver,
		},
		Results:         results,
		Invocations:     invocations,
		VersionControl:  vcs,
		AutomationID:    automation,
		OriginalURIBase: originalURIBases,
	}

	return &Log{
		Schema:  schema,
		Version: version,
		Runs:    []Run{run},
	}
}

// vulnerabilityToRule converts a vulnerability to a SARIF rule definition.
// ruleID is the formatted rule ID (with tool prefix for SARIF2009 compliance).
func vulnerabilityToRule(v report.Vulnerability, ruleID, ruleName string) ReportingDesc {
	shortDesc := v.Summary
	if shortDesc == "" {
		shortDesc = fmt.Sprintf("Vulnerability %s in %s", v.ID, v.Package)
	}

	fullDesc := v.Details
	if fullDesc == "" {
		fullDesc = shortDesc
	}

	helpURI := ""
	if len(v.References) > 0 {
		helpURI = v.References[0]
	}

	// Build help text with references
	var helpText strings.Builder
	helpText.WriteString(fmt.Sprintf("# %s\n\n", v.ID))
	helpText.WriteString(fmt.Sprintf("%s\n\n", fullDesc))

	if len(v.FixedVersions) > 0 {
		helpText.WriteString(fmt.Sprintf("## Fixed Versions\n\n%s\n\n", strings.Join(v.FixedVersions, ", ")))
	}

	if len(v.References) > 0 {
		helpText.WriteString("## References\n\n")
		for _, ref := range v.References {
			helpText.WriteString(fmt.Sprintf("- %s\n", ref))
		}
	}

	properties := &PropertyBag{
		SecuritySeverity: SeverityToScore(v.Severity),
		Tags:             []string{"security", "vulnerability", "dependency"},
		Precision:        "high",
	}

	if v.CVE != "" {
		properties.CVE = v.CVE
	}
	if len(v.FixedVersions) > 0 {
		properties.FixedVersions = v.FixedVersions
	}
	if v.Ecosystem != "" {
		properties.Ecosystem = v.Ecosystem
	}

	// Define message templates for SARIF2002 compliance
	// Templates use {0}, {1}, etc. placeholders that get filled by result.message.arguments
	// SARIF2015: Each placeholder must be individually enclosed in single quotes
	// SARIF2001: Messages must end with a period (the template itself, not just the argument)
	messageStrings := map[string]MultiformatMessageString{
		"default": {
			Text:     "Vulnerable dependency: '{0}'@'{1}' (severity: '{2}'). Status: '{3}'.",
			Markdown: "Vulnerable dependency: `{0}`@`{1}` (severity: `{2}`). Status: `{3}`.",
		},
		"withFix": {
			Text:     "Vulnerable dependency: '{0}'@'{1}' (severity: '{2}'). Upgrade to: '{3}'.",
			Markdown: "Vulnerable dependency: `{0}`@`{1}` (severity: `{2}`). Upgrade to: `{3}`.",
		},
	}

	return ReportingDesc{
		ID:   ruleID,
		Name: ruleName,
		ShortDescription: &Message{
			Text: truncate(shortDesc, MaxShortDescriptionLength),
		},
		FullDescription: &Message{
			Text:     truncate(fullDesc, MaxFullDescriptionLength),
			Markdown: truncate(fullDesc, MaxFullDescriptionLength),
		},
		MessageStrings: messageStrings,
		HelpURI:        helpURI,
		Help: &Message{
			Text:     helpText.String(),
			Markdown: helpText.String(),
		},
		DefaultConfig: &RuleConfig{
			Level: SeverityToLevel(v.Severity),
		},
		Properties: properties,
	}
}

// vulnerabilityToResult converts a vulnerability to a SARIF result.
// ruleID is the formatted rule ID (with tool prefix for SARIF2009 compliance).
func vulnerabilityToResult(v report.Vulnerability, ruleID string, ruleIdx int) Result {
	// Build message using templates (SARIF2002 compliance)
	// Use "withFix" template if fix is available, otherwise "default"
	// ADO1015/ADO1017: Azure DevOps requires 'text' property even when using templates
	var resultMsg Message
	severity := v.Severity
	if severity == "" {
		severity = "UNKNOWN"
	}

	if len(v.FixedVersions) > 0 {
		fixVersions := strings.Join(v.FixedVersions, " or ")
		resultMsg = Message{
			// Text is required by Azure DevOps (ADO1015/ADO1017)
			Text:      fmt.Sprintf("Vulnerable dependency: '%s'@'%s' (severity: '%s'). Upgrade to: '%s'.", v.Package, v.Version, severity, fixVersions),
			ID:        "withFix",
			Arguments: []string{v.Package, v.Version, severity, fixVersions},
		}
	} else {
		resultMsg = Message{
			// Text is required by Azure DevOps (ADO1015/ADO1017)
			// Note: argument doesn't include trailing period since template adds it
			Text:      fmt.Sprintf("Vulnerable dependency: '%s'@'%s' (severity: '%s'). Status: 'No fix available yet'.", v.Package, v.Version, severity),
			ID:        "default",
			Arguments: []string{v.Package, v.Version, severity, "No fix available yet"},
		}
	}

	// Build locations from manifest files
	// GitHub Code Scanning requires at least one location with region.startLine for display.
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
	locations := make([]Location, 0)
	for _, loc := range v.Locations {
		if loc == "" {
			continue
		}

		// Try to find the exact line in the manifest file
		// This provides snippet and context region for better display (SARIF2010/SARIF2011)
		physLoc := &PhysicalLocation{
			ArtifactLocation: ArtifactLocation{
				URI:       normalizeURI(loc),
				URIBaseID: "%SRCROOT%",
			},
			Region: &Region{
				StartLine: 1, // Default if we can't find the exact line
			},
		}

		// Attempt to extract snippet from manifest file
		if snippet := findPackageInManifest(loc, v.Package, v.Version); snippet != nil {
			// Found the package declaration - use exact location
			physLoc.Region = &Region{
				StartLine: snippet.Line,
				Snippet: &ArtifactContent{
					Text: snippet.Snippet,
				},
			}
			// Add context region (surrounding lines) only if it's a proper superset of region
			// SARIF1008: contextRegion must be a superset of region, or omitted if identical
			if len(snippet.ContextLines) > 1 {
				contextEnd := snippet.ContextStart + len(snippet.ContextLines) - 1
				// Only add if context actually extends beyond the single line
				if snippet.ContextStart < snippet.Line || contextEnd > snippet.Line {
					physLoc.ContextRegion = &Region{
						StartLine: snippet.ContextStart,
						EndLine:   contextEnd,
						Snippet: &ArtifactContent{
							Text: strings.Join(snippet.ContextLines, "\n"),
						},
					}
				}
			}
		}
		// Note: We don't add a fake contextRegion for non-manifest locations
		// SARIF1008 requires contextRegion to be a proper superset of region

		locations = append(locations, Location{
			PhysicalLocation: physLoc,
			LogicalLocations: []LogicalLocation{
				{
					Name:               v.Package,
					FullyQualifiedName: v.PURL,
					Kind:               "package",
				},
			},
		})
	}

	// If no locations, create a logical-only location (no physical file)
	// This is valid SARIF but may not display optimally in GitHub
	if len(locations) == 0 {
		locations = append(locations, Location{
			LogicalLocations: []LogicalLocation{
				{
					Name:               v.Package,
					FullyQualifiedName: v.PURL,
					Kind:               "package",
				},
			},
		})
	}

	// Build related locations for affected imports/symbols.
	// This provides additional context about which code paths use the vulnerable package.
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317669
	var relatedLocations []Location
	for _, imp := range v.AffectedImports {
		loc := Location{
			LogicalLocations: []LogicalLocation{
				{
					Name:               imp.Path,
					FullyQualifiedName: imp.Path,
					Kind:               "module",
				},
			},
		}
		// Add symbols if available
		if len(imp.Symbols) > 0 {
			loc.LogicalLocations[0].Name = fmt.Sprintf("%s (%s)", imp.Path, strings.Join(imp.Symbols, ", "))
		}
		relatedLocations = append(relatedLocations, loc)
	}

	// Build code flows for affected imports.
	// Code flows show the path from application code to the vulnerable code.
	// For dependency scanning, we show: manifest → import → vulnerable symbols
	// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317740
	var codeFlows []CodeFlow
	if len(v.AffectedImports) > 0 && len(v.Locations) > 0 {
		threadFlowLocs := make([]ThreadFlowLocation, 0, len(v.AffectedImports)+1)

		// First location: the manifest file where the dependency is declared
		threadFlowLocs = append(threadFlowLocs, ThreadFlowLocation{
			Location: Location{
				PhysicalLocation: &PhysicalLocation{
					ArtifactLocation: ArtifactLocation{
						URI:       normalizeURI(v.Locations[0]),
						URIBaseID: "%SRCROOT%",
					},
					Region: &Region{StartLine: 1},
				},
				Message: &Message{
					Text: fmt.Sprintf("Dependency %s@%s declared here", v.Package, v.Version),
				},
			},
			NestingLevel:   0,
			ExecutionOrder: 1,
			Importance:     "essential",
		})

		// Subsequent locations: each affected import path
		for i, imp := range v.AffectedImports {
			var msgText string
			if len(imp.Symbols) > 0 {
				msgText = fmt.Sprintf("Imports %s (vulnerable symbols: %s)", imp.Path, strings.Join(imp.Symbols, ", "))
			} else {
				msgText = fmt.Sprintf("Imports %s", imp.Path)
			}
			threadFlowLocs = append(threadFlowLocs, ThreadFlowLocation{
				Location: Location{
					LogicalLocations: []LogicalLocation{
						{
							Name:               imp.Path,
							FullyQualifiedName: imp.Path,
							Kind:               "module",
						},
					},
					Message: &Message{Text: msgText},
				},
				NestingLevel:   1,
				ExecutionOrder: i + 2,
				Importance:     "important",
			})
		}

		codeFlows = append(codeFlows, CodeFlow{
			Message: &Message{
				Text: fmt.Sprintf("Dependency chain for %s", v.Package),
			},
			ThreadFlows: []ThreadFlow{
				{
					ID: "dependency-chain",
					Message: &Message{
						Text: "Shows how the vulnerable package is used",
					},
					Locations: threadFlowLocs,
				},
			},
		})
	}

	// Build fingerprints for tracking across runs.
	// GitHub uses partialFingerprints to deduplicate alerts and track them across commits.
	// See: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
	fingerprints := map[string]string{
		"vulnerabilityId/v1": v.ID,
		"package/v1":         v.Package,
		"version/v1":         v.Version,
	}
	if v.PURL != "" {
		fingerprints["purl/v1"] = v.PURL
	}
	// primaryLocationLineHash is strongly recommended by GitHub for stable alert tracking.
	// For dependency vulnerabilities, we create a hash from the vuln ID + package + location.
	if len(v.Locations) > 0 {
		fingerprints["primaryLocationLineHash"] = HashFingerprint(v.ID, v.Package, v.Locations[0])
	} else {
		fingerprints["primaryLocationLineHash"] = HashFingerprint(v.ID, v.Package, "")
	}

	// Build fix suggestions if fixed versions are available.
	// SARIF §3.55.3 requires artifactChanges with minItems=1.
	// We provide a placeholder replacement pointing to the manifest file.
	var fixes []Fix
	if len(v.FixedVersions) > 0 && len(v.Locations) > 0 {
		fixedVersion := v.FixedVersions[0]
		// Find the best location for the fix (prefer manifest files over binaries)
		fixLocation := findManifestLocation(v.Locations)
		fixes = append(fixes, Fix{
			Description: Message{
				Text: fmt.Sprintf("Upgrade %s from %s to %s", v.Package, v.Version, fixedVersion),
			},
			Changes: []ArtifactChange{
				{
					ArtifactLocation: ArtifactLocation{
						URI:       normalizeURI(fixLocation),
						URIBaseID: "%SRCROOT%",
					},
					Replacements: []Replacement{
						{
							// Point to line 1 as a placeholder since exact line requires parsing
							DeletedRegion: Region{StartLine: 1, EndLine: 1},
							InsertedContent: InsertedContent{
								Text: fmt.Sprintf("# Upgrade %s to %s", v.Package, fixedVersion),
							},
						},
					},
				},
			},
		})
	}

	// Build properties
	properties := &PropertyBag{
		Package:   v.Package,
		Version:   v.Version,
		Ecosystem: v.Ecosystem,
		PURL:      v.PURL,
		IsDirect:  v.IsDirect,
	}
	if v.CVE != "" {
		properties.CVE = v.CVE
	}
	if len(v.FixedVersions) > 0 {
		properties.FixedVersions = slices.Clone(v.FixedVersions)
	}
	if len(v.Aliases) > 0 {
		properties.Aliases = slices.Clone(v.Aliases)
	}

	return Result{
		RuleID:              ruleID,
		RuleIndex:           ruleIdx,
		Level:               SeverityToLevel(v.Severity),
		Message:             resultMsg,
		Locations:           locations,
		RelatedLocations:    relatedLocations,
		CodeFlows:           codeFlows,
		Fixes:               fixes,
		PartialFingerprints: fingerprints,
		Properties:          properties,
	}
}

// policyFindingToRule converts a policy finding to a SARIF rule definition.
// ruleID is the formatted rule ID (with tool prefix for SARIF2009 compliance).
func policyFindingToRule(pf report.PolicyFinding, ruleID, ruleName string) ReportingDesc {
	shortDesc := pf.Reason
	if shortDesc == "" {
		shortDesc = fmt.Sprintf("Policy violation: %s", pf.Source)
	}

	fullDesc := pf.Message
	if fullDesc == "" {
		fullDesc = shortDesc
	}

	level := "warning"
	if strings.EqualFold(pf.Action, "deny") {
		level = "error"
	}

	var helpText strings.Builder
	helpText.WriteString(fmt.Sprintf("# Policy: %s\n\n", pf.Source))
	helpText.WriteString(fmt.Sprintf("%s\n\n", fullDesc))
	if pf.Remediation != "" {
		helpText.WriteString(fmt.Sprintf("## Remediation\n\n%s\n", pf.Remediation))
	}

	return ReportingDesc{
		ID:   ruleID,
		Name: ruleName,
		ShortDescription: &Message{
			Text: truncate(shortDesc, MaxShortDescriptionLength),
		},
		FullDescription: &Message{
			Text: truncate(fullDesc, MaxFullDescriptionLength),
		},
		Help: &Message{
			Text:     helpText.String(),
			Markdown: helpText.String(),
		},
		DefaultConfig: &RuleConfig{
			Level: level,
		},
		Properties: &PropertyBag{
			Tags: []string{"security", "policy"},
		},
	}
}

// policyFindingToResult converts a policy finding to a SARIF result.
// ruleID is the formatted rule ID (with tool prefix for SARIF2009 compliance).
func policyFindingToResult(pf report.PolicyFinding, ruleID string, ruleIdx int) Result {
	level := "warning"
	if strings.EqualFold(pf.Action, "deny") {
		level = "error"
	}

	msg := pf.Reason
	if pf.Message != "" {
		msg = pf.Message
	}
	if msg == "" {
		msg = fmt.Sprintf("Policy %s triggered %s action", pf.Source, pf.Action)
	}

	fingerprints := map[string]string{
		"policySource/v1": pf.Source,
		"policyAction/v1": pf.Action,
	}
	if pf.Code != "" {
		fingerprints["policyCode/v1"] = pf.Code
	}
	// primaryLocationLineHash for stable alert tracking
	fingerprints["primaryLocationLineHash"] = HashFingerprint(ruleID, pf.Action, pf.Reason)

	return Result{
		RuleID:              ruleID,
		RuleIndex:           ruleIdx,
		Level:               level,
		Message:             Message{Text: msg},
		PartialFingerprints: fingerprints,
	}
}

// Helper functions

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func normalizeURI(path string) string {
	// Remove leading ./ and normalize slashes
	path = strings.TrimPrefix(path, "./")
	path = strings.TrimPrefix(path, "/")
	return path
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// findManifestLocation returns the best location for a fix suggestion.
// Prefers manifest files (go.mod, package.json, etc.) over binary names.
func findManifestLocation(locations []string) string {
	// Known manifest file patterns
	manifests := []string{
		"go.mod", "go.sum",
		"package.json", "package-lock.json", "npm-shrinkwrap.json",
		"yarn.lock", "pnpm-lock.yaml",
		"requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
		"Gemfile", "Gemfile.lock",
		"Cargo.toml", "Cargo.lock",
		"pom.xml", "build.gradle", "build.gradle.kts",
		"composer.json", "composer.lock",
	}

	for _, loc := range locations {
		for _, manifest := range manifests {
			if strings.HasSuffix(loc, manifest) {
				return loc
			}
		}
	}
	// Fall back to first location if no manifest found
	if len(locations) > 0 {
		return locations[0]
	}
	return ""
}

// HashFingerprint creates a stable hash for primaryLocationLineHash.
// GitHub uses this to track alerts across runs and commits.
// The hash should be stable for the same logical issue.
func HashFingerprint(parts ...string) string {
	// Use a simple concatenation with separator, then hash it.
	// SHA-256 is standard for fingerprinting, truncated to 16 chars for readability.
	combined := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", h[:8]) // 16 hex chars
}

// formatRuleID creates a SARIF-compliant rule ID with tool-specific prefix.
// SARIF2009 recommends: "<tool-prefix><numeric-rule-number>" (e.g., "CS2001").
// We generate a stable numeric ID from the original vulnerability/policy ID
// using a hash to ensure consistency across runs.
func formatRuleID(originalID string) string {
	// Generate a stable 4-digit number from the original ID
	h := sha256.Sum256([]byte(originalID))
	// Use first 2 bytes as uint16, mod 10000 to get 4 digits
	num := (uint16(h[0])<<8 | uint16(h[1])) % 10000
	return fmt.Sprintf("DEP%04d", num)
}

// formatRuleName creates a SARIF2012-compliant PascalCase name from the original ID.
// The SARIF2012 validator requires names to match: ^(\p{Lu}[\p{Ll}\p{Nd}]+)*$
// This means each "word" must be: uppercase letter + one or more lowercase/digits.
// We convert the original ID (e.g., "CVE-2021-44228" or "GHSA-f786-75f3-74xj") to
// PascalCase (e.g., "Cve202144228" or "Ghsaf78675f374xj").
// SARIF1001 requires name to be different from id if both are present.
// The result is truncated to MaxRuleNameLength (255 chars) at a word boundary.
func formatRuleName(originalID string) string {
	// Split on non-alphanumeric characters and convert to PascalCase
	var result strings.Builder
	newWord := true

	for _, r := range originalID {
		// Stop if we're at the max length (leave room for potential truncation)
		if result.Len() >= MaxRuleNameLength {
			break
		}

		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if newWord {
				// First char of word: uppercase
				if r >= 'a' && r <= 'z' {
					result.WriteByte(byte(r - 32)) // to upper
				} else if r >= 'A' && r <= 'Z' {
					result.WriteByte(byte(r))
				} else {
					// Digit at start of word - need a letter prefix for valid PascalCase
					result.WriteString("N") // "N" for number
					result.WriteByte(byte(r))
				}
				newWord = false
			} else {
				// Subsequent chars: lowercase (letters) or as-is (digits)
				if r >= 'A' && r <= 'Z' {
					result.WriteByte(byte(r - 'A' + 'a')) // to lower
				} else {
					result.WriteByte(byte(r))
				}
			}
		} else {
			// Non-alphanumeric: start a new word
			newWord = true
		}
	}

	if result.Len() == 0 {
		return "UnknownRule"
	}
	return result.String()
}

// snippetInfo contains location and content information extracted from a manifest file.
type snippetInfo struct {
	Line         int      // 1-based line number
	Snippet      string   // The matching line content
	ContextLines []string // Surrounding lines for context (typically 2 before and 2 after)
	ContextStart int      // 1-based line number of first context line
}

// findPackageInManifest searches a manifest file for a package declaration.
// Returns nil if the file cannot be read or the package is not found.
// This handles common cases but may not find transitive-only dependencies.
func findPackageInManifest(manifestPath, packageName, version string) *snippetInfo {
	// Resolve the path (may be relative to working directory)
	absPath := manifestPath
	if !filepath.IsAbs(manifestPath) {
		if wd, err := os.Getwd(); err == nil {
			absPath = filepath.Join(wd, manifestPath)
		}
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil // File not accessible
	}
	defer file.Close()

	// Build search patterns based on manifest type and package name
	patterns := buildSearchPatterns(manifestPath, packageName, version)
	if len(patterns) == 0 {
		return nil
	}

	// Read file and search for patterns
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil
	}

	// Search for the package declaration
	for i, line := range lines {
		for _, pattern := range patterns {
			if strings.Contains(line, pattern) {
				// Found a match - extract snippet and context
				info := &snippetInfo{
					Line:    i + 1, // 1-based
					Snippet: line,
				}

				// Extract context (2 lines before and after)
				contextStart := i - 2
				if contextStart < 0 {
					contextStart = 0
				}
				contextEnd := i + 3
				if contextEnd > len(lines) {
					contextEnd = len(lines)
				}

				info.ContextStart = contextStart + 1 // 1-based
				info.ContextLines = lines[contextStart:contextEnd]

				return info
			}
		}
	}

	return nil // Package not found in manifest
}

// buildSearchPatterns creates search patterns for finding a package in a manifest.
// Different manifest formats require different patterns.
func buildSearchPatterns(manifestPath, packageName, version string) []string {
	base := filepath.Base(manifestPath)
	var patterns []string

	switch {
	case base == "go.mod" || base == "go.sum":
		// Go modules: "package version" or "package v1.2.3"
		patterns = append(patterns, packageName)
		if version != "" {
			patterns = append(patterns, packageName+" "+version)
			patterns = append(patterns, packageName+" v"+version)
		}

	case base == "package.json" || base == "package-lock.json":
		// npm: "package": "version" or "package": "^version"
		patterns = append(patterns, `"`+packageName+`"`)

	case base == "requirements.txt" || base == "Pipfile" || base == "pyproject.toml":
		// Python: package==version or package>=version
		patterns = append(patterns, packageName)

	case base == "Gemfile" || base == "Gemfile.lock":
		// Ruby: gem 'package' or package (version)
		patterns = append(patterns, packageName)

	case base == "Cargo.toml" || base == "Cargo.lock":
		// Rust: package = "version" or name = "package"
		patterns = append(patterns, packageName)

	case base == "pom.xml" || base == "build.gradle" || base == "build.gradle.kts":
		// Java: artifactId or implementation/compile dependency
		patterns = append(patterns, packageName)
		// For Maven coordinates like "org.apache:package:version"
		if parts := strings.Split(packageName, ":"); len(parts) >= 2 {
			patterns = append(patterns, parts[len(parts)-1]) // artifact ID
		}

	default:
		// Generic: just search for the package name
		patterns = append(patterns, packageName)
	}

	return patterns
}
