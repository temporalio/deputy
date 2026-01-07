// Package secrets provides secret detection capabilities.
package secrets

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// PolicyFinding represents a secret finding for CEL policy evaluation.
// This is a CEL-friendly representation of a Finding.
type PolicyFinding struct {
	// Type is the secret type (e.g., "github_token", "aws_access_key").
	Type string `json:"type"`
	// Description provides context about the finding.
	Description string `json:"description"`
	// File is the path where the secret was found.
	File string `json:"file"`
	// Line is the line number (1-indexed).
	Line int `json:"line"`
	// Column is the column number (1-indexed).
	Column int `json:"column"`
	// Confidence is the detection confidence (0.0-1.0).
	Confidence float64 `json:"confidence"`
	// Validated indicates if the secret was verified as active.
	Validated bool `json:"validated"`
	// Redacted is the safe redacted representation.
	Redacted string `json:"redacted"`
	// Source identifies where the secret was found (for container scans).
	Source string `json:"source,omitempty"`
	// InBaseImage indicates if found in base image layer (for containers).
	InBaseImage bool `json:"inBaseImage,omitempty"`
	// LayerIndex is the layer where the secret was found (for containers).
	LayerIndex int `json:"layerIndex,omitempty"`
}

// PolicyReport represents the full secrets scan report for CEL evaluation.
type PolicyReport struct {
	// Target is what was scanned (directory, image, archive).
	Target string `json:"target"`
	// FilesScanned is the number of files analyzed.
	FilesScanned int `json:"filesScanned"`
	// SecretsFound is the total number of secrets detected.
	SecretsFound int `json:"secretsFound"`
	// HighConfidenceCount is findings with >= 90% confidence.
	HighConfidenceCount int `json:"highConfidenceCount"`
	// ValidatedCount is the number of verified active secrets.
	ValidatedCount int `json:"validatedCount"`
	// Stats provides aggregate counts by secret type.
	Stats map[string]int `json:"stats"`
}

// ToPolicyFinding converts a Finding to a PolicyFinding for CEL evaluation.
func ToPolicyFinding(f Finding) PolicyFinding {
	return PolicyFinding{
		Type:        string(f.Type),
		Description: f.Description,
		File:        f.File,
		Line:        f.Line,
		Column:      f.Column,
		Confidence:  f.Confidence,
		Validated:   f.Validated,
		Redacted:    f.Redacted,
	}
}

// ToPolicyFindings converts a slice of Findings to PolicyFindings.
func ToPolicyFindings(findings []Finding) []PolicyFinding {
	result := make([]PolicyFinding, len(findings))
	for i, f := range findings {
		result[i] = ToPolicyFinding(f)
	}
	return result
}

// ContainerFindingToPolicyFinding converts a ContainerFinding to PolicyFinding.
func ContainerFindingToPolicyFinding(f ContainerFinding) PolicyFinding {
	pf := ToPolicyFinding(f.Finding)
	pf.Source = string(f.Source)
	pf.InBaseImage = f.InBaseImage
	pf.LayerIndex = f.LayerIndex
	return pf
}

// ContainerFindingsToPolicyFindings converts ContainerFindings to PolicyFindings.
func ContainerFindingsToPolicyFindings(findings []ContainerFinding) []PolicyFinding {
	result := make([]PolicyFinding, len(findings))
	for i, f := range findings {
		result[i] = ContainerFindingToPolicyFinding(f)
	}
	return result
}

// BuildPolicyReport creates a PolicyReport from findings for CEL evaluation.
func BuildPolicyReport(target string, filesScanned int, findings []Finding) PolicyReport {
	stats := make(map[string]int)
	var highConf, validated int
	for _, f := range findings {
		stats[string(f.Type)]++
		if f.Confidence >= 0.9 {
			highConf++
		}
		if f.Validated {
			validated++
		}
	}

	return PolicyReport{
		Target:              target,
		FilesScanned:        filesScanned,
		SecretsFound:        len(findings),
		HighConfidenceCount: highConf,
		ValidatedCount:      validated,
		Stats:               stats,
	}
}

// SecretsPolicyVariables contains the CEL variable definitions for secrets policies.
// These are the variables available in CEL expressions when evaluating secrets policies.
var SecretsPolicyVariables = []cel.EnvOption{
	// secret - the current finding being evaluated (for secrets_finding entrypoint)
	cel.Variable("secret", cel.MapType(cel.StringType, cel.DynType)),

	// secrets - all findings in the report (for secrets_report entrypoint)
	cel.Variable("secrets", cel.ListType(cel.MapType(cel.StringType, cel.DynType))),

	// report - the full scan report (for secrets_report entrypoint)
	cel.Variable("report", cel.MapType(cel.StringType, cel.DynType)),
}

// SecretsFindingActivation creates a CEL activation for a single finding evaluation.
func SecretsFindingActivation(finding PolicyFinding) map[string]any {
	return map[string]any{
		"secret": findingToMap(finding),
	}
}

// SecretsReportActivation creates a CEL activation for full report evaluation.
func SecretsReportActivation(report PolicyReport, findings []PolicyFinding) map[string]any {
	secretsList := make([]map[string]any, len(findings))
	for i, f := range findings {
		secretsList[i] = findingToMap(f)
	}

	return map[string]any{
		"secrets": secretsList,
		"report":  reportToMap(report),
	}
}

// findingToMap converts a PolicyFinding to a map for CEL.
func findingToMap(f PolicyFinding) map[string]any {
	m := map[string]any{
		"type":        f.Type,
		"description": f.Description,
		"file":        f.File,
		"line":        f.Line,
		"column":      f.Column,
		"confidence":  f.Confidence,
		"validated":   f.Validated,
		"redacted":    f.Redacted,
	}
	if f.Source != "" {
		m["source"] = f.Source
		m["inBaseImage"] = f.InBaseImage
		m["layerIndex"] = f.LayerIndex
	}
	return m
}

// reportToMap converts a PolicyReport to a map for CEL.
func reportToMap(r PolicyReport) map[string]any {
	return map[string]any{
		"target":              r.Target,
		"filesScanned":        r.FilesScanned,
		"secretsFound":        r.SecretsFound,
		"highConfidenceCount": r.HighConfidenceCount,
		"validatedCount":      r.ValidatedCount,
		"stats":               r.Stats,
	}
}

// SecretsHelperFunctions returns CEL helper functions for secrets policies.
func SecretsHelperFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		// isHighConfidence(secret) - returns true if confidence >= 0.9
		cel.Function("isHighConfidence",
			cel.Overload("isHighConfidence_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					// Try to get confidence field from the map
					if m, ok := val.Value().(map[string]any); ok {
						if conf, ok := m["confidence"].(float64); ok {
							return types.Bool(conf >= 0.9)
						}
					}
					// Try traits-based access for CEL maps
					if indexer, ok := val.(traits.Indexer); ok {
						conf := indexer.Get(types.String("confidence"))
						if conf != nil && conf.Type() != types.ErrType {
							if confFloat, ok := conf.Value().(float64); ok {
								return types.Bool(confFloat >= 0.9)
							}
						}
					}
					return types.False
				}),
			),
		),

		// isVerified(secret) - returns true if the secret was verified as active
		cel.Function("isVerified",
			cel.Overload("isVerified_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					if m, ok := val.Value().(map[string]any); ok {
						if validated, ok := m["validated"].(bool); ok {
							return types.Bool(validated)
						}
					}
					if indexer, ok := val.(traits.Indexer); ok {
						validated := indexer.Get(types.String("validated"))
						if validated != nil && validated.Type() != types.ErrType {
							if b, ok := validated.Value().(bool); ok {
								return types.Bool(b)
							}
						}
					}
					return types.False
				}),
			),
		),

		// secretType(secret) - returns the secret type as a string
		cel.Function("secretType",
			cel.Overload("secretType_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.StringType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					if m, ok := val.Value().(map[string]any); ok {
						if t, ok := m["type"].(string); ok {
							return types.String(t)
						}
					}
					if indexer, ok := val.(traits.Indexer); ok {
						t := indexer.Get(types.String("type"))
						if t != nil && t.Type() != types.ErrType {
							if s, ok := t.Value().(string); ok {
								return types.String(s)
							}
						}
					}
					return types.String("")
				}),
			),
		),
	}
}

// Example policy YAML for secrets:
//
// policies:
//   - name: block-high-confidence-secrets
//     entrypoints: ["secrets_report"]
//     rules:
//       - action: deny
//         when: secrets.exists(s, isHighConfidence(s))
//         reason: "High-confidence secrets detected"
//
//   - name: block-verified-secrets
//     entrypoints: ["secrets_finding"]
//     rules:
//       - action: deny
//         when: isVerified(secret)
//         reason: "Verified active secret detected"
//
//   - name: allow-low-confidence
//     entrypoints: ["secrets_finding"]
//     rules:
//       - action: allow
//         when: secret.confidence < 0.7
//         reason: "Low confidence findings are allowed"
//
//   - name: block-cloud-credentials
//     entrypoints: ["secrets_finding"]
//     vars:
//       cloudSecrets: ["aws_access_key", "aws_secret_key", "gcp_api_key", "gcp_service_account_key"]
//     rules:
//       - action: deny
//         when: secretType(secret) in cloudSecrets
//         reason: "Cloud credentials must not be committed"
