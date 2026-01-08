// Package proto provides helpers for working with deputy proto types directly.
//
// Proto-First Architecture:
//
// Deputy uses a proto-first approach where proto types defined in api/deputy/*/*.proto
// are the source of truth for API contracts. This package provides:
//
//  1. Validation via protovalidate (see validate.go)
//  2. Helper functions for working with proto types directly
//  3. Conversion functions for legacy internal types (see types.go, scan.go, remediation.go)
//
// New code should prefer using proto types directly with these helpers rather than
// converting to/from internal types. Internal types exist for legacy compatibility
// and domain logic that requires Go-specific features (methods, interfaces, etc.).
//
// Guidelines:
//   - Use domain proto types at API boundaries (server handlers, client interfaces)
//   - Use protovalidate for input validation instead of manual checks
//   - Use helper functions in this package for common operations
//   - Only convert to internal types when needed for legacy code integration
package proto

import (
	"strings"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
)

// TargetKind helpers - work with proto TargetKind directly

// ParseTargetKind converts a string target kind to proto TargetKind.
// Returns TARGET_KIND_UNSPECIFIED for unknown values.
func ParseTargetKind(s string) targetv1.TargetKind {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "dir", "directory":
		return targetv1.TargetKind_TARGET_KIND_DIR
	case "file":
		return targetv1.TargetKind_TARGET_KIND_FILE
	case "binary":
		return targetv1.TargetKind_TARGET_KIND_BINARY
	case "git", "repo", "repository":
		return targetv1.TargetKind_TARGET_KIND_GIT
	case "container-image", "image", "container", "docker":
		return targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE
	case "container-instance":
		return targetv1.TargetKind_TARGET_KIND_CONTAINER_INSTANCE
	case "vm-image", "vm":
		return targetv1.TargetKind_TARGET_KIND_VM_IMAGE
	case "extension":
		return targetv1.TargetKind_TARGET_KIND_EXTENSION
	case "sbom":
		return targetv1.TargetKind_TARGET_KIND_SBOM
	case "purl":
		return targetv1.TargetKind_TARGET_KIND_PURL
	case "dockerfile":
		return targetv1.TargetKind_TARGET_KIND_DOCKERFILE
	default:
		return targetv1.TargetKind_TARGET_KIND_UNSPECIFIED
	}
}

// TargetKindString returns a human-readable string for a TargetKind.
func TargetKindString(k targetv1.TargetKind) string {
	switch k {
	case targetv1.TargetKind_TARGET_KIND_DIR:
		return "dir"
	case targetv1.TargetKind_TARGET_KIND_FILE:
		return "file"
	case targetv1.TargetKind_TARGET_KIND_BINARY:
		return "binary"
	case targetv1.TargetKind_TARGET_KIND_GIT:
		return "git"
	case targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE:
		return "container-image"
	case targetv1.TargetKind_TARGET_KIND_CONTAINER_INSTANCE:
		return "container-instance"
	case targetv1.TargetKind_TARGET_KIND_VM_IMAGE:
		return "vm-image"
	case targetv1.TargetKind_TARGET_KIND_EXTENSION:
		return "extension"
	case targetv1.TargetKind_TARGET_KIND_SBOM:
		return "sbom"
	case targetv1.TargetKind_TARGET_KIND_PURL:
		return "purl"
	case targetv1.TargetKind_TARGET_KIND_DOCKERFILE:
		return "dockerfile"
	default:
		return "unknown"
	}
}

// Severity helpers - work with proto Severity directly

// ParseSeverityLevel converts a string severity to proto SeverityLevel.
func ParseSeverityLevel(s string) vulnerabilityv1.SeverityLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL
	case "HIGH":
		return vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH
	case "MEDIUM", "MODERATE":
		return vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM
	case "LOW":
		return vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW
	default:
		return vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED
	}
}

// SeverityLevelString returns a human-readable string for a SeverityLevel.
func SeverityLevelString(l vulnerabilityv1.SeverityLevel) string {
	switch l {
	case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL:
		return "CRITICAL"
	case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH:
		return "HIGH"
	case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM:
		return "MEDIUM"
	case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// IsCriticalOrHigh returns true if the severity is CRITICAL or HIGH.
func IsCriticalOrHigh(l vulnerabilityv1.SeverityLevel) bool {
	return l == vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL ||
		l == vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH
}

// Finding helpers - work with proto Finding directly

// FindingHasFix returns true if the finding has at least one fixed version.
func FindingHasFix(f *vulnerabilityv1.Finding) bool {
	if f == nil || f.Advisory == nil {
		return false
	}
	return len(f.Advisory.FixedVersions) > 0
}

// FindingIsDirect returns true if the finding is in a direct dependency.
func FindingIsDirect(f *vulnerabilityv1.Finding) bool {
	if f == nil || f.Package == nil {
		return false
	}
	return f.Package.Direct
}

// FindingSeverity returns the severity level of a finding.
// Returns UNSPECIFIED if the finding has no advisory or severity.
func FindingSeverity(f *vulnerabilityv1.Finding) vulnerabilityv1.SeverityLevel {
	if f == nil || f.Advisory == nil || f.Advisory.Severity == nil {
		return vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED
	}
	return f.Advisory.Severity.Level
}

// Stats helpers - work with proto Stats directly

// NewStats creates a Stats from findings.
func NewStats(findings []*vulnerabilityv1.Finding) *vulnerabilityv1.Stats {
	stats := &vulnerabilityv1.Stats{}
	for _, f := range findings {
		stats.Total++
		switch FindingSeverity(f) {
		case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL:
			stats.Critical++
		case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH:
			stats.High++
		case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM:
			stats.Medium++
		case vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW:
			stats.Low++
		default:
			stats.Unknown++
		}
	}
	return stats
}

// HasCritical returns true if there are any critical vulnerabilities.
func HasCritical(s *vulnerabilityv1.Stats) bool {
	return s != nil && s.Critical > 0
}

// HasCriticalOrHigh returns true if there are any critical or high vulnerabilities.
func HasCriticalOrHigh(s *vulnerabilityv1.Stats) bool {
	return s != nil && (s.Critical > 0 || s.High > 0)
}

// Package helpers - work with proto Package directly

// PackageKey returns a unique key for a package (ecosystem:name@version).
func PackageKey(p *dependencyv1.Package) string {
	if p == nil {
		return ""
	}
	if p.Version != "" {
		return p.Ecosystem + ":" + p.Name + "@" + p.Version
	}
	return p.Ecosystem + ":" + p.Name
}

// PackageDisplayName returns a human-readable display name for a package.
func PackageDisplayName(p *dependencyv1.Package) string {
	if p == nil {
		return ""
	}
	if p.Version != "" {
		return p.Name + "@" + p.Version
	}
	return p.Name
}

// Scan progress helpers

// IsComplete returns true if the scan phase indicates completion.
func IsComplete(phase scanv1.ScanPhase) bool {
	return phase == scanv1.ScanPhase_SCAN_PHASE_COMPLETE
}

// IsFailed returns true if the scan phase indicates failure.
func IsFailed(phase scanv1.ScanPhase) bool {
	return phase == scanv1.ScanPhase_SCAN_PHASE_FAILED
}

// IsTerminal returns true if the scan phase is a terminal state.
func IsTerminal(phase scanv1.ScanPhase) bool {
	return IsComplete(phase) || IsFailed(phase)
}

// Agent helpers

// IsAgentComplete returns true if the agent phase indicates completion.
func IsAgentComplete(phase remediationv1.AgentPhase) bool {
	return phase == remediationv1.AgentPhase_AGENT_PHASE_COMPLETED
}

// IsAgentFailed returns true if the agent phase indicates failure.
func IsAgentFailed(phase remediationv1.AgentPhase) bool {
	return phase == remediationv1.AgentPhase_AGENT_PHASE_FAILED
}

// IsAgentTerminal returns true if the agent phase is a terminal state.
func IsAgentTerminal(phase remediationv1.AgentPhase) bool {
	return phase == remediationv1.AgentPhase_AGENT_PHASE_COMPLETED ||
		phase == remediationv1.AgentPhase_AGENT_PHASE_FAILED ||
		phase == remediationv1.AgentPhase_AGENT_PHASE_INTERRUPTED
}
