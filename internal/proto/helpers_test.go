package proto

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	remediationv1 "github.com/temporalio/deputy/gen/deputy/remediation/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

func TestParseTargetKind(t *testing.T) {
	tests := []struct {
		input string
		want  targetv1.TargetKind
	}{
		{"dir", targetv1.TargetKind_TARGET_KIND_DIR},
		{"directory", targetv1.TargetKind_TARGET_KIND_DIR},
		{"DIR", targetv1.TargetKind_TARGET_KIND_DIR},
		{"file", targetv1.TargetKind_TARGET_KIND_FILE},
		{"binary", targetv1.TargetKind_TARGET_KIND_BINARY},
		{"git", targetv1.TargetKind_TARGET_KIND_GIT},
		{"repo", targetv1.TargetKind_TARGET_KIND_GIT},
		{"container-image", targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE},
		{"image", targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE},
		{"docker", targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE},
		{"sbom", targetv1.TargetKind_TARGET_KIND_SBOM},
		{"purl", targetv1.TargetKind_TARGET_KIND_PURL},
		{"dockerfile", targetv1.TargetKind_TARGET_KIND_DOCKERFILE},
		{"unknown", targetv1.TargetKind_TARGET_KIND_UNSPECIFIED},
		{"", targetv1.TargetKind_TARGET_KIND_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseTargetKind(tt.input)
			if got != tt.want {
				t.Errorf("ParseTargetKind(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTargetKindString(t *testing.T) {
	tests := []struct {
		input targetv1.TargetKind
		want  string
	}{
		{targetv1.TargetKind_TARGET_KIND_DIR, "dir"},
		{targetv1.TargetKind_TARGET_KIND_FILE, "file"},
		{targetv1.TargetKind_TARGET_KIND_GIT, "git"},
		{targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE, "container-image"},
		{targetv1.TargetKind_TARGET_KIND_UNSPECIFIED, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := TargetKindString(tt.input)
			if got != tt.want {
				t.Errorf("TargetKindString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSeverityLevel(t *testing.T) {
	tests := []struct {
		input string
		want  vulnerabilityv1.SeverityLevel
	}{
		{"CRITICAL", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL},
		{"critical", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL},
		{"HIGH", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH},
		{"MEDIUM", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM},
		{"MODERATE", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM},
		{"LOW", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW},
		{"unknown", vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseSeverityLevel(tt.input)
			if got != tt.want {
				t.Errorf("ParseSeverityLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCriticalOrHigh(t *testing.T) {
	tests := []struct {
		level vulnerabilityv1.SeverityLevel
		want  bool
	}{
		{vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL, true},
		{vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH, true},
		{vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM, false},
		{vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW, false},
		{vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED, false},
	}

	for _, tt := range tests {
		t.Run(SeverityLevelString(tt.level), func(t *testing.T) {
			got := IsCriticalOrHigh(tt.level)
			if got != tt.want {
				t.Errorf("IsCriticalOrHigh(%v) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

func TestFindingHelpers(t *testing.T) {
	t.Run("FindingHasFix", func(t *testing.T) {
		// No fix
		noFix := &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{FixedVersions: nil},
		}
		if FindingHasFix(noFix) {
			t.Error("expected no fix")
		}

		// Has fix
		hasFix := &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{FixedVersions: []string{"1.2.3"}},
		}
		if !FindingHasFix(hasFix) {
			t.Error("expected has fix")
		}

		// Nil finding
		if FindingHasFix(nil) {
			t.Error("expected false for nil")
		}
	})

	t.Run("FindingIsDirect", func(t *testing.T) {
		direct := &vulnerabilityv1.Finding{
			Package: &dependencyv1.Package{Direct: true},
		}
		if !FindingIsDirect(direct) {
			t.Error("expected direct")
		}

		transitive := &vulnerabilityv1.Finding{
			Package: &dependencyv1.Package{Direct: false},
		}
		if FindingIsDirect(transitive) {
			t.Error("expected not direct")
		}
	})

	t.Run("FindingSeverity", func(t *testing.T) {
		critical := &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL},
			},
		}
		if FindingSeverity(critical) != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL {
			t.Error("expected critical")
		}

		noSeverity := &vulnerabilityv1.Finding{}
		if FindingSeverity(noSeverity) != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED {
			t.Error("expected unspecified")
		}
	})
}

func TestNewStats(t *testing.T) {
	findings := []*vulnerabilityv1.Finding{
		{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL}}},
		{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL}}},
		{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH}}},
		{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM}}},
		{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW}}},
		{Advisory: nil}, // Unknown
	}

	stats := NewStats(findings)

	if stats.Total != 6 {
		t.Errorf("Total = %d, want 6", stats.Total)
	}
	if stats.Critical != 2 {
		t.Errorf("Critical = %d, want 2", stats.Critical)
	}
	if stats.High != 1 {
		t.Errorf("High = %d, want 1", stats.High)
	}
	if stats.Medium != 1 {
		t.Errorf("Medium = %d, want 1", stats.Medium)
	}
	if stats.Low != 1 {
		t.Errorf("Low = %d, want 1", stats.Low)
	}
	if stats.Unknown != 1 {
		t.Errorf("Unknown = %d, want 1", stats.Unknown)
	}
}

func TestHasCriticalOrHigh(t *testing.T) {
	tests := []struct {
		name  string
		stats *vulnerabilityv1.Stats
		want  bool
	}{
		{"nil", nil, false},
		{"empty", &vulnerabilityv1.Stats{}, false},
		{"critical only", &vulnerabilityv1.Stats{Critical: 1}, true},
		{"high only", &vulnerabilityv1.Stats{High: 1}, true},
		{"both", &vulnerabilityv1.Stats{Critical: 1, High: 2}, true},
		{"medium only", &vulnerabilityv1.Stats{Medium: 5}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasCriticalOrHigh(tt.stats)
			if got != tt.want {
				t.Errorf("HasCriticalOrHigh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackageKey(t *testing.T) {
	tests := []struct {
		pkg  *dependencyv1.Package
		want string
	}{
		{nil, ""},
		{&dependencyv1.Package{Ecosystem: "go", Name: "example.com/foo"}, "go:example.com/foo"},
		{&dependencyv1.Package{Ecosystem: "go", Name: "example.com/foo", Version: "1.2.3"}, "go:example.com/foo@1.2.3"},
		{&dependencyv1.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}, "npm:lodash@4.17.21"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := PackageKey(tt.pkg)
			if got != tt.want {
				t.Errorf("PackageKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScanPhaseHelpers(t *testing.T) {
	if !IsComplete(scanv1.ScanPhase_SCAN_PHASE_COMPLETE) {
		t.Error("COMPLETE should be complete")
	}
	if IsComplete(scanv1.ScanPhase_SCAN_PHASE_EXTRACTING_INVENTORY) {
		t.Error("EXTRACTING_INVENTORY should not be complete")
	}

	if !IsFailed(scanv1.ScanPhase_SCAN_PHASE_FAILED) {
		t.Error("FAILED should be failed")
	}

	if !IsTerminal(scanv1.ScanPhase_SCAN_PHASE_COMPLETE) {
		t.Error("COMPLETE should be terminal")
	}
	if !IsTerminal(scanv1.ScanPhase_SCAN_PHASE_FAILED) {
		t.Error("FAILED should be terminal")
	}
	if IsTerminal(scanv1.ScanPhase_SCAN_PHASE_RESOLVING_TARGET) {
		t.Error("RESOLVING_TARGET should not be terminal")
	}
}

func TestAgentPhaseHelpers(t *testing.T) {
	if !IsAgentComplete(remediationv1.AgentPhase_AGENT_PHASE_COMPLETED) {
		t.Error("COMPLETED should be complete")
	}

	if !IsAgentFailed(remediationv1.AgentPhase_AGENT_PHASE_FAILED) {
		t.Error("FAILED should be failed")
	}

	terminalPhases := []remediationv1.AgentPhase{
		remediationv1.AgentPhase_AGENT_PHASE_COMPLETED,
		remediationv1.AgentPhase_AGENT_PHASE_FAILED,
		remediationv1.AgentPhase_AGENT_PHASE_INTERRUPTED,
	}
	for _, phase := range terminalPhases {
		if !IsAgentTerminal(phase) {
			t.Errorf("%v should be terminal", phase)
		}
	}

	nonTerminalPhases := []remediationv1.AgentPhase{
		remediationv1.AgentPhase_AGENT_PHASE_ANALYZING,
		remediationv1.AgentPhase_AGENT_PHASE_PLANNING,
		remediationv1.AgentPhase_AGENT_PHASE_EXECUTING,
	}
	for _, phase := range nonTerminalPhases {
		if IsAgentTerminal(phase) {
			t.Errorf("%v should not be terminal", phase)
		}
	}
}
