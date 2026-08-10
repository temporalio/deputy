package policy

import (
	"strings"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// findingRegistry adapts Finding protos into CEL values the way the policy
// environment does; the default adapter cannot adapt unregistered messages.
var findingRegistry = func() *types.Registry {
	reg, err := types.NewRegistry(&vulnerabilityv1.Finding{})
	if err != nil {
		panic(err)
	}
	return reg
}()

// findingWithSeverity builds a CEL value for a Finding carrying the given
// severity level, matching what policies receive at evaluation time.
func findingWithSeverity(level vulnerabilityv1.SeverityLevel) ref.Val {
	return findingRegistry.NativeToValue(&vulnerabilityv1.Finding{
		Advisory: &vulnerabilityv1.Advisory{
			Severity: &vulnerabilityv1.Severity{Level: level},
		},
	})
}

// TestSeverityAtLeastRejectsUnknownLevel pins that an unrecognized threshold is a
// loud CEL error instead of a rank-zero threshold that matches every finding.
func TestSeverityAtLeastRejectsUnknownLevel(t *testing.T) {
	cases := []struct {
		name    string
		level   string
		finding vulnerabilityv1.SeverityLevel
		wantErr bool
		want    bool
	}{
		{name: "critical threshold not met by low", level: "CRITICAL", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW},
		{name: "critical threshold met by critical", level: "CRITICAL", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL, want: true},
		{name: "lowercase threshold accepted", level: "high", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL, want: true},
		{name: "unspecified threshold matches anything", level: "UNSPECIFIED", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW, want: true},
		{name: "transposed letters", level: "CRITCAL", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW, wantErr: true},
		{name: "unmodeled synonym", level: "MODERATE", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW, wantErr: true},
		{name: "empty level", level: "", finding: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := severityAtLeastBinding(findingWithSeverity(tc.finding), types.String(tc.level))
			if tc.wantErr {
				err, ok := got.(*types.Err)
				if !ok {
					t.Fatalf("expected CEL error for level %q, got %v", tc.level, got)
				}
				msg := err.String()
				for _, want := range []string{tc.level, "UNSPECIFIED|LOW|MEDIUM|HIGH|CRITICAL"} {
					if !strings.Contains(msg, want) {
						t.Fatalf("error %q missing %q", msg, want)
					}
				}
				return
			}
			if got.Value() != tc.want {
				t.Fatalf("severityAtLeast(%s, %q) = %v, want %v", tc.finding, tc.level, got.Value(), tc.want)
			}
		})
	}
}

// TestSeverityAtLeastErrorSurfacesFromEvaluation pins that the CEL error reaches
// the caller as a failed evaluation rather than being swallowed into a result.
func TestSeverityAtLeastErrorSurfacesFromEvaluation(t *testing.T) {
	src := `severityAtLeast(vulnerability, "CRITCAL") ? [{"action": "deny", "reason": "critical"}] : []`
	input := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW},
			},
		},
	}
	got, err := Evaluate(t.Context(), src, input)
	if err == nil {
		t.Fatalf("expected evaluation error, got result %#v", got)
	}
	if !strings.Contains(err.Error(), "CRITCAL") {
		t.Fatalf("error %q should name the offending level", err)
	}
}

// TestFindingSeverityRankToleratesUnknownData pins the asymmetry: observed data
// that lacks a severity ranks as unspecified rather than failing evaluation.
func TestFindingSeverityRankToleratesUnknownData(t *testing.T) {
	cases := []struct {
		name  string
		value ref.Val
		want  int
	}{
		{name: "missing advisory", value: findingRegistry.NativeToValue(&vulnerabilityv1.Finding{}), want: severityRankUnspecified},
		{name: "critical", value: findingWithSeverity(vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL), want: severityRankCritical},
		{name: "unmodeled map level", value: types.DefaultTypeAdapter.NativeToValue(map[string]any{
			"advisory": map[string]any{"severity": map[string]any{"level": "MODERATE"}},
		}), want: severityRankUnspecified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := findingSeverityRank(tc.value); got != tc.want {
				t.Fatalf("findingSeverityRank = %d, want %d", got, tc.want)
			}
		})
	}
}
