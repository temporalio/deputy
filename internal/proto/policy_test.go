package proto

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/policy"
)

func TestPolicyActionToProto(t *testing.T) {
	subject := &policyv1.Subject{Package: "lodash", Version: "4.17.21", Ecosystem: "npm"}
	tests := []struct {
		name       string
		action     policy.Action
		entrypoint string
		subject    *policyv1.Subject
		wantType   policyv1.ActionType
		wantPolicy string
		wantRule   string
	}{
		{
			name:       "SplitsCombinedSource",
			action:     policy.Action{Type: "warn", Source: "policy/ci/pr-review.yaml::pr-license-check", Reason: "No license information detected"},
			entrypoint: "diff_dependency_change",
			subject:    subject,
			wantType:   policyv1.ActionType_ACTION_TYPE_WARN,
			wantPolicy: "policy/ci/pr-review.yaml",
			wantRule:   "pr-license-check",
		},
		{
			name:       "BareSourceHasNoRule",
			action:     policy.Action{Type: "deny", Source: "inline-policy", Reason: "blocked"},
			wantType:   policyv1.ActionType_ACTION_TYPE_DENY,
			wantPolicy: "inline-policy",
			wantRule:   "",
		},
		{
			name:       "CaseInsensitiveType",
			action:     policy.Action{Type: "WARN", Source: "p.yaml::r"},
			wantType:   policyv1.ActionType_ACTION_TYPE_WARN,
			wantPolicy: "p.yaml",
			wantRule:   "r",
		},
		{
			name:       "UnknownTypeMapsToUnspecified",
			action:     policy.Action{Type: "audit", Source: "p.yaml::r"},
			wantType:   policyv1.ActionType_ACTION_TYPE_UNSPECIFIED,
			wantPolicy: "p.yaml",
			wantRule:   "r",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyActionToProto(tt.action, tt.entrypoint, tt.subject)
			if got.GetType() != tt.wantType {
				t.Errorf("Type = %v, want %v", got.GetType(), tt.wantType)
			}
			if got.GetPolicyName() != tt.wantPolicy {
				t.Errorf("PolicyName = %q, want %q", got.GetPolicyName(), tt.wantPolicy)
			}
			if got.GetRuleName() != tt.wantRule {
				t.Errorf("RuleName = %q, want %q", got.GetRuleName(), tt.wantRule)
			}
			if got.GetEntrypoint() != tt.entrypoint {
				t.Errorf("Entrypoint = %q, want %q", got.GetEntrypoint(), tt.entrypoint)
			}
			if got.GetReason() != tt.action.Reason {
				t.Errorf("Reason = %q, want %q", got.GetReason(), tt.action.Reason)
			}
			if (tt.subject == nil) != (got.GetSubject() == nil) {
				t.Errorf("Subject presence mismatch: got %v, want %v", got.GetSubject(), tt.subject)
			}
		})
	}
}

func TestPolicyActionToProto_CarriesMessageAndCode(t *testing.T) {
	act := policy.Action{Type: "warn", Source: "p.yaml::r", Message: "extra context", Code: "LICENSE_MISSING"}
	got := PolicyActionToProto(act, "", nil)
	if got.GetMessage() != "extra context" {
		t.Errorf("Message = %q, want %q", got.GetMessage(), "extra context")
	}
	if got.GetCode() != "LICENSE_MISSING" {
		t.Errorf("Code = %q, want %q", got.GetCode(), "LICENSE_MISSING")
	}
}

func TestPolicyActionsFromProto(t *testing.T) {
	// Round-trip: ToProto then FromProto preserves the fields the
	// internal action carries. Entrypoint and subject have no internal
	// counterpart and are dropped by design.
	actions := []policy.Action{
		{Type: "deny", Source: "policy/ci/security-gate.yaml::ci-block-fixable-high", Reason: "High severity vulnerability has an available fix", Remediation: "Upgrade to a fixed version", Code: "GATE"},
		{Type: "warn", Source: "inline-policy", Reason: "blocked", Message: "extra context"},
		{Type: "audit", Source: "p.yaml::r", Reason: "unknown type"},
	}
	got := PolicyActionsFromProto(PolicyActionsToProto(actions))
	if len(got) != len(actions) {
		t.Fatalf("len = %d, want %d", len(got), len(actions))
	}
	for i, want := range actions {
		if got[i].Source != want.Source {
			t.Errorf("[%d] Source = %q, want %q", i, got[i].Source, want.Source)
		}
		if got[i].Reason != want.Reason || got[i].Message != want.Message ||
			got[i].Remediation != want.Remediation || got[i].Code != want.Code {
			t.Errorf("[%d] fields = %+v, want %+v", i, got[i], want)
		}
	}
	if got[0].Type != policy.ActionDeny || got[1].Type != policy.ActionWarn {
		t.Errorf("types = %q/%q, want deny/warn", got[0].Type, got[1].Type)
	}
	if got[2].Type != "" {
		t.Errorf("unknown type round-trips as %q, want empty", got[2].Type)
	}
	if got := PolicyActionsFromProto(nil); got != nil {
		t.Errorf("nil input = %v, want nil", got)
	}
}

func TestPolicySubjectFromPackage(t *testing.T) {
	if got := PolicySubjectFromPackage(nil); got != nil {
		t.Fatalf("expected nil subject for nil package, got %v", got)
	}
	pkg := &dependencyv1.Package{Name: "golang.org/x/text", Version: "0.39.0", Ecosystem: "go", Purl: "pkg:golang/golang.org/x/text@0.39.0"}
	got := PolicySubjectFromPackage(pkg)
	if got.GetPackage() != pkg.GetName() || got.GetVersion() != pkg.GetVersion() || got.GetEcosystem() != pkg.GetEcosystem() || got.GetPurl() != pkg.GetPurl() {
		t.Errorf("subject = %v, want fields copied from %v", got, pkg)
	}
	if got.GetAdvisory() != "" {
		t.Errorf("Advisory = %q, want empty for package subject", got.GetAdvisory())
	}
}

func TestPolicySubjectFromFinding(t *testing.T) {
	if got := PolicySubjectFromFinding(nil); got != nil {
		t.Fatalf("expected nil subject for nil finding, got %v", got)
	}
	finding := &vulnerabilityv1.Finding{
		AdvisoryId: "GHSA-xxxx-yyyy-zzzz",
		Package:    &dependencyv1.Package{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
	}
	got := PolicySubjectFromFinding(finding)
	if got.GetAdvisory() != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("Advisory = %q, want %q", got.GetAdvisory(), "GHSA-xxxx-yyyy-zzzz")
	}
	if got.GetPackage() != "lodash" || got.GetVersion() != "4.17.20" {
		t.Errorf("subject package = %q@%q, want lodash@4.17.20", got.GetPackage(), got.GetVersion())
	}

	// A finding with no package still yields an advisory-only subject.
	got = PolicySubjectFromFinding(&vulnerabilityv1.Finding{AdvisoryId: "CVE-2026-1234"})
	if got.GetAdvisory() != "CVE-2026-1234" || got.GetPackage() != "" {
		t.Errorf("advisory-only subject = %v, want advisory set and package empty", got)
	}
}
