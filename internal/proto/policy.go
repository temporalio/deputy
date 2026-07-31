package proto

import (
	"strings"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/policy"
)

// PolicyActionToProto converts one internal policy action into the
// surface-crossing deputy.policy.v1.Action shape, attributing it to the
// entrypoint that evaluated it and the subject it evaluated. Entrypoint may
// be empty and subject nil for report-level evaluations where no single
// subject applies.
//
// The internal engine names actions with a combined "path::rule" source (see
// internal/policy/source.go); the conversion restores the two halves so
// consumers can group results by rule and link back to the policy file.
func PolicyActionToProto(a policy.Action, entrypoint string, subject *policyv1.Subject) *policyv1.Action {
	policyName, ruleName := splitPolicySource(a.Source)
	return &policyv1.Action{
		Type:        policyActionTypeToProto(a.Type),
		PolicyName:  policyName,
		RuleName:    ruleName,
		Reason:      a.Reason,
		Message:     a.Message,
		Remediation: a.Remediation,
		Code:        a.Code,
		Entrypoint:  entrypoint,
		Subject:     subject,
	}
}

// PolicyActionsToProto converts internal policy actions without entrypoint or
// subject attribution, for call sites that evaluate a single report-level
// payload. Prefer PolicyActionToProto where the evaluated subject is known.
func PolicyActionsToProto(actions []policy.Action) []*policyv1.Action {
	if len(actions) == 0 {
		return nil
	}
	out := make([]*policyv1.Action, len(actions))
	for i, a := range actions {
		out[i] = PolicyActionToProto(a, "", nil)
	}
	return out
}

// splitPolicySource splits the engine's combined "path::rule" action source
// into its policy source and rule name halves. A source without the
// separator is treated as a bare policy name with no rule.
func splitPolicySource(source string) (policyName, ruleName string) {
	if p, r, ok := strings.Cut(source, "::"); ok {
		return p, r
	}
	return source, ""
}

// policyActionTypeToProto converts an action type string to the proto enum.
// Unknown types map to unspecified rather than failing, because Action.Type
// is an open vocabulary in the engine.
func policyActionTypeToProto(actionType string) policyv1.ActionType {
	switch {
	case policy.ActionTypeIs(actionType, policy.ActionDeny):
		return policyv1.ActionType_ACTION_TYPE_DENY
	case policy.ActionTypeIs(actionType, policy.ActionWarn):
		return policyv1.ActionType_ACTION_TYPE_WARN
	case policy.ActionTypeIs(actionType, policy.ActionAllow):
		return policyv1.ActionType_ACTION_TYPE_ALLOW
	default:
		return policyv1.ActionType_ACTION_TYPE_UNSPECIFIED
	}
}

// PolicySubjectFromPackage builds the policy subject for a package-scoped
// evaluation (e.g., diff_dependency_change, sbom_component).
func PolicySubjectFromPackage(pkg *dependencyv1.Package) *policyv1.Subject {
	if pkg == nil {
		return nil
	}
	return &policyv1.Subject{
		Package:   pkg.GetName(),
		Version:   pkg.GetVersion(),
		Ecosystem: pkg.GetEcosystem(),
		Purl:      pkg.GetPurl(),
	}
}

// PolicySubjectFromFinding builds the policy subject for a
// vulnerability-scoped evaluation (e.g., diff_vulnerability,
// scan_vulnerability), carrying both the advisory ID and the affected
// package so consumers can render either.
func PolicySubjectFromFinding(f *vulnerabilityv1.Finding) *policyv1.Subject {
	if f == nil {
		return nil
	}
	subject := PolicySubjectFromPackage(f.GetPackage())
	if subject == nil {
		subject = &policyv1.Subject{}
	}
	subject.Advisory = f.GetAdvisoryId()
	return subject
}
