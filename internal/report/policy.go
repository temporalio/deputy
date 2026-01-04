package report

import (
	"strings"

	"github.com/picatz/deputy/internal/policy"
)

// PolicyFinding represents a policy action emitted during evaluation.
type PolicyFinding struct {
	// Source is the name of the policy that generated this finding.
	Source string `json:"source"`
	// Action is the policy decision type (e.g., "deny", "warn", "allow").
	Action string `json:"action"`
	// Reason explains why the policy triggered this action.
	Reason string `json:"reason,omitempty"`
	// Message provides additional context or details about the finding.
	Message string `json:"message,omitempty"`
	// Remediation suggests steps to resolve the policy violation.
	Remediation string `json:"remediation,omitempty"`
	// Status is an optional HTTP status code suggestion for proxy mode.
	Status *int `json:"status,omitempty"`
	// Code is a machine-readable identifier for the finding type.
	Code string `json:"code,omitempty"`
}

// PolicyFindingsFromActions converts policy actions into report findings.
// Actions with empty type or "allow" type are filtered out.
func PolicyFindingsFromActions(actions []policy.Action) []PolicyFinding {
	if len(actions) == 0 {
		return nil
	}
	var findings []PolicyFinding
	for _, act := range actions {
		actionType := strings.TrimSpace(act.Type)
		if actionType == "" || policy.ActionTypeIs(actionType, policy.ActionAllow) {
			continue
		}
		f := PolicyFinding{
			Source:      act.Source,
			Action:      actionType,
			Reason:      act.Reason,
			Message:     act.Message,
			Remediation: act.Remediation,
			Status:      act.Status,
			Code:        act.Code,
		}
		findings = append(findings, f)
	}
	return findings
}
