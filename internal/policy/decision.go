package policy

// Decision represents a normalized policy outcome for reporting and gating.
type Decision struct {
	Source      string
	Action      string
	Reason      string
	Message     string
	Remediation string
	Code        string
	Status      *int
	Headers     map[string]string
	Annotations map[string]any
}

// DecisionFromAction converts a policy Action into a Decision.
func DecisionFromAction(action Action) Decision {
	return Decision{
		Source:      action.Source,
		Action:      action.Type,
		Reason:      action.Reason,
		Message:     action.Message,
		Remediation: action.Remediation,
		Code:        action.Code,
		Status:      action.Status,
		Headers:     action.Headers,
		Annotations: action.Annotations,
	}
}
