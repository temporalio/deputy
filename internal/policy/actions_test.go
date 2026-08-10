package policy

import (
	"slices"
	"strings"
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
)

// TestActionTypesMatchProtoDescriptor pins the authored action vocabulary to
// deputy.policy.v1.ActionType: every non-zero enum value must be accepted, in
// enum-number order, and the exported constants must spell those values. A
// rename in the proto fails here instead of leaving policy loading rejecting an
// action the API considers valid.
func TestActionTypesMatchProtoDescriptor(t *testing.T) {
	values := policyv1.ActionType(0).Descriptor().Values()
	var want []string
	for i := range values.Len() {
		value := values.Get(i)
		if value.Number() == 0 {
			continue
		}
		want = append(want, strings.ToLower(strings.TrimPrefix(string(value.Name()), actionTypePrefix)))
	}
	if got := ActionTypes(); !slices.Equal(got, want) {
		t.Fatalf("ActionTypes() = %v, want the enum values %v", got, want)
	}
	for _, name := range want {
		t.Run(name, func(t *testing.T) {
			normalized, err := ValidateActionType(name)
			if err != nil {
				t.Fatalf("ValidateActionType rejects declared action %q: %v", name, err)
			}
			if normalized != name {
				t.Fatalf("ValidateActionType(%q) = %q, want the canonical spelling", name, normalized)
			}
		})
	}
	constants := map[string]string{
		strings.ToLower(strings.TrimPrefix(policyv1.ActionType_ACTION_TYPE_ALLOW.String(), actionTypePrefix)): ActionAllow,
		strings.ToLower(strings.TrimPrefix(policyv1.ActionType_ACTION_TYPE_DENY.String(), actionTypePrefix)):  ActionDeny,
		strings.ToLower(strings.TrimPrefix(policyv1.ActionType_ACTION_TYPE_WARN.String(), actionTypePrefix)):  ActionWarn,
	}
	for enumName, constant := range constants {
		if enumName != constant {
			t.Fatalf("constant %q does not spell its enum value %q", constant, enumName)
		}
	}
}

// TestActionVocabularyIsImplemented pins the vocabulary against what the engine
// actually does with an action. Deriving the list from the proto keeps it from
// drifting, but an action the engine does not implement would be accepted by
// lint and then quietly do nothing at evaluation time, which is the failure this
// validation exists to prevent. Wire a new action up, then widen this list.
func TestActionVocabularyIsImplemented(t *testing.T) {
	implemented := []string{ActionAllow, ActionDeny, ActionWarn}
	if got := ActionTypes(); !slices.Equal(got, implemented) {
		t.Fatalf("action vocabulary is %v but the engine implements %v: implement the new action before accepting it", got, implemented)
	}
}

// TestValidateActionType covers the vocabulary boundaries: the zero enum value
// is not an authored action, and casing and padding are normalized rather than
// rejected.
func TestValidateActionType(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "deny", input: "deny", want: ActionDeny},
		{name: "uppercase", input: "WARN", want: ActionWarn},
		{name: "padded", input: "  allow\t", want: ActionAllow},
		{name: "unspecified is not authorable", input: "unspecified", wantErr: true},
		{name: "proto spelling is not authorable", input: "ACTION_TYPE_DENY", wantErr: true},
		{name: "typo", input: "dney", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateActionType(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.input, got)
				}
				if !strings.Contains(err.Error(), strings.Join(ActionTypes(), "|")) {
					t.Fatalf("error %q should quote the vocabulary", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateActionType(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateActionType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
