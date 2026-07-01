package server

import (
	"slices"
	"testing"

	"connectrpc.com/connect"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/policy"
)

func TestPolicyListEntrypointsUsesBindingProfiles(t *testing.T) {
	handler := NewPolicyHandler()
	resp, err := handler.ListEntrypoints(t.Context(), connect.NewRequest(&policyv1.ListEntrypointsRequest{
		Category: "scan",
	}))
	if err != nil {
		t.Fatalf("ListEntrypoints failed: %v", err)
	}

	got := map[string]*policyv1.EntrypointInfo{}
	for _, info := range resp.Msg.GetEntrypoints() {
		got[info.GetName()] = info
		if info.GetCategory() != "scan" {
			t.Errorf("entrypoint %q category = %q, want scan", info.GetName(), info.GetCategory())
		}
	}

	for _, ep := range policy.EntrypointsScan {
		info := got[string(ep)]
		if info == nil {
			t.Fatalf("missing entrypoint %q", ep)
		}
		profile := policy.GetBindingProfile(ep)
		if profile == nil {
			t.Fatalf("missing binding profile for %q", ep)
		}
		if info.GetDescription() != profile.Description {
			t.Errorf("%s description = %q, want %q", ep, info.GetDescription(), profile.Description)
		}

		varNames := make([]string, 0, len(info.GetVariables()))
		required := map[string]bool{}
		for _, variable := range info.GetVariables() {
			varNames = append(varNames, variable.GetName())
			required[variable.GetName()] = variable.GetRequired()
			if variable.GetType() == "" {
				t.Errorf("%s variable %q has empty type", ep, variable.GetName())
			}
			if variable.GetDescription() == "" {
				t.Errorf("%s variable %q has empty description", ep, variable.GetName())
			}
		}
		if want := profile.Variables(); !slices.Equal(varNames, want) {
			t.Errorf("%s variables = %v, want %v", ep, varNames, want)
		}
		for _, name := range profile.Required {
			if !required[name] {
				t.Errorf("%s variable %q Required = false, want true", ep, name)
			}
		}
		for _, name := range profile.Optional {
			if required[name] {
				t.Errorf("%s variable %q Required = true, want false", ep, name)
			}
		}
	}
}

func TestPolicyListEntrypointsAcceptsLegacyCategoryAliases(t *testing.T) {
	handler := NewPolicyHandler()
	tests := []struct {
		category string
		want     []policy.Entrypoint
	}{
		{category: "service", want: policy.EntrypointsService},
		{category: "container", want: policy.EntrypointsContainerDiff},
	}
	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			resp, err := handler.ListEntrypoints(t.Context(), connect.NewRequest(&policyv1.ListEntrypointsRequest{
				Category: tt.category,
			}))
			if err != nil {
				t.Fatalf("ListEntrypoints failed: %v", err)
			}
			got := make([]policy.Entrypoint, 0, len(resp.Msg.GetEntrypoints()))
			for _, info := range resp.Msg.GetEntrypoints() {
				got = append(got, policy.Entrypoint(info.GetName()))
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("entrypoints = %v, want %v", got, tt.want)
			}
		})
	}
}
