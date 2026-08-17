package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/policy"
)

// inlinePolicy wraps YAML policy text as an inline evaluation source.
func inlinePolicy(body string) *policyv1.PolicySource {
	return &policyv1.PolicySource{Source: &policyv1.PolicySource_Inline{Inline: body}}
}

// canceledContext returns a context that is already canceled, standing in for
// a caller that hung up before the handler finished.
func canceledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

// expiredContext returns a context whose deadline has already passed, standing
// in for a caller whose RPC timeout fired.
func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Minute))
	t.Cleanup(cancel)
	return ctx
}

// TestPolicyEvaluateFailsClosed pins the invariant from issue #267: a caller
// can never read a policy failure as a permission. Every failure mode must
// answer with a connect error and no response, so there is no outcome field to
// misread, while genuine allow, warn, and deny decisions still come back as
// decisions.
func TestPolicyEvaluateFailsClosed(t *testing.T) {
	const (
		// divideByZero compiles but traps at evaluation time.
		divideByZero = `policies:
  - name: boom
    rules:
      - action: deny
        when: 1/0 == 0
        reason: never reached
`
		denyAlways = `policies:
  - name: deny-all
    rules:
      - action: deny
        when: "true"
        reason: denied by test policy
`
		warnAlways = `policies:
  - name: warn-all
    rules:
      - action: warn
        when: "true"
        reason: warned by test policy
`
		allowQuiet = `policies:
  - name: never-fires
    rules:
      - action: deny
        when: "false"
        reason: never fires
`
		uncompilable = `policies:
  - name: nonsense
    rules:
      - action: deny
        when: this_variable_does_not_exist
        reason: never compiles
`
	)

	tests := []struct {
		name            string
		localMode       bool
		policies        []*policyv1.PolicySource
		ctx             func(t *testing.T) context.Context
		wantCode        connect.Code // zero means a decision is expected
		wantErrContains []string
		wantOutcome     policyv1.ActionType
		wantActions     int
	}{
		{
			name:     "evaluation failure is an error, not an allow",
			policies: []*policyv1.PolicySource{inlinePolicy(divideByZero)},
			wantCode: connect.CodeInternal,
			wantErrContains: []string{
				"evaluate policies",
				string(policy.EntrypointScanVulnerability),
				"boom",
				"division by zero",
			},
		},
		{
			name:            "evaluation failure alongside a healthy policy is still an error",
			policies:        []*policyv1.PolicySource{inlinePolicy(allowQuiet), inlinePolicy(divideByZero)},
			wantCode:        connect.CodeInternal,
			wantErrContains: []string{"division by zero"},
		},
		{
			name:            "compile failure is an error, not an allow",
			policies:        []*policyv1.PolicySource{inlinePolicy(uncompilable)},
			wantCode:        connect.CodeInvalidArgument,
			wantErrContains: []string{"compile policies", "this_variable_does_not_exist"},
		},
		{
			name:            "unparseable inline source is an error, not an allow",
			policies:        []*policyv1.PolicySource{inlinePolicy("policies: [[[")},
			wantCode:        connect.CodeInvalidArgument,
			wantErrContains: []string{"load policy sources", "parse inline policy"},
		},
		{
			name: "path source refused in remote mode is an error, not an allow",
			policies: []*policyv1.PolicySource{
				inlinePolicy(allowQuiet),
				{Source: &policyv1.PolicySource_Path{Path: "/nonexistent/policy.yaml"}},
			},
			wantCode:        connect.CodeInvalidArgument,
			wantErrContains: []string{"load policy sources", "require local mode"},
		},
		{
			name:      "unreadable path source in local mode is an error, not an allow",
			localMode: true,
			policies: []*policyv1.PolicySource{
				{Source: &policyv1.PolicySource_Path{Path: "/nonexistent/policy.yaml"}},
			},
			wantCode:        connect.CodeInvalidArgument,
			wantErrContains: []string{"load policy sources", "/nonexistent/policy.yaml"},
		},
		{
			name: "unimplemented url source is an error, not an allow",
			policies: []*policyv1.PolicySource{
				{Source: &policyv1.PolicySource_Url{Url: "https://example.com/policy.yaml"}},
			},
			wantCode:        connect.CodeInvalidArgument,
			wantErrContains: []string{"load policy sources", "URL policy sources"},
		},
		{
			// The engine builds CEL programs without cel.InterruptCheckFrequency,
			// so cancellation is never observed mid-evaluation and the error the
			// engine returns is the policy's own. The context state still has to
			// win, or a canceled request is reported as a server failure the
			// caller may retry.
			name:            "canceled context outranks an evaluation failure",
			policies:        []*policyv1.PolicySource{inlinePolicy(divideByZero)},
			ctx:             canceledContext,
			wantCode:        connect.CodeCanceled,
			wantErrContains: []string{"evaluate policies", "division by zero"},
		},
		{
			name:            "expired deadline outranks an evaluation failure",
			policies:        []*policyv1.PolicySource{inlinePolicy(divideByZero)},
			ctx:             expiredContext,
			wantCode:        connect.CodeDeadlineExceeded,
			wantErrContains: []string{"evaluate policies", "division by zero"},
		},
		{
			name:            "canceled context outranks a source load failure",
			policies:        []*policyv1.PolicySource{inlinePolicy("policies: [[[")},
			ctx:             canceledContext,
			wantCode:        connect.CodeCanceled,
			wantErrContains: []string{"load policy sources"},
		},
		{
			name:            "expired deadline outranks a compile failure",
			policies:        []*policyv1.PolicySource{inlinePolicy(uncompilable)},
			ctx:             expiredContext,
			wantCode:        connect.CodeDeadlineExceeded,
			wantErrContains: []string{"compile policies"},
		},
		{
			name:        "genuine allow still allows",
			policies:    []*policyv1.PolicySource{inlinePolicy(allowQuiet)},
			wantOutcome: policyv1.ActionType_ACTION_TYPE_ALLOW,
			wantActions: 0,
		},
		{
			name:        "genuine deny still denies",
			policies:    []*policyv1.PolicySource{inlinePolicy(denyAlways)},
			wantOutcome: policyv1.ActionType_ACTION_TYPE_DENY,
			wantActions: 1,
		},
		{
			name:        "genuine warn still warns",
			policies:    []*policyv1.PolicySource{inlinePolicy(warnAlways)},
			wantOutcome: policyv1.ActionType_ACTION_TYPE_WARN,
			wantActions: 1,
		},
		{
			name:        "deny wins over warn",
			policies:    []*policyv1.PolicySource{inlinePolicy(warnAlways), inlinePolicy(denyAlways)},
			wantOutcome: policyv1.ActionType_ACTION_TYPE_DENY,
			wantActions: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []PolicyOption
			if tt.localMode {
				opts = append(opts, WithPolicyLocalMode())
			}
			handler := NewPolicyHandler(opts...)

			ctx := t.Context()
			if tt.ctx != nil {
				ctx = tt.ctx(t)
			}

			resp, err := handler.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
				Policies: tt.policies,
				Input: &policyv1.EvaluateRequest_ScanVulnerability{
					ScanVulnerability: &policyv1.ScanVulnerabilityPolicyInput{},
				},
			}))

			if tt.wantCode != 0 {
				if err == nil {
					t.Fatalf("Evaluate succeeded with outcome %v and %d actions, want error %v",
						resp.Msg.GetOutcome(), len(resp.Msg.GetActions()), tt.wantCode)
				}
				// The invariant: no response at all, so there is no outcome
				// field a client could read as a permission.
				if resp != nil {
					t.Errorf("Evaluate returned both an error and a response with outcome %v; a failure must not carry a decision",
						resp.Msg.GetOutcome())
				}
				if got := connect.CodeOf(err); got != tt.wantCode {
					t.Errorf("Evaluate error code = %v, want %v (err: %v)", got, tt.wantCode, err)
				}
				for _, want := range tt.wantErrContains {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Evaluate error %q does not contain %q", err.Error(), want)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}
			if got := resp.Msg.GetOutcome(); got != tt.wantOutcome {
				t.Errorf("outcome = %v, want %v", got, tt.wantOutcome)
			}
			if got := len(resp.Msg.GetActions()); got != tt.wantActions {
				t.Errorf("actions = %d, want %d", got, tt.wantActions)
			}
			// A decision is only a decision when nothing failed.
			if got := resp.Msg.GetErrors(); len(got) != 0 {
				t.Errorf("errors = %v, want none alongside outcome %v", got, resp.Msg.GetOutcome())
			}
		})
	}
}

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

// TestPolicyConnectError covers the classification itself, including the
// error-chain branch that the handler cannot reach today: the engine builds
// CEL programs without cel.InterruptCheckFrequency, so cel-go never raises an
// InterruptError and never wraps context.Cause. If interrupt checking is ever
// enabled, that error must already map to the right code rather than to
// CodeInternal.
func TestPolicyConnectError(t *testing.T) {
	liveCtx := func(t *testing.T) context.Context { return t.Context() }

	tests := []struct {
		name     string
		ctx      func(t *testing.T) context.Context
		fallback connect.Code
		err      error
		wantCode connect.Code
	}{
		{
			name:     "plain failure uses the fallback",
			ctx:      liveCtx,
			fallback: connect.CodeInternal,
			err:      errors.New("division by zero"),
			wantCode: connect.CodeInternal,
		},
		{
			name:     "plain failure honors a different fallback",
			ctx:      liveCtx,
			fallback: connect.CodeInvalidArgument,
			err:      errors.New("parse inline policy"),
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "wrapped cancellation wins over the fallback",
			ctx:      liveCtx,
			fallback: connect.CodeInternal,
			err:      fmt.Errorf("evaluate policies: %w", context.Canceled),
			wantCode: connect.CodeCanceled,
		},
		{
			name:     "wrapped deadline wins over the fallback",
			ctx:      liveCtx,
			fallback: connect.CodeInternal,
			err:      fmt.Errorf("evaluate policies: %w", context.DeadlineExceeded),
			wantCode: connect.CodeDeadlineExceeded,
		},
		{
			name:     "canceled context wins when the error is silent about it",
			ctx:      canceledContext,
			fallback: connect.CodeInternal,
			err:      errors.New("division by zero"),
			wantCode: connect.CodeCanceled,
		},
		{
			name:     "expired context wins when the error is silent about it",
			ctx:      expiredContext,
			fallback: connect.CodeInvalidArgument,
			err:      errors.New("parse inline policy"),
			wantCode: connect.CodeDeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyConnectError(tt.ctx(t), tt.fallback, tt.err)
			if got.Code() != tt.wantCode {
				t.Errorf("code = %v, want %v", got.Code(), tt.wantCode)
			}
			// The cause must survive classification or the failure is
			// undebuggable from the wire.
			if !errors.Is(got, tt.err) {
				t.Errorf("error %v does not wrap the cause %v", got, tt.err)
			}
		})
	}
}
