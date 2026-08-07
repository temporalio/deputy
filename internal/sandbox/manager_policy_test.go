package sandbox

import (
	"strings"
	"testing"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
	"github.com/temporalio/deputy/internal/policy"
)

// TestEvaluateExecutionPolicyBindingTypes pins the runtime CEL types of the
// variables evaluateExecutionPolicy binds from ExecuteRequest, so the
// documented variable contract (policy.VariableInfo and the generated
// policy-inputs reference) cannot silently drift from the live binding.
// It evaluates real policies through the production code path: command is an
// argv list (repeated string), workspace_dir is a string, and requested_config
// and context are message-shaped with snake_case proto fields. A future type
// flip (for example binding command as a joined string) fails these cases.
func TestEvaluateExecutionPolicyBindingTypes(t *testing.T) {
	req := &sandboxv1.ExecuteRequest{
		Command:      []string{"curl", "https://example.com"},
		WorkspaceDir: "/workspace/app",
		Config: &sandboxv1.SandboxConfig{
			Image:       "alpine:3.20",
			NetworkMode: sandboxv1.NetworkMode_NETWORK_MODE_NONE,
		},
		Context: &sandboxv1.ExecutionContext{
			Source:         sandboxv1.ExecutionSource_EXECUTION_SOURCE_EXEC,
			WrappedCommand: "curl https://example.com",
		},
	}

	tests := []struct {
		name string
		body string
		// wantDeny is the expected denial reason; empty means the policy must
		// evaluate cleanly and allow.
		wantDeny string
		// wantErrContains asserts an evaluation failure, proving the
		// expression's type assumptions do not hold at runtime.
		wantErrContains string
	}{
		{
			name: "command supports list operations",
			body: `command.exists(a, a == "curl") && size(command) == 2 && command[0] == "curl"
  ? [{"action": "deny", "reason": "curl is not allowed"}]
  : [{"action": "allow"}]`,
			wantDeny: "curl is not allowed",
		},
		{
			name: "command is not a string",
			body: `command.startsWith("curl")
  ? [{"action": "deny", "reason": "unreachable"}]
  : [{"action": "allow"}]`,
			wantErrContains: "no such overload",
		},
		{
			name: "workspace_dir supports string operations",
			body: `workspace_dir.startsWith("/workspace")
  ? [{"action": "deny", "reason": "workspace dir matched"}]
  : [{"action": "allow"}]`,
			wantDeny: "workspace dir matched",
		},
		{
			name: "requested_config exposes SandboxConfig proto fields",
			body: `requested_config.image == "alpine:3.20"
  ? [{"action": "deny", "reason": "image matched"}]
  : [{"action": "allow"}]`,
			wantDeny: "image matched",
		},
		{
			name: "context exposes ExecutionContext proto fields",
			body: `context.wrapped_command.startsWith("curl")
  ? [{"action": "deny", "reason": "wrapped command matched"}]
  : [{"action": "allow"}]`,
			wantDeny: "wrapped command matched",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := policy.NewEngine([]policy.Source{{Name: "binding-probe", Body: tc.body}})
			if err != nil {
				t.Fatalf("NewEngine() error: %v", err)
			}
			mgr, err := NewManager(t.Context(), WithPolicyEngine(eng))
			if err != nil {
				t.Fatalf("NewManager() error: %v", err)
			}

			err = mgr.evaluateExecutionPolicy(t.Context(), req)
			switch {
			case tc.wantErrContains != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) {
					t.Fatalf("evaluateExecutionPolicy() error = %v, want containing %q", err, tc.wantErrContains)
				}
			case tc.wantDeny != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantDeny) {
					t.Fatalf("evaluateExecutionPolicy() error = %v, want denial containing %q", err, tc.wantDeny)
				}
			default:
				if err != nil {
					t.Fatalf("evaluateExecutionPolicy() error = %v, want allow", err)
				}
			}
		})
	}
}
