package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/deputy/internal/collections"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
)

// deepCloneMap creates a deep copy of a map[string]any for testing.
func deepCloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCloneValue(v)
	}
	return out
}

func deepCloneValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCloneMap(val)
	case []any:
		clone := make([]any, len(val))
		for i, elem := range val {
			clone[i] = deepCloneValue(elem)
		}
		return clone
	default:
		return v
	}
}

func TestNewEngine_Empty(t *testing.T) {
	eng, err := NewEngine(nil)
	if err != nil {
		t.Fatalf("NewEngine(nil) returned error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngine(nil) returned nil engine")
	}
	if len(eng.compiled) != 0 {
		t.Errorf("expected 0 compiled policies, got %d", len(eng.compiled))
	}
}

func TestNewEngine_EmptySlice(t *testing.T) {
	eng, err := NewEngine([]Source{})
	if err != nil {
		t.Fatalf("NewEngine([]) returned error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngine([]) returned nil engine")
	}
	if len(eng.compiled) != 0 {
		t.Errorf("expected 0 compiled policies, got %d", len(eng.compiled))
	}
}

func TestNewEngine_ValidSource(t *testing.T) {
	sources := []Source{
		{Name: "test-policy", Body: `[{"action": "allow"}]`},
	}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() returned error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngine() returned nil engine")
	}
	if len(eng.compiled) != 1 {
		t.Errorf("expected 1 compiled policy, got %d", len(eng.compiled))
	}
}

func TestNewEngine_CompilationError(t *testing.T) {
	sources := []Source{
		{Name: "bad-policy", Body: `this is not valid CEL syntax !@#$`},
	}
	_, err := NewEngine(sources)
	if err == nil {
		t.Fatal("NewEngine() should return error for invalid CEL syntax")
	}
	if !strings.Contains(err.Error(), "bad-policy") {
		t.Errorf("error should contain policy name, got: %v", err)
	}
}

func TestNewEngine_MultipleSourcesWithOneError(t *testing.T) {
	sources := []Source{
		{Name: "good-policy", Body: `[{"action": "allow"}]`},
		{Name: "bad-policy", Body: `invalid syntax !!!`},
	}
	_, err := NewEngine(sources)
	if err == nil {
		t.Fatal("NewEngine() should return error when any source fails")
	}
}

func TestEvaluateAll_NilEngine(t *testing.T) {
	var eng *Engine
	actions, err := eng.EvaluateAll(t.Context(), nil, "", "")
	if err != nil {
		t.Errorf("EvaluateAll on nil engine should not error, got: %v", err)
	}
	if actions != nil {
		t.Errorf("EvaluateAll on nil engine should return nil actions, got: %v", actions)
	}
}

func TestEvaluateAll_EmptyEngine(t *testing.T) {
	eng := &Engine{}
	actions, err := eng.EvaluateAll(t.Context(), nil, "", "")
	if err != nil {
		t.Errorf("EvaluateAll on empty engine should not error, got: %v", err)
	}
	if actions != nil {
		t.Errorf("EvaluateAll on empty engine should return nil actions, got: %v", actions)
	}
}

func TestEvaluateAll_SimpleAllow(t *testing.T) {
	sources := []Source{
		{Name: "allow-all", Body: `[{"action": "allow"}]`},
	}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	actions, err := eng.EvaluateAll(t.Context(), nil, "", "")
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != "allow" {
		t.Errorf("expected action type 'allow', got %q", actions[0].Type)
	}
}

func TestEvaluateAll_DenyWithReason(t *testing.T) {
	sources := []Source{
		{Name: "deny-policy", Body: `[{"action": "deny", "reason": "test reason"}]`},
	}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	actions, err := eng.EvaluateAll(t.Context(), nil, "", "")
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != "deny" {
		t.Errorf("expected action type 'deny', got %q", actions[0].Type)
	}
	if actions[0].Reason != "test reason" {
		t.Errorf("expected reason 'test reason', got %q", actions[0].Reason)
	}
}

func TestEvaluateAll_CommandFiltering(t *testing.T) {
	tests := []struct {
		name       string
		policyBody string
		command    string
		wantSkip   bool
	}{
		{
			name:       "no command restriction, always runs",
			policyBody: `[{"action": "allow"}]`,
			command:    "scan",
			wantSkip:   false,
		},
		{
			name: "command matches restriction",
			policyBody: `//! policy.commands = scan
[{"action": "allow"}]`,
			command:  "scan",
			wantSkip: false,
		},
		{
			name: "command does not match restriction",
			policyBody: `//! policy.commands = proxy
[{"action": "deny"}]`,
			command:  "scan",
			wantSkip: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := []Source{{Name: "test", Body: tc.policyBody}}
			eng, err := NewEngine(sources)
			if err != nil {
				t.Fatalf("NewEngine() error: %v", err)
			}

			actions, err := eng.EvaluateAll(t.Context(), nil, tc.command, "")
			if err != nil {
				t.Fatalf("EvaluateAll() error: %v", err)
			}

			if tc.wantSkip && len(actions) > 0 {
				t.Errorf("expected policy to be skipped, but got %d actions", len(actions))
			}
			if !tc.wantSkip && len(actions) == 0 {
				t.Error("expected policy to run, but got no actions")
			}
		})
	}
}

func TestEvaluateAll_EntrypointFiltering(t *testing.T) {
	tests := []struct {
		name       string
		policyBody string
		entrypoint string
		wantSkip   bool
	}{
		{
			name:       "no entrypoint restriction, always runs",
			policyBody: `[{"action": "allow"}]`,
			entrypoint: "go_artifact_request",
			wantSkip:   false,
		},
		{
			name: "entrypoint matches restriction",
			policyBody: `//! policy.entrypoints = go_artifact_request
[{"action": "allow"}]`,
			entrypoint: "go_artifact_request",
			wantSkip:   false,
		},
		{
			name: "entrypoint does not match restriction",
			policyBody: `//! policy.entrypoints = npm_artifact_request
[{"action": "deny"}]`,
			entrypoint: "go_artifact_request",
			wantSkip:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := []Source{{Name: "test", Body: tc.policyBody}}
			eng, err := NewEngine(sources)
			if err != nil {
				t.Fatalf("NewEngine() error: %v", err)
			}

			actions, err := eng.EvaluateAll(t.Context(), nil, "", tc.entrypoint)
			if err != nil {
				t.Fatalf("EvaluateAll() error: %v", err)
			}

			if tc.wantSkip && len(actions) > 0 {
				t.Errorf("expected policy to be skipped, but got %d actions", len(actions))
			}
			if !tc.wantSkip && len(actions) == 0 {
				t.Error("expected policy to run, but got no actions")
			}
		})
	}
}

func TestEvaluateAll_AdvisoryMode(t *testing.T) {
	policyBody := `//! policy.mode = advisory
[{"action": "deny", "reason": "should become warn"}]`

	sources := []Source{{Name: "advisory-test", Body: policyBody}}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	actions, err := eng.EvaluateAll(t.Context(), nil, "", "")
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != "warn" {
		t.Errorf("advisory mode should downgrade deny to warn, got %q", actions[0].Type)
	}
}

func TestEvaluateAll_MultipleAdvisoryActions(t *testing.T) {
	policyBody := `//! policy.mode = advisory
[{"action": "deny", "reason": "first"}, {"action": "deny", "reason": "second"}, {"action": "warn", "reason": "third"}]`

	sources := []Source{{Name: "multi-advisory", Body: policyBody}}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	actions, err := eng.EvaluateAll(t.Context(), nil, "", "")
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(actions))
	}

	// All deny should be downgraded to warn
	for i, act := range actions {
		if act.Type != "warn" {
			t.Errorf("action[%d] should be warn in advisory mode, got %q", i, act.Type)
		}
	}
}

func TestEvaluateAll_ContextCancellation(t *testing.T) {
	// Create a simple policy
	sources := []Source{{Name: "test", Body: `[{"action": "allow"}]`}}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	// Cancel the context before evaluation
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Evaluation should still work for simple policies (CEL doesn't check context for simple evals)
	// This is primarily a smoke test for context passing
	_, _ = eng.EvaluateAll(ctx, nil, "", "")
}

func TestEvaluateAll_PayloadNotModified(t *testing.T) {
	sources := []Source{{Name: "test", Body: `[{"action": "allow"}]`}}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	// Create a payload
	original := map[string]any{
		"key": "value",
	}

	_, err = eng.EvaluateAllMap(t.Context(), original, "scan", "scan_report")
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	// Verify original payload wasn't modified
	if original["env"] != nil {
		t.Error("original payload should not have been modified with env")
	}
}

// TestNewEngine_UndeclaredVariableRejected verifies that policies using unknown
// variables are rejected at compile time - preventing injection attacks.
func TestNewEngine_UndeclaredVariableRejected(t *testing.T) {
	tests := []struct {
		name       string
		policyBody string
		wantErr    bool
	}{
		{
			name:       "known variable pkg is allowed",
			policyBody: `pkg.name == "test" ? [{"action": "deny"}] : [{"action": "allow"}]`,
			wantErr:    false,
		},
		{
			name:       "unknown variable is rejected",
			policyBody: `injected_var == true ? [{"action": "deny"}] : [{"action": "allow"}]`,
			wantErr:    true,
		},
		{
			name:       "undeclared variable in complex expression is rejected",
			policyBody: `pkg.name == "test" && malicious_payload.execute() ? [{"action": "deny"}] : [{"action": "allow"}]`,
			wantErr:    true,
		},
		{
			name:       "all default variables are allowed",
			policyBody: `vulnerability != null && pkg != null ? [{"action": "deny"}] : [{"action": "allow"}]`,
			wantErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := []Source{{Name: "test-policy", Body: tc.policyBody}}
			_, err := NewEngine(sources)
			if tc.wantErr && err == nil {
				t.Error("expected error for undeclared variable, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestNewEngine_InvalidEntrypointRejected verifies that policies with unknown
// entrypoints are rejected at load time.
func TestNewEngine_InvalidEntrypointRejected(t *testing.T) {
	tests := []struct {
		name       string
		policyBody string
		wantErr    bool
		errContain string
	}{
		{
			name: "valid entrypoint is allowed",
			policyBody: `//! policy.entrypoints = scan_report
[{"action": "allow"}]`,
			wantErr: false,
		},
		{
			name: "invalid entrypoint is rejected",
			policyBody: `//! policy.entrypoints = malicious_entrypoint
[{"action": "allow"}]`,
			wantErr:    true,
			errContain: "invalid entrypoint",
		},
		{
			name: "mixed valid and invalid entrypoints is rejected",
			policyBody: `//! policy.entrypoints = scan_report, fake_entrypoint
[{"action": "allow"}]`,
			wantErr:    true,
			errContain: "invalid entrypoint",
		},
		{
			name:       "no entrypoint restriction is allowed",
			policyBody: `[{"action": "allow"}]`,
			wantErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := []Source{{Name: "test-policy", Body: tc.policyBody}}
			_, err := NewEngine(sources)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error for invalid entrypoint, got nil")
				} else if tc.errContain != "" && !strings.Contains(err.Error(), tc.errContain) {
					t.Errorf("error should contain %q, got: %v", tc.errContain, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestEvaluateAll_InvalidEntrypointRejected verifies that invalid entrypoints
// are rejected at evaluation time.
func TestEvaluateAll_InvalidEntrypointRejected(t *testing.T) {
	sources := []Source{{Name: "test", Body: `[{"action": "allow"}]`}}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	_, err = eng.EvaluateAll(t.Context(), nil, "scan", "fake_entrypoint")
	if err == nil {
		t.Error("expected error for invalid entrypoint at evaluation time")
	}
	if !strings.Contains(err.Error(), "invalid entrypoint") {
		t.Errorf("error should mention invalid entrypoint, got: %v", err)
	}
}

func TestShouldSkip(t *testing.T) {
	tests := []struct {
		name       string
		pol        compiledPolicy
		command    string
		entrypoint string
		wantSkip   bool
	}{
		{
			name:       "no restrictions, no skip",
			pol:        compiledPolicy{},
			command:    "scan",
			entrypoint: "go_request",
			wantSkip:   false,
		},
		{
			name: "command matches, no skip",
			pol: compiledPolicy{
				commands: map[string]struct{}{"scan": {}},
			},
			command:  "scan",
			wantSkip: false,
		},
		{
			name: "command does not match, skip",
			pol: compiledPolicy{
				commands: map[string]struct{}{"proxy": {}},
			},
			command:  "scan",
			wantSkip: true,
		},
		{
			name: "entrypoint matches, no skip",
			pol: compiledPolicy{
				entrypoints: map[string]struct{}{"go_request": {}},
			},
			entrypoint: "go_request",
			wantSkip:   false,
		},
		{
			name: "entrypoint does not match, skip",
			pol: compiledPolicy{
				entrypoints: map[string]struct{}{"npm_request": {}},
			},
			entrypoint: "go_request",
			wantSkip:   true,
		},
		{
			name: "both restrictions match, no skip",
			pol: compiledPolicy{
				commands:    map[string]struct{}{"scan": {}},
				entrypoints: map[string]struct{}{"go_request": {}},
			},
			command:    "scan",
			entrypoint: "go_request",
			wantSkip:   false,
		},
		{
			name: "command matches but entrypoint doesn't, skip",
			pol: compiledPolicy{
				commands:    map[string]struct{}{"scan": {}},
				entrypoints: map[string]struct{}{"npm_request": {}},
			},
			command:    "scan",
			entrypoint: "go_request",
			wantSkip:   true,
		},
		{
			name: "empty command in request, skip when restriction exists",
			pol: compiledPolicy{
				commands: map[string]struct{}{"scan": {}},
			},
			command:  "",
			wantSkip: false, // Empty command means no filtering
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkip(tc.pol, tc.command, tc.entrypoint)
			if got != tc.wantSkip {
				t.Errorf("shouldSkip() = %v, want %v", got, tc.wantSkip)
			}
		})
	}
}

func TestNewSetFunc(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected collections.Set[string]
	}{
		{
			name:     "nil slice",
			items:    nil,
			expected: nil,
		},
		{
			name:     "empty slice",
			items:    []string{},
			expected: nil,
		},
		{
			name:     "single item",
			items:    []string{"foo"},
			expected: collections.Set[string]{"foo": {}},
		},
		{
			name:     "multiple items",
			items:    []string{"foo", "bar", "baz"},
			expected: collections.Set[string]{"foo": {}, "bar": {}, "baz": {}},
		},
		{
			name:     "whitespace trimmed",
			items:    []string{"  foo  ", "bar", "  "},
			expected: collections.Set[string]{"foo": {}, "bar": {}},
		},
		{
			name:     "empty strings filtered",
			items:    []string{"foo", "", "bar"},
			expected: collections.Set[string]{"foo": {}, "bar": {}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := collections.NewSetFunc(tc.items, strings.TrimSpace)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %d items, got %d", len(tc.expected), len(result))
				return
			}
			for k := range tc.expected {
				if _, ok := result[k]; !ok {
					t.Errorf("expected key %q not found in result", k)
				}
			}
		})
	}
}

func TestDowngradeAdvisory(t *testing.T) {
	tests := []struct {
		name     string
		actions  []Action
		expected []Action
	}{
		{
			name:     "nil actions",
			actions:  nil,
			expected: nil,
		},
		{
			name:     "empty actions",
			actions:  []Action{},
			expected: []Action{},
		},
		{
			name: "deny becomes warn",
			actions: []Action{
				{Type: "deny", Reason: "test"},
			},
			expected: []Action{
				{Type: "warn", Reason: "test"},
			},
		},
		{
			name: "DENY (uppercase) becomes warn",
			actions: []Action{
				{Type: "DENY", Reason: "test"},
			},
			expected: []Action{
				{Type: "warn", Reason: "test"},
			},
		},
		{
			name: "warn stays warn",
			actions: []Action{
				{Type: "warn", Reason: "already warn"},
			},
			expected: []Action{
				{Type: "warn", Reason: "already warn"},
			},
		},
		{
			name: "allow stays allow",
			actions: []Action{
				{Type: "allow"},
			},
			expected: []Action{
				{Type: "allow"},
			},
		},
		{
			name: "deny without reason gets default",
			actions: []Action{
				{Type: "deny", Reason: ""},
			},
			expected: []Action{
				{Type: "warn", Reason: "advisory policy (originally deny)"},
			},
		},
		{
			name: "status cleared on downgrade",
			actions: []Action{
				{Type: "deny", Status: intPtr(403)},
			},
			expected: []Action{
				{Type: "warn", Status: nil, Reason: "advisory policy (originally deny)"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := downgradeAdvisory(tc.actions)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %d actions, got %d", len(tc.expected), len(result))
				return
			}
			for i := range tc.expected {
				if result[i].Type != tc.expected[i].Type {
					t.Errorf("action[%d].Type = %q, want %q", i, result[i].Type, tc.expected[i].Type)
				}
				if result[i].Reason != tc.expected[i].Reason {
					t.Errorf("action[%d].Reason = %q, want %q", i, result[i].Reason, tc.expected[i].Reason)
				}
			}
		})
	}
}

func TestCloneMap(t *testing.T) {
	t.Run("nil map returns empty", func(t *testing.T) {
		result := cloneMap(nil)
		if result == nil {
			t.Error("cloneMap(nil) should return empty map, not nil")
		}
		if len(result) != 0 {
			t.Error("cloneMap(nil) should return empty map")
		}
	})

	t.Run("shallow clone is independent", func(t *testing.T) {
		original := map[string]any{"key": "value"}
		clone := cloneMap(original)

		clone["key"] = "modified"
		if original["key"] != "value" {
			t.Error("modifying clone should not affect original")
		}
	})

	t.Run("adding keys to clone does not affect original", func(t *testing.T) {
		original := map[string]any{"key": "value"}
		clone := cloneMap(original)

		clone["new_key"] = "new_value"
		if _, exists := original["new_key"]; exists {
			t.Error("adding key to clone should not affect original")
		}
	})

	t.Run("shallow clone shares nested references", func(t *testing.T) {
		// This is expected behavior for shallow clone - nested maps are shared
		nested := map[string]any{"key": "value"}
		original := map[string]any{"nested": nested}
		clone := cloneMap(original)

		// Verify both point to same nested map (shallow clone behavior)
		nestedClone := clone["nested"].(map[string]any)
		nestedOriginal := original["nested"].(map[string]any)
		nestedClone["key"] = "modified"

		// With shallow clone, original IS affected (this is expected)
		if nestedOriginal["key"] != "modified" {
			t.Error("shallow clone should share nested map references")
		}
	})

	t.Run("preserves all keys", func(t *testing.T) {
		original := map[string]any{
			"a": 1,
			"b": "two",
			"c": true,
		}
		clone := cloneMap(original)

		if len(clone) != len(original) {
			t.Errorf("clone has %d keys, want %d", len(clone), len(original))
		}
		for k, v := range original {
			if clone[k] != v {
				t.Errorf("clone[%q] = %v, want %v", k, clone[k], v)
			}
		}
	})
}

// mockProgram is a test double for celProgram that allows controlled behavior.
type mockProgram struct {
	returnVal ref.Val
	returnErr error
}

func (m *mockProgram) ContextEval(ctx context.Context, input any) (ref.Val, *cel.EvalDetails, error) {
	if m.returnErr != nil {
		return nil, nil, m.returnErr
	}
	return m.returnVal, nil, nil
}

func TestEvaluateAll_ProgramError(t *testing.T) {
	// Create engine with mock program that returns error
	eng := &Engine{
		compiled: []compiledPolicy{
			{
				source:  Source{Name: "error-policy"},
				program: &mockProgram{returnErr: errors.New("eval failed")},
			},
		},
	}

	_, err := eng.EvaluateAllMap(t.Context(), nil, "", "")
	if err == nil {
		t.Fatal("expected error from failing program")
	}
	if !strings.Contains(err.Error(), "error-policy") {
		t.Errorf("error should contain policy name, got: %v", err)
	}
}

// TestEvaluateAll_ProtoFirst verifies that proto messages can be passed directly
// to the policy engine and accessed via CEL's native proto support.
func TestEvaluateAll_ProtoFirst(t *testing.T) {
	tests := []struct {
		name       string
		policyBody string
		payload    map[string]any
		wantAction string
		wantReason string
	}{
		{
			name: "access vulnerability finding proto",
			policyBody: `
vulnerability.advisory.id == "CVE-2021-44228"
  ? [{"action": "deny", "reason": "Log4Shell detected"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{
						Id: "CVE-2021-44228",
					},
				},
			},
			wantAction: "deny",
			wantReason: "Log4Shell detected",
		},
		{
			name: "access package proto fields",
			policyBody: `
pkg.name == "lodash" && pkg.ecosystem == "npm"
  ? [{"action": "deny", "reason": "lodash blocked"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"pkg": &dependencyv1.Package{
					Name:      "lodash",
					Version:   "4.17.21",
					Ecosystem: "npm",
				},
			},
			wantAction: "deny",
			wantReason: "lodash blocked",
		},
		{
			name: "access target proto fields via field",
			policyBody: `
target.display_path.contains("github.com")
  ? [{"action": "allow", "reason": "github allowed"}]
  : [{"action": "deny"}]`,
			payload: map[string]any{
				"target": &targetv1.Target{
					DisplayPath: "github.com/foo/bar",
				},
			},
			wantAction: "allow",
			wantReason: "github allowed",
		},
		{
			name: "access env proto fields",
			policyBody: `
env.command == "scan" && env.entrypoint == "scan_vulnerability"
  ? [{"action": "allow"}]
  : [{"action": "deny"}]`,
			payload: map[string]any{
				"env": &policyv1.Environment{
					Command:    "scan",
					Entrypoint: "scan_vulnerability",
				},
			},
			wantAction: "allow",
		},
		{
			name: "access severity level enum",
			policyBody: `
vulnerability.advisory.severity.level == deputy.vulnerability.v1.SeverityLevel.SEVERITY_LEVEL_CRITICAL
  ? [{"action": "deny", "reason": "critical vuln"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{
						Severity: &vulnerabilityv1.Severity{
							Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						},
					},
				},
			},
			wantAction: "deny",
			wantReason: "critical vuln",
		},
		{
			name: "list of vulnerability protos",
			policyBody: `
vulnerabilities.exists(v, v.advisory.id == "CVE-2023-1234")
  ? [{"action": "deny", "reason": "known vuln found"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerabilities": []*vulnerabilityv1.Finding{
					{Advisory: &vulnerabilityv1.Advisory{Id: "CVE-2021-1111"}},
					{Advisory: &vulnerabilityv1.Advisory{Id: "CVE-2023-1234"}},
				},
			},
			wantAction: "deny",
			wantReason: "known vuln found",
		},
		{
			name: "scan vulnerability context proto",
			policyBody: `
vulnerability.advisory.id == "CVE-2024-5678" && pkg.name == "example"
  ? [{"action": "deny", "reason": "context match"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{Id: "CVE-2024-5678"},
				},
				"pkg": &dependencyv1.Package{Name: "example"},
			},
			wantAction: "deny",
			wantReason: "context match",
		},
		// Severity helper function tests - global function syntax
		{
			name: "severityAtLeast global function syntax",
			policyBody: `
severityAtLeast(vulnerability, "HIGH")
  ? [{"action": "deny", "reason": "high or above"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{
						Severity: &vulnerabilityv1.Severity{
							Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						},
					},
				},
			},
			wantAction: "deny",
			wantReason: "high or above",
		},
		// Severity helper function tests - method syntax
		{
			name: "severityAtLeast method syntax",
			policyBody: `
vulnerability.severityAtLeast("HIGH")
  ? [{"action": "deny", "reason": "high or above method"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{
						Severity: &vulnerabilityv1.Severity{
							Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						},
					},
				},
			},
			wantAction: "deny",
			wantReason: "high or above method",
		},
		{
			name: "isCritical method syntax",
			policyBody: `
vulnerability.isCritical()
  ? [{"action": "deny", "reason": "critical method"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{
						Severity: &vulnerabilityv1.Severity{
							Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
						},
					},
				},
			},
			wantAction: "deny",
			wantReason: "critical method",
		},
		{
			name: "isHighOrAbove method syntax",
			policyBody: `
vulnerability.isHighOrAbove()
  ? [{"action": "deny", "reason": "high or above method"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerability": &vulnerabilityv1.Finding{
					Advisory: &vulnerabilityv1.Advisory{
						Severity: &vulnerabilityv1.Severity{
							Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
						},
					},
				},
			},
			wantAction: "deny",
			wantReason: "high or above method",
		},
		{
			name: "method syntax in filter",
			policyBody: `
vulnerabilities.filter(v, v.isCritical()).size() > 0
  ? [{"action": "deny", "reason": "has critical"}]
  : [{"action": "allow"}]`,
			payload: map[string]any{
				"vulnerabilities": []*vulnerabilityv1.Finding{
					{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW}}},
					{Advisory: &vulnerabilityv1.Advisory{Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL}}},
				},
			},
			wantAction: "deny",
			wantReason: "has critical",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sources := []Source{{Name: "proto-test", Body: tc.policyBody}}
			eng, err := NewEngine(sources)
			if err != nil {
				t.Fatalf("NewEngine() error: %v", err)
			}

			actions, err := eng.EvaluateAllMap(t.Context(), tc.payload, "", "")
			if err != nil {
				t.Fatalf("EvaluateAll() error: %v", err)
			}

			if len(actions) != 1 {
				t.Fatalf("expected 1 action, got %d: %+v", len(actions), actions)
			}
			if actions[0].Type != tc.wantAction {
				t.Errorf("action type = %q, want %q", actions[0].Type, tc.wantAction)
			}
			if tc.wantReason != "" && actions[0].Reason != tc.wantReason {
				t.Errorf("action reason = %q, want %q", actions[0].Reason, tc.wantReason)
			}
		})
	}
}

// Helper functions

func intPtr(i int) *int {
	return &i
}
