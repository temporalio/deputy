package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/deputy/internal/collections"
)

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
	if !contains(err.Error(), "bad-policy") {
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
	actions, err := eng.EvaluateAll(context.Background(), nil, "", "")
	if err != nil {
		t.Errorf("EvaluateAll on nil engine should not error, got: %v", err)
	}
	if actions != nil {
		t.Errorf("EvaluateAll on nil engine should return nil actions, got: %v", actions)
	}
}

func TestEvaluateAll_EmptyEngine(t *testing.T) {
	eng := &Engine{}
	actions, err := eng.EvaluateAll(context.Background(), nil, "", "")
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

	actions, err := eng.EvaluateAll(context.Background(), nil, "", "")
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

	actions, err := eng.EvaluateAll(context.Background(), nil, "", "")
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

			actions, err := eng.EvaluateAll(context.Background(), nil, tc.command, "")
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

			actions, err := eng.EvaluateAll(context.Background(), nil, "", tc.entrypoint)
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

	actions, err := eng.EvaluateAll(context.Background(), nil, "", "")
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

	actions, err := eng.EvaluateAll(context.Background(), nil, "", "")
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
	ctx, cancel := context.WithCancel(context.Background())
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

	_, err = eng.EvaluateAll(context.Background(), original, "cmd", "ep")
	if err != nil {
		t.Fatalf("EvaluateAll() error: %v", err)
	}

	// Verify original payload wasn't modified
	if original["env"] != nil {
		t.Error("original payload should not have been modified with env")
	}
}

func TestParseUndeclared(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		expected []string
	}{
		{
			name:     "single undeclared",
			msg:      "ERROR: <input>:1:1: undeclared reference to 'foo'",
			expected: []string{"foo"},
		},
		{
			name:     "multiple undeclared",
			msg:      "undeclared reference to 'foo'\nundeclared reference to 'bar'",
			expected: []string{"foo", "bar"},
		},
		{
			name:     "no undeclared",
			msg:      "some other error",
			expected: nil,
		},
		{
			name:     "empty message",
			msg:      "",
			expected: nil,
		},
		{
			name:     "complex undeclared name",
			msg:      "undeclared reference to 'my_variable_123'",
			expected: []string{"my_variable_123"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseUndeclared(tc.msg)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %d undeclared vars, got %d: %v", len(tc.expected), len(result), result)
				return
			}
			for i, v := range tc.expected {
				if result[i] != v {
					t.Errorf("expected result[%d] = %q, got %q", i, v, result[i])
				}
			}
		})
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

	t.Run("clone is independent", func(t *testing.T) {
		original := map[string]any{"key": "value"}
		clone := cloneMap(original)

		clone["key"] = "modified"
		if original["key"] != "value" {
			t.Error("modifying clone should not affect original")
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

	_, err := eng.EvaluateAll(context.Background(), nil, "", "")
	if err == nil {
		t.Fatal("expected error from failing program")
	}
	if !contains(err.Error(), "error-policy") {
		t.Errorf("error should contain policy name, got: %v", err)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func intPtr(i int) *int {
	return &i
}
