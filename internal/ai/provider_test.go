package ai

import (
	"context"
	"errors"
	"iter"
	"testing"
)

// mockProvider is a test implementation of the Provider interface.
type mockProvider struct {
	name         string
	capabilities ProviderCapabilities
	response     *CompletionResponse
	err          error
	events       []StreamEvent
}

func (m *mockProvider) Name() string                           { return m.name }
func (m *mockProvider) Capabilities() ProviderCapabilities     { return m.capabilities }

func (m *mockProvider) Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func (m *mockProvider) Stream(ctx context.Context, req *CompletionRequest) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		for _, event := range m.events {
			if !yield(event, nil) {
				return
			}
		}
	}
}

func TestRegistry_Register(t *testing.T) {
	t.Run("registers new provider", func(t *testing.T) {
		r := NewRegistry()
		p := &mockProvider{name: "test-provider"}

		err := r.Register(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		got, err := r.Get("test-provider")
		if err != nil {
			t.Fatalf("failed to get provider: %v", err)
		}
		if got != p {
			t.Error("got different provider instance")
		}
	})

	t.Run("rejects duplicate registration", func(t *testing.T) {
		r := NewRegistry()
		p1 := &mockProvider{name: "dup-provider"}
		p2 := &mockProvider{name: "dup-provider"}

		if err := r.Register(p1); err != nil {
			t.Fatalf("first registration failed: %v", err)
		}

		err := r.Register(p2)
		if err == nil {
			t.Fatal("expected error for duplicate registration")
		}
	})
}

func TestRegistry_MustRegister(t *testing.T) {
	t.Run("panics on duplicate", func(t *testing.T) {
		r := NewRegistry()
		p1 := &mockProvider{name: "panic-provider"}
		p2 := &mockProvider{name: "panic-provider"}

		r.MustRegister(p1)

		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic for duplicate MustRegister")
			}
		}()
		r.MustRegister(p2)
	})
}

func TestRegistry_Get(t *testing.T) {
	t.Run("returns error for unknown provider", func(t *testing.T) {
		r := NewRegistry()

		_, err := r.Get("nonexistent")
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
	})
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockProvider{name: "charlie"})
	r.Register(&mockProvider{name: "alpha"})
	r.Register(&mockProvider{name: "bravo"})

	names := r.List()

	if len(names) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(names))
	}
	// Should be sorted alphabetically
	if names[0] != "alpha" || names[1] != "bravo" || names[2] != "charlie" {
		t.Errorf("expected sorted list [alpha, bravo, charlie], got %v", names)
	}
}

func TestStreamEvents(t *testing.T) {
	tests := []struct {
		event    StreamEvent
		expected streamEventType
	}{
		{TextEvent{Text: "hello"}, streamEventText},
		{ToolCallEvent{Call: ToolCall{Name: "test"}}, streamEventTool},
		{CommandEvent{Command: "ls"}, streamEventCommand},
		{FileEvent{Path: "/tmp/test"}, streamEventFile},
		{ErrorEvent{Message: "oops"}, streamEventError},
		{DoneEvent{SessionID: "123"}, streamEventDone},
	}

	for _, tt := range tests {
		if got := tt.event.eventType(); got != tt.expected {
			t.Errorf("%T.eventType() = %q, want %q", tt.event, got, tt.expected)
		}
	}
}

func TestErrorEvent_Error(t *testing.T) {
	t.Run("returns wrapped error", func(t *testing.T) {
		underlying := errors.New("underlying error")
		e := ErrorEvent{Message: "message", Err: underlying}

		if got := e.Error(); got != underlying {
			t.Errorf("expected underlying error, got %v", got)
		}
	})

	t.Run("creates error from message", func(t *testing.T) {
		e := ErrorEvent{Message: "something went wrong"}

		err := e.Error()
		if err == nil || err.Error() != "something went wrong" {
			t.Errorf("expected error with message, got %v", err)
		}
	})

	t.Run("returns generic error when empty", func(t *testing.T) {
		e := ErrorEvent{}

		err := e.Error()
		if err == nil || err.Error() != "unknown AI error" {
			t.Errorf("expected generic error, got %v", err)
		}
	})
}

func TestSandboxConstants(t *testing.T) {
	tests := []struct {
		sandbox  Sandbox
		expected string
	}{
		{SandboxReadOnly, "read-only"},
		{SandboxWorkspaceWrite, "workspace-write"},
		{SandboxFullAccess, "full-access"},
	}

	for _, tt := range tests {
		if string(tt.sandbox) != tt.expected {
			t.Errorf("Sandbox %v = %q, want %q", tt.sandbox, string(tt.sandbox), tt.expected)
		}
	}
}

func TestProviderCapabilities(t *testing.T) {
	caps := ProviderCapabilities{
		Streaming:         true,
		ToolUse:           true,
		Vision:            false,
		Agentic:           true,
		SessionResumption: true,
		MaxContextTokens:  128000,
	}

	if !caps.Streaming {
		t.Error("expected Streaming to be true")
	}
	if !caps.ToolUse {
		t.Error("expected ToolUse to be true")
	}
	if caps.Vision {
		t.Error("expected Vision to be false")
	}
	if !caps.Agentic {
		t.Error("expected Agentic to be true")
	}
	if caps.MaxContextTokens != 128000 {
		t.Errorf("expected MaxContextTokens 128000, got %d", caps.MaxContextTokens)
	}
}

func TestFinishReasonConstants(t *testing.T) {
	tests := []struct {
		reason   FinishReason
		expected string
	}{
		{FinishReasonStop, "stop"},
		{FinishReasonLength, "length"},
		{FinishReasonToolCalls, "tool_calls"},
		{FinishReasonError, "error"},
	}

	for _, tt := range tests {
		if string(tt.reason) != tt.expected {
			t.Errorf("FinishReason %v = %q, want %q", tt.reason, string(tt.reason), tt.expected)
		}
	}
}

func TestRoleConstants(t *testing.T) {
	tests := []struct {
		role     Role
		expected string
	}{
		{RoleUser, "user"},
		{RoleAssistant, "assistant"},
		{RoleSystem, "system"},
		{RoleTool, "tool"},
	}

	for _, tt := range tests {
		if string(tt.role) != tt.expected {
			t.Errorf("Role %v = %q, want %q", tt.role, string(tt.role), tt.expected)
		}
	}
}
