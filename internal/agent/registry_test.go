package agent

import (
	"context"
	"iter"
	"testing"

	"connectrpc.com/connect"
	agentv1 "github.com/picatz/deputy/gen/deputy/agent/v1"
	"github.com/picatz/deputy/gen/deputy/agent/v1/agentv1connect"
)

// mockHandler is a simple test handler implementing AgentPluginHandler.
type mockHandler struct {
	agentv1connect.UnimplementedAgentPluginHandler
	name string
}

func newMockHandler(name string) *mockHandler {
	return &mockHandler{name: name}
}

func (h *mockHandler) GetInfo(ctx context.Context, req *connect.Request[agentv1.GetInfoRequest]) (*connect.Response[agentv1.GetInfoResponse], error) {
	return connect.NewResponse(&agentv1.GetInfoResponse{
		Name:        h.name,
		DisplayName: h.name,
		Description: "Test handler",
		Version:     "1.0.0",
		Capabilities: &agentv1.AgentCapabilities{
			Streaming: true,
			Agentic:   true,
		},
	}), nil
}

func (h *mockHandler) Execute(ctx context.Context, req *connect.Request[agentv1.ExecuteRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	return stream.Send(&agentv1.ExecuteEvent{
		SessionId: "test-session",
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
	})
}

func (h *mockHandler) Resume(ctx context.Context, req *connect.Request[agentv1.ResumeRequest], stream *connect.ServerStream[agentv1.ExecuteEvent]) error {
	return stream.Send(&agentv1.ExecuteEvent{
		SessionId: req.Msg.GetSessionId(),
		Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
	})
}

func (h *mockHandler) Approve(ctx context.Context, req *connect.Request[agentv1.ApproveRequest]) (*connect.Response[agentv1.ApproveResponse], error) {
	return connect.NewResponse(&agentv1.ApproveResponse{Accepted: true}), nil
}

func (h *mockHandler) Cancel(ctx context.Context, req *connect.Request[agentv1.CancelRequest]) (*connect.Response[agentv1.CancelResponse], error) {
	return connect.NewResponse(&agentv1.CancelResponse{Cancelled: true}), nil
}

// Implement Executor interface for testing
func (h *mockHandler) ExecuteIter(ctx context.Context, req *agentv1.ExecuteRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	return func(yield func(*agentv1.ExecuteEvent, error) bool) {
		yield(&agentv1.ExecuteEvent{
			SessionId: "test-session",
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		}, nil)
	}
}

func (h *mockHandler) ResumeIter(ctx context.Context, req *agentv1.ResumeRequest) iter.Seq2[*agentv1.ExecuteEvent, error] {
	return func(yield func(*agentv1.ExecuteEvent, error) bool) {
		yield(&agentv1.ExecuteEvent{
			SessionId: req.GetSessionId(),
			Phase:     agentv1.ExecutionPhase_EXECUTION_PHASE_COMPLETED,
		}, nil)
	}
}

// Verify mockHandler implements both interfaces
var _ agentv1connect.AgentPluginHandler = (*mockHandler)(nil)
var _ Executor = (*mockHandler)(nil)

func TestRegistry(t *testing.T) {
	t.Run("register and get", func(t *testing.T) {
		reg := NewRegistry()
		handler := newMockHandler("test-handler")

		if err := reg.RegisterBuiltin("test-handler", handler); err != nil {
			t.Fatalf("failed to register handler: %v", err)
		}

		got, err := reg.Get("test-handler")
		if err != nil {
			t.Fatalf("failed to get handler: %v", err)
		}

		// Verify by calling GetInfo
		ctx := context.Background()
		info, err := got.GetInfo(ctx, connect.NewRequest(&agentv1.GetInfoRequest{}))
		if err != nil {
			t.Fatalf("GetInfo failed: %v", err)
		}
		if info.Msg.GetName() != "test-handler" {
			t.Errorf("got name %q, want %q", info.Msg.GetName(), "test-handler")
		}
	})

	t.Run("duplicate registration fails", func(t *testing.T) {
		reg := NewRegistry()
		handler := newMockHandler("dup-handler")

		if err := reg.RegisterBuiltin("dup-handler", handler); err != nil {
			t.Fatalf("first registration failed: %v", err)
		}

		if err := reg.RegisterBuiltin("dup-handler", handler); err == nil {
			t.Error("expected error for duplicate registration, got nil")
		}
	})

	t.Run("get unknown handler fails", func(t *testing.T) {
		reg := NewRegistry()

		_, err := reg.Get("unknown")
		if err == nil {
			t.Error("expected error for unknown handler, got nil")
		}
	})

	t.Run("list returns sorted names", func(t *testing.T) {
		reg := NewRegistry()
		_ = reg.RegisterBuiltin("charlie", newMockHandler("charlie"))
		_ = reg.RegisterBuiltin("alpha", newMockHandler("alpha"))
		_ = reg.RegisterBuiltin("bravo", newMockHandler("bravo"))

		names := reg.List()
		if len(names) != 3 {
			t.Fatalf("got %d names, want 3", len(names))
		}
		if names[0] != "alpha" || names[1] != "bravo" || names[2] != "charlie" {
			t.Errorf("names not sorted: %v", names)
		}
	})

	t.Run("unregister removes handler", func(t *testing.T) {
		reg := NewRegistry()
		_ = reg.RegisterBuiltin("to-remove", newMockHandler("to-remove"))

		if err := reg.Unregister("to-remove"); err != nil {
			t.Fatalf("unregister failed: %v", err)
		}

		if _, err := reg.Get("to-remove"); err == nil {
			t.Error("handler should not exist after unregister")
		}
	})

	t.Run("close closes all handlers", func(t *testing.T) {
		reg := NewRegistry()
		_ = reg.RegisterBuiltin("h1", newMockHandler("h1"))
		_ = reg.RegisterBuiltin("h2", newMockHandler("h2"))

		if err := reg.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		if len(reg.List()) != 0 {
			t.Error("registry should be empty after close")
		}
	})

	t.Run("entries returns all entries", func(t *testing.T) {
		reg := NewRegistry()
		_ = reg.RegisterBuiltin("handler1", newMockHandler("handler1"))
		_ = reg.RegisterBuiltin("handler2", newMockHandler("handler2"))

		entries := reg.Entries()
		if len(entries) != 2 {
			t.Fatalf("got %d entries, want 2", len(entries))
		}
	})
}

func TestAsExecutor(t *testing.T) {
	t.Run("returns executor for implementing handler", func(t *testing.T) {
		handler := newMockHandler("test")
		exec := AsExecutor(handler)
		if exec == nil {
			t.Fatal("expected executor, got nil")
		}

		// Test ExecuteIter
		ctx := context.Background()
		req := &agentv1.ExecuteRequest{Prompt: "test"}
		var count int
		for event, err := range exec.ExecuteIter(ctx, req) {
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if event == nil {
				t.Fatal("expected event, got nil")
			}
			count++
		}
		if count != 1 {
			t.Errorf("got %d events, want 1", count)
		}
	})

	t.Run("returns nil for non-implementing handler", func(t *testing.T) {
		// Create a handler that only implements AgentPluginHandler, not Executor
		handler := &agentv1connect.UnimplementedAgentPluginHandler{}
		exec := AsExecutor(handler)
		if exec != nil {
			t.Error("expected nil for non-implementing handler")
		}
	})
}

func TestPluginPrefix(t *testing.T) {
	if PluginPrefix != "deputy-plugin-" {
		t.Errorf("PluginPrefix = %q, want %q", PluginPrefix, "deputy-plugin-")
	}
}

func TestListAvailable(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterBuiltin("builtin1", newMockHandler("builtin1"))
	_ = reg.RegisterBuiltin("builtin2", newMockHandler("builtin2"))

	available := reg.ListAvailable()
	if len(available) < 2 {
		t.Errorf("ListAvailable returned %d items, expected at least 2", len(available))
	}

	// Check that builtins are included
	found := make(map[string]bool)
	for _, name := range available {
		found[name] = true
	}
	if !found["builtin1"] || !found["builtin2"] {
		t.Errorf("ListAvailable missing builtins: %v", available)
	}
}

func TestGetOrDiscover(t *testing.T) {
	t.Run("returns registered handler", func(t *testing.T) {
		reg := NewRegistry()
		handler := newMockHandler("registered")
		_ = reg.RegisterBuiltin("registered", handler)

		ctx := context.Background()
		got, err := reg.GetOrDiscover(ctx, "registered")
		if err != nil {
			t.Fatalf("GetOrDiscover failed: %v", err)
		}
		if got == nil {
			t.Fatal("expected handler, got nil")
		}
	})

	t.Run("returns error for unknown plugin not in PATH", func(t *testing.T) {
		reg := NewRegistry()
		ctx := context.Background()

		_, err := reg.GetOrDiscover(ctx, "nonexistent-plugin-xyz")
		if err == nil {
			t.Error("expected error for non-existent plugin")
		}
	})
}

func TestFindPluginInPath(t *testing.T) {
	// Test that looking for a non-existent plugin returns empty string
	result := FindPluginInPath("definitely-not-a-real-plugin-xyz123")
	if result != "" {
		t.Errorf("FindPluginInPath returned %q for non-existent plugin, expected empty", result)
	}
}
