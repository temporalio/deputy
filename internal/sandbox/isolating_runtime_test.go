package sandbox

import (
	"context"
	"iter"
	"testing"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
)

func TestShouldWrapWithIsolation(t *testing.T) {
	tests := []struct {
		name     string
		runtime  sandboxv1.Runtime
		expected bool
	}{
		// Container runtimes handle isolation internally
		{
			name:     "docker should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_DOCKER,
			expected: false,
		},
		{
			name:     "podman should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_PODMAN,
			expected: false,
		},
		{
			name:     "containerd should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_CONTAINERD,
			expected: false,
		},
		{
			name:     "gvisor should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_GVISOR,
			expected: false,
		},
		{
			name:     "firecracker should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_FIRECRACKER,
			expected: false,
		},
		{
			name:     "apple container should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_APPLE_CONTAINER,
			expected: false,
		},
		{
			name:     "plugin should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_PLUGIN,
			expected: false,
		},
		// Host-native runtimes need the wrapper
		{
			name:     "sandbox-exec should wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC,
			expected: true,
		},
		{
			name:     "bwrap should wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_BWRAP,
			expected: true,
		},
		{
			name:     "namespaces should wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_NAMESPACES,
			expected: true,
		},
		{
			name:     "landlock should wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_LANDLOCK,
			expected: true,
		},
		{
			name:     "none runtime should wrap for review workflow",
			runtime:  sandboxv1.Runtime_RUNTIME_NONE,
			expected: true,
		},
		// Unknown/unspecified - safer to not wrap
		{
			name:     "unspecified should not wrap",
			runtime:  sandboxv1.Runtime_RUNTIME_UNSPECIFIED,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldWrapWithIsolation(tt.runtime)
			if got != tt.expected {
				t.Errorf("ShouldWrapWithIsolation(%v) = %v, want %v", tt.runtime, got, tt.expected)
			}
		})
	}
}

func TestNewIsolatingRuntime_ReturnsNilForDirectMode(t *testing.T) {
	// Direct mode should return nil (no wrapping needed)
	wrapper, err := NewIsolatingRuntime(nil, IsolatingRuntimeConfig{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT,
		OriginalPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrapper != nil {
		t.Error("expected nil wrapper for direct mode")
	}
}

func TestNewIsolatingRuntime_ReturnsNilForUnspecifiedMode(t *testing.T) {
	// Unspecified mode should return nil (no wrapping needed)
	wrapper, err := NewIsolatingRuntime(nil, IsolatingRuntimeConfig{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_UNSPECIFIED,
		OriginalPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrapper != nil {
		t.Error("expected nil wrapper for unspecified mode")
	}
}

func TestNewIsolatingRuntime_RequiresInnerRuntime(t *testing.T) {
	// Snapshot mode without inner runtime should fail
	_, err := NewIsolatingRuntime(nil, IsolatingRuntimeConfig{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: "/tmp/test",
	})
	if err == nil {
		t.Error("expected error when inner runtime is nil")
	}
}

func TestNewIsolatingRuntime_RequiresOriginalPath(t *testing.T) {
	// Create a mock runtime for testing
	mockRuntime := &mockRuntime{}

	// Snapshot mode without original path should fail
	_, err := NewIsolatingRuntime(mockRuntime, IsolatingRuntimeConfig{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: "",
	})
	if err == nil {
		t.Error("expected error when original path is empty")
	}
}

// mockRuntime is a minimal mock for testing
type mockRuntime struct{}

func (m *mockRuntime) Name() sandboxv1.Runtime {
	return sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC
}

func (m *mockRuntime) Info(_ context.Context) (*sandboxv1.RuntimeInfo, error) {
	return &sandboxv1.RuntimeInfo{Runtime: sandboxv1.Runtime_RUNTIME_SANDBOX_EXEC}, nil
}

func (m *mockRuntime) Available(_ context.Context) bool {
	return true
}

func (m *mockRuntime) Version(_ context.Context) string {
	return "test"
}

func (m *mockRuntime) Capabilities() *sandboxv1.RuntimeCapabilities {
	return &sandboxv1.RuntimeCapabilities{}
}

func (m *mockRuntime) Execute(_ context.Context, _ *sandboxv1.ExecuteRequest) iter.Seq2[*sandboxv1.ExecuteEvent, error] {
	return func(yield func(*sandboxv1.ExecuteEvent, error) bool) {}
}

func (m *mockRuntime) Cleanup(_ context.Context, _ string) error {
	return nil
}
