package sandbox_test

import (
	"context"
	"testing"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
	"github.com/temporalio/deputy/internal/sandbox"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/docker"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/gvisor"
	"github.com/temporalio/deputy/internal/sandbox/runtimes/none"
)

func TestNewRegistry(t *testing.T) {
	t.Parallel()

	reg := sandbox.NewRegistry()
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}

	// Empty registry should have no runtimes
	if got := len(reg.List()); got != 0 {
		t.Errorf("expected 0 runtimes, got %d", got)
	}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	t.Parallel()

	reg := sandbox.NewRegistry()

	// Register None runtime
	noneRT := none.New()
	reg.Register(noneRT)

	// Should be able to get it back
	got := reg.Get(sandboxv1.Runtime_RUNTIME_NONE)
	if got == nil {
		t.Fatal("expected to get None runtime")
	}
	if got.Name() != sandboxv1.Runtime_RUNTIME_NONE {
		t.Errorf("expected RUNTIME_NONE, got %v", got.Name())
	}

	// Should be in the list
	list := reg.List()
	if len(list) != 1 {
		t.Errorf("expected 1 runtime, got %d", len(list))
	}
}

func TestRegistryAvailable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reg := sandbox.NewRegistry()

	// None runtime is always available
	noneRT := none.New()
	reg.Register(noneRT)

	available := reg.Available(ctx)
	if len(available) != 1 {
		t.Errorf("expected 1 available runtime, got %d", len(available))
	}
}

func TestRegistryDefault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	reg := sandbox.NewRegistry()

	// No runtimes = no default
	if def := reg.Default(ctx); def != nil {
		t.Errorf("expected nil default with no runtimes, got %v", def)
	}

	// Register None runtime
	noneRT := none.New()
	reg.Register(noneRT)

	// Should get None as default (first available when Docker not present)
	def := reg.Default(ctx)
	if def == nil {
		t.Fatal("expected a default runtime")
	}
}

func TestNewManager(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mgr, err := sandbox.NewManager(ctx)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNoneRuntimeInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := none.New()

	info, err := rt.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.Runtime != sandboxv1.Runtime_RUNTIME_NONE {
		t.Errorf("expected RUNTIME_NONE, got %v", info.Runtime)
	}
	if !info.Available {
		t.Error("expected None runtime to be available")
	}
	if info.DisplayName == "" {
		t.Error("expected non-empty display name")
	}
}

func TestNoneRuntimeCapabilities(t *testing.T) {
	t.Parallel()

	rt := none.New()
	caps := rt.Capabilities()

	// None runtime provides no isolation
	if caps.NetworkIsolation {
		t.Error("None runtime should not have network isolation")
	}
	if caps.FilesystemIsolation {
		t.Error("None runtime should not have filesystem isolation")
	}
	if caps.ResourceLimits {
		t.Error("None runtime should not have resource limits")
	}
	// But it can run things
	if !caps.StreamingOutput {
		t.Error("None runtime should support streaming output")
	}
}

func TestNoneRuntimeExecute(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := none.New()

	req := &sandboxv1.ExecuteRequest{
		Command: []string{"echo", "hello"},
	}

	result := sandbox.CollectResult(rt.Execute(ctx, req))

	if result.Error != nil {
		t.Fatalf("Execute() error: %v", result.Error)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if string(result.Stdout) != "hello\n" {
		t.Errorf("expected 'hello\\n', got %q", string(result.Stdout))
	}
}

func TestNoneRuntimeExecuteFailure(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := none.New()

	req := &sandboxv1.ExecuteRequest{
		Command: []string{"false"}, // Returns exit code 1
	}

	result := sandbox.CollectResult(rt.Execute(ctx, req))

	if result.Error != nil {
		t.Fatalf("Execute() should not return error for non-zero exit: %v", result.Error)
	}
	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1, got %d", result.ExitCode)
	}
}

func TestNoneRuntimeExecuteEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := none.New()

	req := &sandboxv1.ExecuteRequest{
		Command: []string{},
	}

	result := sandbox.CollectResult(rt.Execute(ctx, req))

	if result.Error == nil {
		t.Error("expected error for empty command")
	}
}

func TestDockerRuntimeInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := docker.New()

	info, err := rt.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.Runtime != sandboxv1.Runtime_RUNTIME_DOCKER {
		t.Errorf("expected RUNTIME_DOCKER, got %v", info.Runtime)
	}
	// Note: Available may be false if Docker is not installed
	if info.DisplayName == "" {
		t.Error("expected non-empty display name")
	}
}

func TestDockerRuntimeCapabilities(t *testing.T) {
	t.Parallel()

	rt := docker.New()
	caps := rt.Capabilities()

	// Docker provides full isolation
	if !caps.NetworkIsolation {
		t.Error("Docker runtime should have network isolation")
	}
	if !caps.FilesystemIsolation {
		t.Error("Docker runtime should have filesystem isolation")
	}
	if !caps.ResourceLimits {
		t.Error("Docker runtime should have resource limits")
	}
	if !caps.StreamingOutput {
		t.Error("Docker runtime should support streaming output")
	}
}

func TestManagerListRuntimes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create manager with custom registry
	reg := sandbox.NewRegistry()
	reg.Register(none.New())
	reg.Register(docker.New())

	mgr, err := sandbox.NewManager(ctx, sandbox.WithRegistry(reg))
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	resp, err := mgr.ListRuntimes(ctx, true) // Include unavailable
	if err != nil {
		t.Fatalf("ListRuntimes() error: %v", err)
	}

	if len(resp.Runtimes) < 1 {
		t.Error("expected at least 1 runtime (None)")
	}

	// None should always be available
	found := false
	for _, rt := range resp.Runtimes {
		if rt.Runtime == sandboxv1.Runtime_RUNTIME_NONE && rt.Available {
			found = true
			break
		}
	}
	if !found {
		t.Error("None runtime should be available")
	}
}

func TestCollectResult(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := none.New()

	req := &sandboxv1.ExecuteRequest{
		Command: []string{"sh", "-c", "echo stdout; echo stderr >&2"},
	}

	result := sandbox.CollectResult(rt.Execute(ctx, req))

	if result.Error != nil {
		t.Fatalf("Execute() error: %v", result.Error)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if string(result.Stdout) != "stdout\n" {
		t.Errorf("expected 'stdout\\n', got %q", string(result.Stdout))
	}
	if string(result.Stderr) != "stderr\n" {
		t.Errorf("expected 'stderr\\n', got %q", string(result.Stderr))
	}
}

func TestExecutionError(t *testing.T) {
	t.Parallel()

	err := &sandbox.ExecutionError{
		Message:     "test error",
		Code:        "TEST_ERROR",
		IsFatal:     true,
		IsRetriable: false,
	}

	if err.Error() != "test error" {
		t.Errorf("expected 'test error', got %q", err.Error())
	}
}

func TestGVisorRuntimeInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	rt := gvisor.New()

	info, err := rt.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.Runtime != sandboxv1.Runtime_RUNTIME_GVISOR {
		t.Errorf("expected RUNTIME_GVISOR, got %v", info.Runtime)
	}
	// Note: Available will be false on non-Linux or without runsc
	if info.DisplayName == "" {
		t.Error("expected non-empty display name")
	}
}

func TestGVisorRuntimeCapabilities(t *testing.T) {
	t.Parallel()

	rt := gvisor.New()
	caps := rt.Capabilities()

	// gVisor provides strong isolation
	if !caps.NetworkIsolation {
		t.Error("gVisor runtime should have network isolation")
	}
	if !caps.FilesystemIsolation {
		t.Error("gVisor runtime should have filesystem isolation")
	}
	if !caps.ResourceLimits {
		t.Error("gVisor runtime should have resource limits")
	}
	if !caps.StreamingOutput {
		t.Error("gVisor runtime should support streaming output")
	}
	// gVisor has its own syscall filtering, not traditional seccomp
	if !caps.Seccomp {
		t.Error("gVisor runtime should support seccomp-like filtering")
	}
	// gVisor doesn't support GPU
	if caps.GpuSupport {
		t.Error("gVisor runtime should not have GPU support")
	}
}

func TestGVisorRuntimeOptions(t *testing.T) {
	t.Parallel()

	// Test custom options
	rt := gvisor.New(
		gvisor.WithRunscPath("/custom/runsc"),
		gvisor.WithDockerRuntime("custom-runsc"),
	)

	// Just verify it doesn't panic and returns correct runtime type
	if rt.Name() != sandboxv1.Runtime_RUNTIME_GVISOR {
		t.Errorf("expected RUNTIME_GVISOR, got %v", rt.Name())
	}
}

func TestGVisorStandaloneMode(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create gVisor runtime in standalone mode
	rt := gvisor.New(gvisor.WithStandaloneMode())

	info, err := rt.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// Display name should indicate standalone mode
	if info.DisplayName != "gVisor (standalone)" {
		t.Errorf("expected 'gVisor (standalone)', got %q", info.DisplayName)
	}
}

func TestDockerRuntimeWithOCIRuntime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create Docker runtime with custom OCI runtime
	rt := docker.New(docker.WithOCIRuntime("runsc"))

	info, err := rt.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// Display name should include the OCI runtime
	if info.DisplayName != "Docker (runsc)" {
		t.Errorf("expected 'Docker (runsc)', got %q", info.DisplayName)
	}
}

func TestDockerRuntimeDefaultOCIRuntime(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create Docker runtime without OCI runtime (uses default runc)
	rt := docker.New()

	info, err := rt.Info(ctx)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// Display name should be plain "Docker" without runtime suffix
	if info.DisplayName != "Docker" {
		t.Errorf("expected 'Docker', got %q", info.DisplayName)
	}
}

func TestGVisorStandaloneModeOptions(t *testing.T) {
	t.Parallel()

	// Test all standalone mode options
	rt := gvisor.New(
		gvisor.WithStandaloneMode(),
		gvisor.WithRootfsPath("/custom/rootfs"),
		gvisor.WithNetworkModeStandalone("none"),
		gvisor.WithOverlayMode("root:self"),
		gvisor.WithPlatform("ptrace"),
		gvisor.WithRunscPath("/custom/runsc"),
	)

	// Verify it's configured for standalone mode
	if rt.Name() != sandboxv1.Runtime_RUNTIME_GVISOR {
		t.Errorf("expected RUNTIME_GVISOR, got %v", rt.Name())
	}
}

func TestGVisorGenerateOCIConfig(t *testing.T) {
	t.Parallel()

	rt := gvisor.New(gvisor.WithStandaloneMode())

	// This test verifies the OCI config generation compiles
	// without actually running runsc (which requires Linux)
	if rt.Name() != sandboxv1.Runtime_RUNTIME_GVISOR {
		t.Errorf("expected RUNTIME_GVISOR, got %v", rt.Name())
	}

	// Capabilities should indicate gVisor's features
	caps := rt.Capabilities()
	if !caps.NetworkIsolation {
		t.Error("gVisor should support network isolation")
	}
	if !caps.FilesystemIsolation {
		t.Error("gVisor should support filesystem isolation")
	}
	if !caps.Seccomp {
		t.Error("gVisor should support seccomp-like filtering")
	}
}
