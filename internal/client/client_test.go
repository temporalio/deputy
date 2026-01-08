package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
)

func TestModeString(t *testing.T) {
	tests := []struct {
		mode Mode
		want string
	}{
		{ModeInProcess, "in-process"},
		{ModeLocalDaemon, "local-daemon"},
		{ModeRemote, "remote"},
		{Mode(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("Mode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestNewInProcess(t *testing.T) {
	c := NewInProcess(nil)
	if c == nil {
		t.Fatal("NewInProcess(nil) returned nil")
	}
	if c.scanner == nil {
		t.Error("NewInProcess(nil) should create default scanner")
	}
	if c.Mode() != ModeInProcess {
		t.Errorf("Mode() = %v, want %v", c.Mode(), ModeInProcess)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestNewDefaultMode(t *testing.T) {
	// Unset DEPUTY_SERVER to ensure we get in-process mode
	os.Unsetenv("DEPUTY_SERVER")

	c, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeInProcess {
		t.Errorf("New() mode = %v, want %v", c.Mode(), ModeInProcess)
	}
}

func TestNewForcedMode(t *testing.T) {
	c, err := New(context.Background(), Options{
		Mode:      ModeInProcess,
		ForceMode: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeInProcess {
		t.Errorf("New() mode = %v, want %v", c.Mode(), ModeInProcess)
	}
}

func TestNewRemoteModeRequiresAddress(t *testing.T) {
	// Unset DEPUTY_SERVER
	os.Unsetenv("DEPUTY_SERVER")

	_, err := New(context.Background(), Options{
		Mode:      ModeRemote,
		ForceMode: true,
	})
	if err == nil {
		t.Fatal("New() should fail for remote mode without address")
	}
}

func TestNewRemoteModeWithAddress(t *testing.T) {
	c, err := New(context.Background(), Options{
		Mode:          ModeRemote,
		ForceMode:     true,
		ServerAddress: "localhost:8090",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeRemote {
		t.Errorf("New() mode = %v, want %v", c.Mode(), ModeRemote)
	}
}

func TestNewRemoteModeFromEnv(t *testing.T) {
	os.Setenv("DEPUTY_SERVER", "localhost:8090")
	defer os.Unsetenv("DEPUTY_SERVER")

	c, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeRemote {
		t.Errorf("New() mode = %v, want %v", c.Mode(), ModeRemote)
	}
}

func TestDefaultDaemonSocket(t *testing.T) {
	socket := defaultDaemonSocket()
	if socket == "" {
		t.Error("defaultDaemonSocket() returned empty string")
	}

	// Verify it contains "deputy"
	if !contains(socket, "deputy") {
		t.Errorf("defaultDaemonSocket() = %q, want to contain 'deputy'", socket)
	}
}

func TestIsDaemonResponsiveNonexistent(t *testing.T) {
	// Test with nonexistent socket
	if isDaemonResponsive("/nonexistent/socket.sock") {
		t.Error("isDaemonResponsive() should return false for nonexistent socket")
	}
}

func TestIsDaemonResponsiveRegularFile(t *testing.T) {
	// Create a regular file, not a socket
	tmp := t.TempDir()
	file := filepath.Join(tmp, "not-a-socket")
	if err := os.WriteFile(file, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	if isDaemonResponsive(file) {
		t.Error("isDaemonResponsive() should return false for regular file")
	}
}

func TestInProcessScanRequiresTarget(t *testing.T) {
	c := NewInProcess(nil)
	defer c.Close()

	req := connect.NewRequest(&scanv1.ScanRequest{
		Target: "", // Empty target
	})

	_, err := c.Scan(context.Background(), req)
	if err == nil {
		t.Fatal("Scan() should fail with empty target")
	}
}

func TestInProcessListPackagesRequiresTarget(t *testing.T) {
	c := NewInProcess(nil)
	defer c.Close()

	req := connect.NewRequest(&listv1.ListPackagesRequest{
		Target: "", // Empty target
	})

	_, err := c.ListPackages(context.Background(), req)
	if err == nil {
		t.Fatal("ListPackages() should fail with empty target")
	}
}

func TestInProcessListEcosystems(t *testing.T) {
	c := NewInProcess(nil)
	defer c.Close()

	req := connect.NewRequest(&listv1.ListEcosystemsRequest{})
	resp, err := c.ListEcosystems(context.Background(), req)
	if err != nil {
		t.Fatalf("ListEcosystems() error = %v", err)
	}

	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("ListEcosystems() returned no ecosystems")
	}

	// Verify Go ecosystem exists
	foundGo := false
	for _, eco := range resp.Msg.Ecosystems {
		if eco.Name == "go" {
			foundGo = true
			if eco.DisplayName != "Go" {
				t.Errorf("Go ecosystem DisplayName = %q, want 'Go'", eco.DisplayName)
			}
			break
		}
	}
	if !foundGo {
		t.Error("ListEcosystems() missing 'go' ecosystem")
	}
}

func TestRemoteMode(t *testing.T) {
	c := NewRemote("localhost:8090", false)
	defer c.Close()

	if c.Mode() != ModeRemote {
		t.Errorf("Mode() = %v, want %v", c.Mode(), ModeRemote)
	}
}

func TestDaemonMode(t *testing.T) {
	c := NewRemote("/tmp/daemon.sock", true)
	defer c.Close()

	if c.Mode() != ModeLocalDaemon {
		t.Errorf("Mode() = %v, want %v", c.Mode(), ModeLocalDaemon)
	}
}

// Test convenience constructors

func TestNewAuto(t *testing.T) {
	// Unset DEPUTY_SERVER to ensure we get in-process mode
	os.Unsetenv("DEPUTY_SERVER")

	c, err := NewAuto(context.Background())
	if err != nil {
		t.Fatalf("NewAuto() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeInProcess {
		t.Errorf("NewAuto() mode = %v, want %v", c.Mode(), ModeInProcess)
	}
}

func TestConnectToServer(t *testing.T) {
	c, err := ConnectToServer(context.Background(), "localhost:8090")
	if err != nil {
		t.Fatalf("ConnectToServer() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeRemote {
		t.Errorf("ConnectToServer() mode = %v, want %v", c.Mode(), ModeRemote)
	}
}

func TestConnectToDaemon(t *testing.T) {
	c, err := ConnectToDaemon(context.Background(), "/tmp/test.sock")
	if err != nil {
		t.Fatalf("ConnectToDaemon() error = %v", err)
	}
	defer c.Close()

	if c.Mode() != ModeLocalDaemon {
		t.Errorf("ConnectToDaemon() mode = %v, want %v", c.Mode(), ModeLocalDaemon)
	}
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
