package sdk

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	ctx := t.Context()
	client, err := NewClient(ctx)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	// Should default to in-process mode
	if client.Mode() != ModeInProcess {
		t.Errorf("expected ModeInProcess, got %v", client.Mode())
	}
}

func TestNewClientWithOptions(t *testing.T) {
	ctx := t.Context()

	t.Run("force in-process mode", func(t *testing.T) {
		client, err := NewClientWithOptions(ctx, Options{
			Mode:      ModeInProcess,
			ForceMode: true,
		})
		if err != nil {
			t.Fatalf("NewClientWithOptions failed: %v", err)
		}
		defer client.Close()

		if client.Mode() != ModeInProcess {
			t.Errorf("expected ModeInProcess, got %v", client.Mode())
		}
	})
}

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
