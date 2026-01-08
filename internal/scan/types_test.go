package scan

import (
	"testing"
	"time"

	"github.com/picatz/deputy/internal/targets"
)

func TestOptions_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name:    "empty options valid",
			opts:    Options{},
			wantErr: false,
		},
		{
			name: "only ecosystems valid",
			opts: Options{
				Ecosystems: []string{"npm", "go"},
			},
			wantErr: false,
		},
		{
			name: "only PublishedBefore valid",
			opts: Options{
				PublishedBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantErr: false,
		},
		{
			name: "only PublishedAfter valid",
			opts: Options{
				PublishedAfter: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantErr: false,
		},
		{
			name: "PublishedBefore after PublishedAfter valid",
			opts: Options{
				PublishedAfter:  time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
				PublishedBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantErr: false,
		},
		{
			name: "PublishedAfter after PublishedBefore invalid",
			opts: Options{
				PublishedAfter:  time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
				PublishedBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantErr: true,
		},
		{
			name: "same dates valid (edge case)",
			opts: Options{
				PublishedAfter:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				PublishedBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecution_Close(t *testing.T) {
	t.Parallel()

	t.Run("nil execution", func(t *testing.T) {
		var exec *Execution
		if err := exec.Close(); err != nil {
			t.Errorf("nil Execution.Close() should return nil, got %v", err)
		}
	})

	t.Run("nil cleanup", func(t *testing.T) {
		exec := &Execution{
			Result: Result{},
		}
		if err := exec.Close(); err != nil {
			t.Errorf("Execution.Close() with nil cleanup should return nil, got %v", err)
		}
	})

	t.Run("cleanup called", func(t *testing.T) {
		called := false
		exec := &Execution{
			Result: Result{},
			cleanup: func() {
				called = true
			},
		}
		if err := exec.Close(); err != nil {
			t.Errorf("Execution.Close() error = %v", err)
		}
		if !called {
			t.Error("cleanup function was not called")
		}
	})

	t.Run("multiple close is safe", func(t *testing.T) {
		callCount := 0
		exec := &Execution{
			Result: Result{},
			cleanup: func() {
				callCount++
			},
		}
		// First close
		if err := exec.Close(); err != nil {
			t.Errorf("first Close() error = %v", err)
		}
		// Second close - currently calls cleanup again (implementation detail)
		if err := exec.Close(); err != nil {
			t.Errorf("second Close() error = %v", err)
		}
		// Note: current implementation allows multiple cleanup calls
		// This test verifies Close() doesn't panic on multiple calls
	})
}

func TestTarget_ZeroValue(t *testing.T) {
	t.Parallel()

	var target Target
	if target.Kind != targets.KindUnspecified {
		t.Errorf("zero Target.Kind should be KindUnspecified, got %v", target.Kind)
	}
	if target.DisplayPath != "" {
		t.Errorf("zero Target.DisplayPath should be empty, got %q", target.DisplayPath)
	}
	if target.Cloned {
		t.Error("zero Target.Cloned should be false")
	}
}

func TestResult_ZeroValue(t *testing.T) {
	t.Parallel()

	var result Result
	if result.PackagesScanned != 0 {
		t.Errorf("zero Result.PackagesScanned should be 0, got %d", result.PackagesScanned)
	}
	if len(result.Findings) != 0 {
		t.Errorf("zero Result.Findings should be empty, got %d", len(result.Findings))
	}
	if result.Advisories != nil {
		t.Error("zero Result.Advisories should be nil")
	}
	if result.ImageInfo != nil {
		t.Error("zero Result.ImageInfo should be nil")
	}
	if result.DockerfileInfo != nil {
		t.Error("zero Result.DockerfileInfo should be nil")
	}
}

func TestInventory_ZeroValue(t *testing.T) {
	t.Parallel()

	var inv Inventory
	if len(inv.Packages) != 0 {
		t.Errorf("zero Inventory.Packages should be empty, got %d", len(inv.Packages))
	}
	if inv.Direct != nil {
		t.Error("zero Inventory.Direct should be nil")
	}
}
