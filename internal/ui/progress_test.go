package ui

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestProgress_BasicUsage(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Loading")
	p.WithStyle(SimpleProgressStyle())

	ctx := t.Context()

	p.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	p.Done()

	// Non-TTY output should be minimal
	// (our buffer isn't a TTY, so we won't see spinner output)
}

func TestProgress_WithTotal(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Processing").WithTotal(100)

	ctx := t.Context()

	p.Start(ctx)
	p.Update(50)
	time.Sleep(50 * time.Millisecond)
	p.Done()
}

func TestProgress_Increment(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Items")

	ctx := t.Context()

	p.Start(ctx)
	p.Increment(1)
	p.Increment(1)
	p.Increment(1)

	if p.current.Load() != 3 {
		t.Errorf("expected current=3, got %d", p.current.Load())
	}

	p.Done()
}

func TestProgress_SetSubMessage(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Scanning")

	ctx := t.Context()

	p.Start(ctx)
	p.SetSubMessage("package.json")
	time.Sleep(50 * time.Millisecond)
	p.SetSubMessage("go.mod")
	time.Sleep(50 * time.Millisecond)
	p.Done()
}

func TestProgress_Fail(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Operation")

	ctx := t.Context()

	p.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	p.Fail()
}

func TestProgress_StopIdempotent(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Test")

	ctx := t.Context()

	p.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Multiple stops should be safe
	p.Done()
	p.Done()
	p.Fail()
}

func TestProgress_StartIdempotent(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Test")

	ctx := t.Context()

	// Multiple starts should be safe
	p.Start(ctx)
	p.Start(ctx)
	p.Start(ctx)

	time.Sleep(50 * time.Millisecond)
	p.Done()
}

func TestDefaultProgressStyle(t *testing.T) {
	style := DefaultProgressStyle()

	if len(style.Spinner) == 0 {
		t.Error("Spinner should not be empty")
	}
	if style.SpinnerFPS <= 0 {
		t.Error("SpinnerFPS should be positive")
	}
	if style.DoneChar == "" {
		t.Error("DoneChar should not be empty")
	}
	if style.FailChar == "" {
		t.Error("FailChar should not be empty")
	}
}

func TestSimpleProgressStyle(t *testing.T) {
	style := SimpleProgressStyle()

	if len(style.Spinner) == 0 {
		t.Error("Spinner should not be empty")
	}

	// Simple style should only use ASCII
	for _, s := range style.Spinner {
		for _, r := range s {
			if r > 127 {
				t.Errorf("Simple style should use ASCII only, got %q", s)
			}
		}
	}
}

func TestMultiProgress_BasicUsage(t *testing.T) {
	var buf bytes.Buffer
	mp := NewMultiProgress(&buf)

	mp.AddTask("task1", "First task")
	mp.AddTask("task2", "Second task")

	mp.UpdateTask("task1", "in progress")
	mp.CompleteTask("task1", true)

	mp.UpdateTask("task2", "processing")
	mp.CompleteTask("task2", false)

	// Check that output was written (non-TTY mode)
	output := buf.String()
	if !strings.Contains(output, "First task") {
		t.Error("Output should contain task messages")
	}
}

func TestMultiProgress_OrderPreserved(t *testing.T) {
	var buf bytes.Buffer
	mp := NewMultiProgress(&buf)

	mp.AddTask("a", "Task A")
	mp.AddTask("b", "Task B")
	mp.AddTask("c", "Task C")

	if len(mp.order) != 3 {
		t.Errorf("expected 3 tasks, got %d", len(mp.order))
	}
	if mp.order[0] != "a" || mp.order[1] != "b" || mp.order[2] != "c" {
		t.Errorf("order not preserved: %v", mp.order)
	}
}

func TestMultiProgress_DuplicateTaskID(t *testing.T) {
	var buf bytes.Buffer
	mp := NewMultiProgress(&buf)

	mp.AddTask("task", "First message")
	mp.AddTask("task", "Updated message")

	if len(mp.order) != 1 {
		t.Errorf("duplicate task ID should not add to order, got %d tasks", len(mp.order))
	}

	if mp.tasks["task"].message != "Updated message" {
		t.Error("task message should be updated")
	}
}

func TestProgressFunc(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()

	// Test successful function
	result, err := ProgressFunc(ctx, &buf, "Computing", func() (int, error) {
		time.Sleep(10 * time.Millisecond)
		return 42, nil
	})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Errorf("expected 42, got %d", result)
	}
}

func TestProgressFunc_Error(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()

	// Test failing function
	_, err := ProgressFunc(ctx, &buf, "Failing", func() (int, error) {
		return 0, context.DeadlineExceeded
	})

	if err == nil {
		t.Error("expected error")
	}
}

func TestIsTTY(t *testing.T) {
	var buf bytes.Buffer

	// Buffer is not a TTY
	if IsTTY(&buf) {
		t.Error("bytes.Buffer should not be a TTY")
	}
}

func TestProgress_Clear(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Scanning")

	ctx := t.Context()

	p.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Clear should stop without printing final status
	p.Clear()

	// Verify progress is stopped
	if p.running {
		t.Error("progress should not be running after Clear")
	}

	// Non-TTY buffer won't show output, but we verify Clear is idempotent
	p.Clear()
}

func TestProgress_ClearIdempotent(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, "Test")

	ctx := t.Context()

	p.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Multiple clears should be safe
	p.Clear()
	p.Clear()
	p.Clear()
}

func TestFormatStatusHint(t *testing.T) {
	tests := []struct {
		input string
	}{
		{"starting"},
		{"thinking"},
		{"analyzing"},
		{"[starting]"},
		{"[thinking]"},
		{"read go.mod"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := FormatStatusHint(tt.input)
			// Result should contain ANSI escape codes for styling
			if result == "" {
				t.Errorf("FormatStatusHint(%q) returned empty string", tt.input)
			}
			// Result should contain brackets
			if !strings.Contains(result, "[") || !strings.Contains(result, "]") {
				t.Errorf("FormatStatusHint(%q) = %q, should contain brackets", tt.input, result)
			}
		})
	}
}

func TestFormatStatusHint_Brackets(t *testing.T) {
	// With brackets - should extract content
	result := FormatStatusHint("[thinking]")
	if !strings.Contains(result, "thinking") {
		t.Errorf("FormatStatusHint([thinking]) should contain 'thinking', got %q", result)
	}

	// Without brackets - should add them
	result2 := FormatStatusHint("analyzing")
	if !strings.Contains(result2, "analyzing") {
		t.Errorf("FormatStatusHint(analyzing) should contain 'analyzing', got %q", result2)
	}
}
