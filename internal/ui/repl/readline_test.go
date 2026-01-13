package repl

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestReadLine_NonTTY(t *testing.T) {
	input := "first line\nsecond line\nthird line\n"
	in := strings.NewReader(input)
	var out bytes.Buffer

	rl := NewReadLine(in, &out)

	// Should not be detected as TTY
	if rl.isTTY {
		t.Skip("running in TTY environment")
	}

	// Read first line
	line, err := rl.Read(context.Background(), "> ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != "first line" {
		t.Errorf("expected 'first line', got %q", line)
	}

	// Read second line
	line, err = rl.Read(context.Background(), "> ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != "second line" {
		t.Errorf("expected 'second line', got %q", line)
	}

	// Read third line
	line, err = rl.Read(context.Background(), "> ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != "third line" {
		t.Errorf("expected 'third line', got %q", line)
	}
}

func TestReadLine_History(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	// Add history items
	rl.AddHistory("first")
	rl.AddHistory("second")
	rl.AddHistory("third")

	if len(rl.History()) != 3 {
		t.Errorf("expected 3 history items, got %d", len(rl.History()))
	}

	// Check history contents
	history := rl.History()
	if history[0] != "first" || history[1] != "second" || history[2] != "third" {
		t.Errorf("unexpected history: %v", history)
	}
}

func TestReadLine_HistoryNoDuplicates(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	rl.AddHistory("same")
	rl.AddHistory("same")
	rl.AddHistory("same")

	if len(rl.History()) != 1 {
		t.Errorf("expected 1 history item (no dups), got %d", len(rl.History()))
	}
}

func TestReadLine_HistoryIgnoresEmpty(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	rl.AddHistory("")
	rl.AddHistory("   ")
	rl.AddHistory("valid")

	if len(rl.History()) != 1 {
		t.Errorf("expected 1 history item, got %d", len(rl.History()))
	}
	if rl.History()[0] != "valid" {
		t.Errorf("expected 'valid', got %q", rl.History()[0])
	}
}

func TestReadLine_SetHistory(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	existing := []string{"one", "two", "three"}
	rl.SetHistory(existing)

	if len(rl.History()) != 3 {
		t.Errorf("expected 3 history items, got %d", len(rl.History()))
	}
}

func TestUTF8Remaining(t *testing.T) {
	tests := []struct {
		first    byte
		expected int
	}{
		{0x00, 0},   // ASCII
		{0x7F, 0},   // ASCII
		{0xC0, 1},   // 2-byte sequence
		{0xDF, 1},   // 2-byte sequence
		{0xE0, 2},   // 3-byte sequence
		{0xEF, 2},   // 3-byte sequence
		{0xF0, 3},   // 4-byte sequence
		{0xF7, 3},   // 4-byte sequence
	}

	for _, tt := range tests {
		got := utf8Remaining(tt.first)
		if got != tt.expected {
			t.Errorf("utf8Remaining(0x%02X) = %d, want %d", tt.first, got, tt.expected)
		}
	}
}

// Tab completion tests

func TestReadLine_TabCompletion_NoCompleter(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	// No completer set - should not panic
	rl.line = []rune("req")
	rl.cursor = 3
	rl.handleTab() // should be a no-op

	if string(rl.line) != "req" {
		t.Errorf("line should be unchanged, got %q", string(rl.line))
	}
}

func TestReadLine_TabCompletion_EmptyCompletions(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	// Completer that returns empty list
	rl.SetCompleter(func(line string, cursor int) []string {
		return []string{}
	})

	rl.line = []rune("xyz")
	rl.cursor = 3

	// First tab - gets empty completions
	rl.handleTab()
	if string(rl.line) != "xyz" {
		t.Errorf("line should be unchanged, got %q", string(rl.line))
	}

	// Second tab - should not panic (this was the bug)
	rl.handleTab()
	if string(rl.line) != "xyz" {
		t.Errorf("line should still be unchanged, got %q", string(rl.line))
	}

	// Third tab - still should not panic
	rl.handleTab()
	if string(rl.line) != "xyz" {
		t.Errorf("line should still be unchanged, got %q", string(rl.line))
	}
}

func TestReadLine_TabCompletion_NilCompletions(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	// Completer that returns nil
	rl.SetCompleter(func(line string, cursor int) []string {
		return nil
	})

	rl.line = []rune("xyz")
	rl.cursor = 3

	// Should not panic on nil return
	rl.handleTab()
	rl.handleTab()
	rl.handleTab()

	if string(rl.line) != "xyz" {
		t.Errorf("line should be unchanged, got %q", string(rl.line))
	}
}

func TestReadLine_TabCompletion_SingleCompletion(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	rl.SetCompleter(func(line string, cursor int) []string {
		return []string{"request"}
	})

	rl.line = []rune("req")
	rl.cursor = 3

	rl.handleTab()
	if string(rl.line) != "request" {
		t.Errorf("expected 'request', got %q", string(rl.line))
	}
	if rl.cursor != 7 {
		t.Errorf("cursor should be at end (7), got %d", rl.cursor)
	}

	// Tab again - should stay on same completion (only one)
	rl.handleTab()
	if string(rl.line) != "request" {
		t.Errorf("expected 'request', got %q", string(rl.line))
	}
}

func TestReadLine_TabCompletion_CycleThroughMultiple(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	rl.SetCompleter(func(line string, cursor int) []string {
		return []string{"apple", "apricot", "avocado"}
	})

	rl.line = []rune("a")
	rl.cursor = 1

	// First tab - first completion
	rl.handleTab()
	if string(rl.line) != "apple" {
		t.Errorf("expected 'apple', got %q", string(rl.line))
	}

	// Second tab - next completion
	rl.handleTab()
	if string(rl.line) != "apricot" {
		t.Errorf("expected 'apricot', got %q", string(rl.line))
	}

	// Third tab - next completion
	rl.handleTab()
	if string(rl.line) != "avocado" {
		t.Errorf("expected 'avocado', got %q", string(rl.line))
	}

	// Fourth tab - wraps around to first
	rl.handleTab()
	if string(rl.line) != "apple" {
		t.Errorf("expected 'apple' (wrap around), got %q", string(rl.line))
	}
}

func TestReadLine_TabCompletion_ResetOnInput(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	callCount := 0
	rl.SetCompleter(func(line string, cursor int) []string {
		callCount++
		return []string{"completion1", "completion2"}
	})

	rl.line = []rune("test")
	rl.cursor = 4

	// First tab
	rl.handleTab()
	if callCount != 1 {
		t.Errorf("completer should be called once, got %d", callCount)
	}

	// Second tab - should NOT call completer again (cycling)
	rl.handleTab()
	if callCount != 1 {
		t.Errorf("completer should still be 1, got %d", callCount)
	}

	// Type a character - resets completion state
	rl.insertChar('x')
	rl.resetCompletion()

	// Tab again - should call completer again
	rl.handleTab()
	if callCount != 2 {
		t.Errorf("completer should be called again, got %d", callCount)
	}
}

func TestReadLine_TabCompletion_CursorPosition(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	rl.SetCompleter(func(line string, cursor int) []string {
		// Return completion based on cursor position
		if cursor == 3 {
			return []string{"request.field"}
		}
		return nil
	})

	rl.line = []rune("req")
	rl.cursor = 3

	rl.handleTab()
	if string(rl.line) != "request.field" {
		t.Errorf("expected 'request.field', got %q", string(rl.line))
	}
	if rl.cursor != 13 {
		t.Errorf("cursor should be at end (13), got %d", rl.cursor)
	}
}

func TestReadLine_ResetCompletion(t *testing.T) {
	var out bytes.Buffer
	rl := NewReadLine(strings.NewReader(""), &out)

	rl.completions = []string{"a", "b", "c"}
	rl.compIdx = 2
	rl.compOriginal = "original"

	rl.resetCompletion()

	if rl.completions != nil {
		t.Error("completions should be nil after reset")
	}
	if rl.compIdx != 0 {
		t.Error("compIdx should be 0 after reset")
	}
	if rl.compOriginal != "" {
		t.Error("compOriginal should be empty after reset")
	}
}

// Fuzz test for tab completion
func FuzzReadLine_HandleTab(f *testing.F) {
	// Seed corpus
	f.Add("", 0, 0)
	f.Add("request", 7, 3)
	f.Add("request.ecosystem", 17, 5)
	f.Add("a", 1, 10)
	f.Add("test", 0, 0)

	f.Fuzz(func(t *testing.T, line string, cursor int, numCompletions int) {
		var out bytes.Buffer
		rl := NewReadLine(strings.NewReader(""), &out)

		// Clamp values to reasonable ranges
		if cursor < 0 {
			cursor = 0
		}
		if cursor > len(line) {
			cursor = len(line)
		}
		if numCompletions < 0 {
			numCompletions = 0
		}
		if numCompletions > 100 {
			numCompletions = 100
		}

		// Create completions slice
		completions := make([]string, numCompletions)
		for i := range completions {
			completions[i] = line + string(rune('a'+i%26))
		}

		rl.SetCompleter(func(l string, c int) []string {
			return completions
		})

		rl.line = []rune(line)
		rl.cursor = cursor

		// Should never panic regardless of input
		for i := 0; i < 10; i++ {
			rl.handleTab()
		}

		// Reset and try again
		rl.resetCompletion()
		for i := 0; i < 5; i++ {
			rl.handleTab()
		}
	})
}

// Test edge cases that could cause panics
func TestReadLine_TabCompletion_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		cursor      int
		completions []string
	}{
		{"empty line", "", 0, []string{"a"}},
		{"empty line no completions", "", 0, []string{}},
		{"empty line nil completions", "", 0, nil},
		{"cursor at start", "test", 0, []string{"abc"}},
		{"cursor past end", "test", 100, []string{"abc"}},
		{"negative cursor", "test", -1, []string{"abc"}},
		{"unicode line", "日本語", 3, []string{"日本語テスト"}},
		{"very long completion", "a", 1, []string{strings.Repeat("x", 10000)}},
		{"many completions", "a", 1, make([]string, 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			rl := NewReadLine(strings.NewReader(""), &out)

			rl.SetCompleter(func(line string, cursor int) []string {
				return tt.completions
			})

			// Clamp cursor to valid range
			cursor := tt.cursor
			if cursor < 0 {
				cursor = 0
			}
			if cursor > len(tt.line) {
				cursor = len(tt.line)
			}

			rl.line = []rune(tt.line)
			rl.cursor = cursor

			// Should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("handleTab panicked: %v", r)
				}
			}()

			for i := 0; i < 5; i++ {
				rl.handleTab()
			}
		})
	}
}
