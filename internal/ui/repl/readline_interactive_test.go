package repl

import (
	"bytes"
	"testing"
)

// TestReadLine_InsertChar tests basic character insertion.
func TestReadLine_InsertChar(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:  &out,
		line: []rune{},
	}

	// Type "hello"
	rl.insertChar('h')
	rl.insertChar('e')
	rl.insertChar('l')
	rl.insertChar('l')
	rl.insertChar('o')

	if string(rl.line) != "hello" {
		t.Errorf("expected 'hello', got %q", string(rl.line))
	}
	if rl.cursor != 5 {
		t.Errorf("expected cursor at 5, got %d", rl.cursor)
	}
}

// TestReadLine_InsertInMiddle tests inserting characters in the middle of text.
func TestReadLine_InsertInMiddle(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("hllo"),
		cursor: 1, // cursor after 'h'
	}

	// Insert 'e' after 'h'
	rl.insertChar('e')

	if string(rl.line) != "hello" {
		t.Errorf("expected 'hello', got %q", string(rl.line))
	}
	if rl.cursor != 2 {
		t.Errorf("expected cursor at 2, got %d", rl.cursor)
	}
}

// TestReadLine_Backspace tests backspace behavior.
func TestReadLine_Backspace(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("hello"),
		cursor: 5,
	}

	// Backspace once
	rl.backspace()

	if string(rl.line) != "hell" {
		t.Errorf("expected 'hell', got %q", string(rl.line))
	}
	if rl.cursor != 4 {
		t.Errorf("expected cursor at 4, got %d", rl.cursor)
	}

	// Backspace at beginning should do nothing
	rl.cursor = 0
	rl.backspace()
	if string(rl.line) != "hell" {
		t.Errorf("backspace at start should not change line, got %q", string(rl.line))
	}
}

// TestReadLine_BackspaceInMiddle tests backspace in the middle of text.
func TestReadLine_BackspaceInMiddle(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("heello"),
		cursor: 3, // cursor after "hee"
	}

	// Backspace should delete the extra 'e'
	rl.backspace()

	if string(rl.line) != "hello" {
		t.Errorf("expected 'hello', got %q", string(rl.line))
	}
	if rl.cursor != 2 {
		t.Errorf("expected cursor at 2, got %d", rl.cursor)
	}
}

// TestReadLine_DeleteChar tests delete key behavior.
func TestReadLine_DeleteChar(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("heello"),
		cursor: 2, // cursor after "he", before extra 'e'
	}

	// Delete should remove character at cursor
	rl.deleteChar()

	if string(rl.line) != "hello" {
		t.Errorf("expected 'hello', got %q", string(rl.line))
	}
	if rl.cursor != 2 {
		t.Errorf("cursor should stay at 2, got %d", rl.cursor)
	}

	// Delete at end should do nothing
	rl.cursor = len(rl.line)
	rl.deleteChar()
	if string(rl.line) != "hello" {
		t.Errorf("delete at end should not change line, got %q", string(rl.line))
	}
}

// TestReadLine_CursorMovement tests arrow key cursor movement.
func TestReadLine_CursorMovement(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("hello"),
		cursor: 2,
	}

	// Move right
	rl.cursorRight()
	if rl.cursor != 3 {
		t.Errorf("expected cursor at 3 after right, got %d", rl.cursor)
	}

	// Move left
	rl.cursorLeft()
	if rl.cursor != 2 {
		t.Errorf("expected cursor at 2 after left, got %d", rl.cursor)
	}

	// Move to end
	rl.cursorEnd()
	if rl.cursor != 5 {
		t.Errorf("expected cursor at 5 (end), got %d", rl.cursor)
	}

	// Right at end should do nothing
	rl.cursorRight()
	if rl.cursor != 5 {
		t.Errorf("cursor should stay at end, got %d", rl.cursor)
	}

	// Move to home
	rl.cursorHome()
	if rl.cursor != 0 {
		t.Errorf("expected cursor at 0 (home), got %d", rl.cursor)
	}

	// Left at home should do nothing
	rl.cursorLeft()
	if rl.cursor != 0 {
		t.Errorf("cursor should stay at home, got %d", rl.cursor)
	}
}

// TestReadLine_KillToEnd tests Ctrl+K behavior.
func TestReadLine_KillToEnd(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("hello world"),
		cursor: 5, // after "hello"
	}

	rl.killToEnd()

	if string(rl.line) != "hello" {
		t.Errorf("expected 'hello', got %q", string(rl.line))
	}
	if rl.cursor != 5 {
		t.Errorf("cursor should stay at 5, got %d", rl.cursor)
	}
}

// TestReadLine_KillToBeginning tests Ctrl+U behavior.
func TestReadLine_KillToBeginning(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("hello world"),
		cursor: 6, // after "hello "
	}

	rl.killToBeginning()

	if string(rl.line) != "world" {
		t.Errorf("expected 'world', got %q", string(rl.line))
	}
	if rl.cursor != 0 {
		t.Errorf("cursor should be at 0, got %d", rl.cursor)
	}
}

// TestReadLine_KillWordBackward tests Ctrl+W behavior.
func TestReadLine_KillWordBackward(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		cursor     int
		wantLine   string
		wantCursor int
	}{
		{
			name:       "kill word at end",
			line:       "hello world",
			cursor:     11,
			wantLine:   "hello ",
			wantCursor: 6,
		},
		{
			name:       "kill word in middle",
			line:       "one two three",
			cursor:     7, // after "one two"
			wantLine:   "one  three",
			wantCursor: 4,
		},
		{
			name:       "at beginning",
			line:       "hello",
			cursor:     0,
			wantLine:   "hello",
			wantCursor: 0,
		},
		{
			name:       "single word",
			line:       "hello",
			cursor:     5,
			wantLine:   "",
			wantCursor: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			rl := &ReadLine{
				out:    &out,
				line:   []rune(tt.line),
				cursor: tt.cursor,
			}

			rl.killWordBackward()

			if string(rl.line) != tt.wantLine {
				t.Errorf("expected %q, got %q", tt.wantLine, string(rl.line))
			}
			if rl.cursor != tt.wantCursor {
				t.Errorf("expected cursor at %d, got %d", tt.wantCursor, rl.cursor)
			}
		})
	}
}

// TestReadLine_HistoryNavigation tests up/down arrow history.
func TestReadLine_HistoryNavigation(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:     &out,
		history: []string{"first", "second", "third"},
		histIdx: 3, // at end (new line)
		line:    []rune{},
		cursor:  0,
	}

	// Up arrow - should show "third"
	rl.historyPrev()
	if string(rl.line) != "third" {
		t.Errorf("expected 'third', got %q", string(rl.line))
	}
	if rl.histIdx != 2 {
		t.Errorf("expected histIdx 2, got %d", rl.histIdx)
	}

	// Up arrow again - should show "second"
	rl.historyPrev()
	if string(rl.line) != "second" {
		t.Errorf("expected 'second', got %q", string(rl.line))
	}

	// Up arrow again - should show "first"
	rl.historyPrev()
	if string(rl.line) != "first" {
		t.Errorf("expected 'first', got %q", string(rl.line))
	}

	// Up arrow at beginning - should stay at "first"
	rl.historyPrev()
	if string(rl.line) != "first" {
		t.Errorf("should stay at 'first', got %q", string(rl.line))
	}

	// Down arrow - should show "second"
	rl.historyNext()
	if string(rl.line) != "second" {
		t.Errorf("expected 'second', got %q", string(rl.line))
	}

	// Down arrow - should show "third"
	rl.historyNext()
	if string(rl.line) != "third" {
		t.Errorf("expected 'third', got %q", string(rl.line))
	}

	// Down arrow at end - should clear line
	rl.historyNext()
	if string(rl.line) != "" {
		t.Errorf("expected empty line, got %q", string(rl.line))
	}
}

// TestReadLine_SetLine tests replacing line content (used by history).
func TestReadLine_SetLine(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("old content"),
		cursor: 5,
	}

	rl.setLine("new content")

	if string(rl.line) != "new content" {
		t.Errorf("expected 'new content', got %q", string(rl.line))
	}
	if rl.cursor != 11 {
		t.Errorf("cursor should be at end (11), got %d", rl.cursor)
	}
}

// TestReadLine_SimulateTypingExpression simulates typing a CEL expression.
func TestReadLine_SimulateTypingExpression(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune{},
		cursor: 0,
	}

	// Simulate typing: vulnerability.severity == "CRITICAL"
	expr := `vulnerability.severity == "CRITICAL"`
	for _, r := range expr {
		rl.insertChar(r)
	}

	if string(rl.line) != expr {
		t.Errorf("expected %q, got %q", expr, string(rl.line))
	}
	if rl.cursor != len(expr) {
		t.Errorf("cursor should be at %d, got %d", len(expr), rl.cursor)
	}
}

// TestReadLine_SimulateEditingMistake simulates making and correcting a typo.
func TestReadLine_SimulateEditingMistake(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune{},
		cursor: 0,
	}

	// Type "vulnerabilty" (typo - missing 'i')
	for _, r := range "vulnerabilty" {
		rl.insertChar(r)
	}

	// Realize mistake, move cursor left 2 positions
	rl.cursorLeft() // before 'y'
	rl.cursorLeft() // before 't'

	// Insert missing 'i'
	rl.insertChar('i')

	if string(rl.line) != "vulnerability" {
		t.Errorf("expected 'vulnerability', got %q", string(rl.line))
	}
}

// TestReadLine_SimulateCtrlUAndRetype simulates clearing and retyping.
func TestReadLine_SimulateCtrlUAndRetype(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune{},
		cursor: 0,
	}

	// Type something wrong
	for _, r := range "wrong expression" {
		rl.insertChar(r)
	}

	// Ctrl+U to clear
	rl.killToBeginning()

	if string(rl.line) != "" {
		t.Errorf("line should be empty after Ctrl+U, got %q", string(rl.line))
	}

	// Type correct expression
	for _, r := range "correct expression" {
		rl.insertChar(r)
	}

	if string(rl.line) != "correct expression" {
		t.Errorf("expected 'correct expression', got %q", string(rl.line))
	}
}

// TestReadLine_SimulateHistoryRecall simulates recalling and editing history.
func TestReadLine_SimulateHistoryRecall(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:     &out,
		history: []string{"severity.CRITICAL", "severity.HIGH", "severity.MEDIUM"},
		histIdx: 3,
		line:    []rune{},
		cursor:  0,
	}

	// Press up to get "severity.MEDIUM"
	rl.historyPrev()

	// Press up again to get "severity.HIGH"
	rl.historyPrev()

	// Edit it to change HIGH to LOW
	// Go to end, backspace 4 times to remove "HIGH", type "LOW"
	rl.cursorEnd()
	rl.backspace() // H
	rl.backspace() // G
	rl.backspace() // I
	rl.backspace() // H

	for _, r := range "LOW" {
		rl.insertChar(r)
	}

	if string(rl.line) != "severity.LOW" {
		t.Errorf("expected 'severity.LOW', got %q", string(rl.line))
	}
}

// TestReadLine_SimulateMultipleBackspaces tests rapid backspacing.
func TestReadLine_SimulateMultipleBackspaces(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune("testing"),
		cursor: 7,
	}

	// Backspace everything
	for i := 0; i < 10; i++ { // More than needed
		rl.backspace()
	}

	if string(rl.line) != "" {
		t.Errorf("expected empty line, got %q", string(rl.line))
	}
	if rl.cursor != 0 {
		t.Errorf("cursor should be at 0, got %d", rl.cursor)
	}
}

// TestReadLine_UTF8Characters tests handling of unicode characters.
func TestReadLine_UTF8Characters(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune{},
		cursor: 0,
	}

	// Type emoji and unicode
	for _, r := range "café ☕ 日本語" {
		rl.insertChar(r)
	}

	if string(rl.line) != "café ☕ 日本語" {
		t.Errorf("expected 'café ☕ 日本語', got %q", string(rl.line))
	}

	// Cursor should be at correct position (rune count, not byte count)
	expectedLen := len([]rune("café ☕ 日本語"))
	if rl.cursor != expectedLen {
		t.Errorf("expected cursor at %d, got %d", expectedLen, rl.cursor)
	}

	// Backspace should remove one rune at a time
	rl.backspace()
	if string(rl.line) != "café ☕ 日本" {
		t.Errorf("expected 'café ☕ 日本', got %q", string(rl.line))
	}
}

// TestReadLine_EmptyHistory tests navigation with no history.
func TestReadLine_EmptyHistory(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:     &out,
		history: []string{},
		histIdx: 0,
		line:    []rune("current"),
		cursor:  7,
	}

	// Up arrow with no history should do nothing
	rl.historyPrev()
	if string(rl.line) != "current" {
		t.Errorf("line should not change with empty history, got %q", string(rl.line))
	}

	// Down arrow with no history should do nothing
	rl.historyNext()
	if string(rl.line) != "current" {
		t.Errorf("line should not change with empty history, got %q", string(rl.line))
	}
}

// TestReadLine_HomeEndWithEmptyLine tests Home/End with empty line.
func TestReadLine_HomeEndWithEmptyLine(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune{},
		cursor: 0,
	}

	// Home on empty line
	rl.cursorHome()
	if rl.cursor != 0 {
		t.Errorf("cursor should be 0, got %d", rl.cursor)
	}

	// End on empty line
	rl.cursorEnd()
	if rl.cursor != 0 {
		t.Errorf("cursor should be 0, got %d", rl.cursor)
	}
}

// TestReadLine_KillOperationsOnEmptyLine tests kill commands on empty line.
func TestReadLine_KillOperationsOnEmptyLine(t *testing.T) {
	var out bytes.Buffer
	rl := &ReadLine{
		out:    &out,
		line:   []rune{},
		cursor: 0,
	}

	// These should not panic
	rl.killToEnd()
	rl.killToBeginning()
	rl.killWordBackward()

	if len(rl.line) != 0 {
		t.Error("line should still be empty")
	}
}
