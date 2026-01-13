package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// CompletionFunc returns completions for the current input at cursor position.
type CompletionFunc func(line string, cursor int) []string

// ReadLine provides interactive line editing with history support.
type ReadLine struct {
	in      io.Reader
	out     io.Writer
	history []string
	histIdx int
	prompt  string

	// Current line state
	line   []rune
	cursor int

	// Terminal state (for raw mode)
	fd       int
	oldState *term.State
	isRaw    bool
	isTTY    bool

	// Simple mode scanner (for non-TTY)
	scanner *bufio.Scanner

	// Completion support
	completer    CompletionFunc
	completions  []string
	compIdx      int
	compOriginal string // original text before cycling
}

// NewReadLine creates a new readline instance.
func NewReadLine(in io.Reader, out io.Writer) *ReadLine {
	rl := &ReadLine{
		in:      in,
		out:     out,
		history: make([]string, 0, 100),
	}

	// Check if input is a TTY
	if f, ok := in.(*os.File); ok {
		rl.fd = int(f.Fd())
		rl.isTTY = term.IsTerminal(rl.fd)
	}

	// Pre-create scanner for non-TTY mode
	if !rl.isTTY {
		rl.scanner = bufio.NewScanner(in)
	}

	return rl
}

// SetHistory sets the history list.
func (rl *ReadLine) SetHistory(history []string) {
	rl.history = history
}

// SetCompleter sets the completion function.
func (rl *ReadLine) SetCompleter(fn CompletionFunc) {
	rl.completer = fn
}

// Read reads a line with interactive editing if available.
func (rl *ReadLine) Read(ctx context.Context, prompt string) (string, error) {
	rl.prompt = prompt

	// If not a TTY, fall back to simple line reading
	if !rl.isTTY {
		return rl.readSimple()
	}

	return rl.readInteractive(ctx)
}

// readSimple reads a line without terminal features (for pipes/non-TTY).
func (rl *ReadLine) readSimple() (string, error) {
	if rl.scanner == nil {
		rl.scanner = bufio.NewScanner(rl.in)
	}
	if !rl.scanner.Scan() {
		if err := rl.scanner.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	return rl.scanner.Text(), nil
}

// readInteractive provides full terminal editing support.
func (rl *ReadLine) readInteractive(ctx context.Context) (string, error) {
	// Enter raw mode
	var err error
	rl.oldState, err = term.MakeRaw(rl.fd)
	if err != nil {
		// Fall back to simple mode
		return rl.readSimple()
	}
	rl.isRaw = true
	defer func() {
		term.Restore(rl.fd, rl.oldState)
		rl.isRaw = false
	}()

	// Reset line state
	rl.line = nil
	rl.cursor = 0
	rl.histIdx = len(rl.history)

	// Display prompt immediately
	fmt.Fprint(rl.out, rl.prompt)

	// Read character by character
	buf := make([]byte, 32)
	for {
		select {
		case <-ctx.Done():
			fmt.Fprint(rl.out, "\r\n")
			return "", ctx.Err()
		default:
		}

		n, err := rl.in.Read(buf)
		if err != nil {
			fmt.Fprint(rl.out, "\r\n")
			return "", err
		}

		for i := 0; i < n; {
			b := buf[i]
			i++

			switch b {
			case 3: // Ctrl+C
				fmt.Fprint(rl.out, "^C\r\n")
				return "", io.EOF

			case 4: // Ctrl+D
				if len(rl.line) == 0 {
					fmt.Fprint(rl.out, "\r\n")
					return "", io.EOF
				}
				// Delete character under cursor
				rl.deleteChar()

			case 13, 10: // Enter
				fmt.Fprint(rl.out, "\r\n")
				return string(rl.line), nil

			case 127, 8: // Backspace
				rl.backspace()

			case 27: // Escape sequence
				if i+1 < n && buf[i] == '[' {
					i++
					if i < n {
						switch buf[i] {
						case 'A': // Up arrow
							rl.historyPrev()
						case 'B': // Down arrow
							rl.historyNext()
						case 'C': // Right arrow
							rl.cursorRight()
						case 'D': // Left arrow
							rl.cursorLeft()
						case 'H': // Home
							rl.cursorHome()
						case 'F': // End
							rl.cursorEnd()
						case '3': // Delete key (needs extra byte)
							if i+1 < n && buf[i+1] == '~' {
								i++
								rl.deleteChar()
							}
						}
						i++
					}
				}

			case 1: // Ctrl+A - beginning of line
				rl.cursorHome()

			case 5: // Ctrl+E - end of line
				rl.cursorEnd()

			case 11: // Ctrl+K - kill to end of line
				rl.killToEnd()

			case 21: // Ctrl+U - kill to beginning of line
				rl.killToBeginning()

			case 23: // Ctrl+W - kill word backward
				rl.killWordBackward()

			case 12: // Ctrl+L - clear screen
				rl.clearScreen()

			case 9: // Tab - completion
				rl.handleTab()

			default:
				if b >= 32 && b < 127 {
					rl.insertChar(rune(b))
					rl.resetCompletion() // reset completion state on normal input
				} else if b >= 128 {
					// Handle UTF-8 multi-byte sequences
					remaining := utf8Remaining(b)
					if i+remaining <= n {
						runeBytes := append([]byte{b}, buf[i:i+remaining]...)
						i += remaining
						r := decodeRune(runeBytes)
						if r != 0 {
							rl.insertChar(r)
						}
					}
				}
			}
		}
	}
}

// insertChar inserts a character at the cursor position.
func (rl *ReadLine) insertChar(r rune) {
	if rl.cursor == len(rl.line) {
		rl.line = append(rl.line, r)
	} else {
		rl.line = append(rl.line[:rl.cursor], append([]rune{r}, rl.line[rl.cursor:]...)...)
	}
	rl.cursor++
	rl.redraw()
}

// backspace deletes the character before the cursor.
func (rl *ReadLine) backspace() {
	if rl.cursor > 0 {
		rl.line = append(rl.line[:rl.cursor-1], rl.line[rl.cursor:]...)
		rl.cursor--
		rl.redraw()
	}
}

// deleteChar deletes the character at the cursor.
func (rl *ReadLine) deleteChar() {
	if rl.cursor < len(rl.line) {
		rl.line = append(rl.line[:rl.cursor], rl.line[rl.cursor+1:]...)
		rl.redraw()
	}
}

// cursorLeft moves the cursor left.
func (rl *ReadLine) cursorLeft() {
	if rl.cursor > 0 {
		rl.cursor--
		fmt.Fprint(rl.out, "\x1b[D")
	}
}

// cursorRight moves the cursor right.
func (rl *ReadLine) cursorRight() {
	if rl.cursor < len(rl.line) {
		rl.cursor++
		fmt.Fprint(rl.out, "\x1b[C")
	}
}

// cursorHome moves the cursor to the beginning of the line.
func (rl *ReadLine) cursorHome() {
	if rl.cursor > 0 {
		fmt.Fprintf(rl.out, "\x1b[%dD", rl.cursor)
		rl.cursor = 0
	}
}

// cursorEnd moves the cursor to the end of the line.
func (rl *ReadLine) cursorEnd() {
	if rl.cursor < len(rl.line) {
		fmt.Fprintf(rl.out, "\x1b[%dC", len(rl.line)-rl.cursor)
		rl.cursor = len(rl.line)
	}
}

// killToEnd removes text from cursor to end of line.
func (rl *ReadLine) killToEnd() {
	rl.line = rl.line[:rl.cursor]
	rl.redraw()
}

// killToBeginning removes text from beginning to cursor.
func (rl *ReadLine) killToBeginning() {
	rl.line = rl.line[rl.cursor:]
	rl.cursor = 0
	rl.redraw()
}

// killWordBackward removes the word before the cursor.
func (rl *ReadLine) killWordBackward() {
	if rl.cursor == 0 {
		return
	}
	// Find start of previous word
	pos := rl.cursor - 1
	// Skip spaces
	for pos > 0 && rl.line[pos] == ' ' {
		pos--
	}
	// Skip word characters
	for pos > 0 && rl.line[pos-1] != ' ' {
		pos--
	}
	rl.line = append(rl.line[:pos], rl.line[rl.cursor:]...)
	rl.cursor = pos
	rl.redraw()
}

// clearScreen clears the screen and redraws.
func (rl *ReadLine) clearScreen() {
	fmt.Fprint(rl.out, "\x1b[2J\x1b[H")
	fmt.Fprint(rl.out, rl.prompt)
	fmt.Fprint(rl.out, string(rl.line))
	if rl.cursor < len(rl.line) {
		fmt.Fprintf(rl.out, "\x1b[%dD", len(rl.line)-rl.cursor)
	}
}

// historyPrev moves to the previous history entry.
func (rl *ReadLine) historyPrev() {
	if rl.histIdx > 0 {
		rl.histIdx--
		rl.setLine(rl.history[rl.histIdx])
	}
}

// historyNext moves to the next history entry.
func (rl *ReadLine) historyNext() {
	if rl.histIdx < len(rl.history)-1 {
		rl.histIdx++
		rl.setLine(rl.history[rl.histIdx])
	} else if rl.histIdx == len(rl.history)-1 {
		rl.histIdx = len(rl.history)
		rl.setLine("")
	}
}

// setLine replaces the current line content.
func (rl *ReadLine) setLine(s string) {
	rl.line = []rune(s)
	rl.cursor = len(rl.line)
	rl.redraw()
}

// redraw redraws the current line.
func (rl *ReadLine) redraw() {
	// Move to beginning, clear line, print prompt and content
	fmt.Fprint(rl.out, "\r\x1b[K")
	fmt.Fprint(rl.out, rl.prompt)
	fmt.Fprint(rl.out, string(rl.line))
	// Move cursor to correct position
	if rl.cursor < len(rl.line) {
		fmt.Fprintf(rl.out, "\x1b[%dD", len(rl.line)-rl.cursor)
	}
}

// utf8Remaining returns the number of remaining bytes for a UTF-8 sequence.
func utf8Remaining(first byte) int {
	if first&0x80 == 0 {
		return 0
	} else if first&0xE0 == 0xC0 {
		return 1
	} else if first&0xF0 == 0xE0 {
		return 2
	} else if first&0xF8 == 0xF0 {
		return 3
	}
	return 0
}

// decodeRune decodes a UTF-8 byte sequence to a rune.
func decodeRune(b []byte) rune {
	s := string(b)
	if len(s) == 0 {
		return 0
	}
	for _, r := range s {
		return r
	}
	return 0
}

// AddHistory adds a line to history (avoiding duplicates and empty lines).
func (rl *ReadLine) AddHistory(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	// Avoid duplicates at end
	if len(rl.history) > 0 && rl.history[len(rl.history)-1] == line {
		return
	}
	rl.history = append(rl.history, line)
	// Limit history size
	if len(rl.history) > 1000 {
		rl.history = rl.history[1:]
	}
}

// History returns the current history.
func (rl *ReadLine) History() []string {
	return rl.history
}

// handleTab handles tab completion.
func (rl *ReadLine) handleTab() {
	if rl.completer == nil {
		return
	}

	// First tab: get completions
	if rl.completions == nil {
		rl.compOriginal = string(rl.line)
		rl.completions = rl.completer(string(rl.line), rl.cursor)
		rl.compIdx = 0
	} else if len(rl.completions) > 0 {
		// Subsequent tabs: cycle through completions
		rl.compIdx = (rl.compIdx + 1) % len(rl.completions)
	}

	// Apply completion
	if len(rl.completions) > 0 {
		rl.line = []rune(rl.completions[rl.compIdx])
		rl.cursor = len(rl.line)
		rl.redraw()
	}
}

// resetCompletion clears the completion state.
func (rl *ReadLine) resetCompletion() {
	rl.completions = nil
	rl.compIdx = 0
	rl.compOriginal = ""
}
