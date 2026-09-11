package ui

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// testEnviron is a fixed environment so profile decisions can be asserted
// without depending on the terminal or CI variables the test process inherits.
type testEnviron map[string]string

// Environ returns the environment in the KEY=VALUE form termenv expects.
func (e testEnviron) Environ() []string {
	out := make([]string, 0, len(e))
	for k, v := range e {
		out = append(out, k+"="+v)
	}
	return out
}

// Getenv returns the value for key, or the empty string when unset.
func (e testEnviron) Getenv(key string) string {
	return e[key]
}

// trueColorTerminalEnv is the environment of a color-capable terminal, used to
// prove that a non-terminal destination stays plain even when the process is
// attached to one.
func trueColorTerminalEnv() testEnviron {
	return testEnviron{"TERM": "xterm-256color", "COLORTERM": "truecolor"}
}

func TestColorProfileFor(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.Create(filepath.Join(t.TempDir(), "report.txt"))
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	t.Cleanup(func() { _ = tmpFile.Close() })

	tests := []struct {
		name   string
		writer io.Writer
		tty    bool
		env    testEnviron
		want   termenv.Profile
	}{
		{
			// The defect in #285: a file destination inherited the terminal's
			// answer and got SGR escapes written into it.
			name:   "file destination is plain even on a color terminal",
			writer: tmpFile,
			env:    trueColorTerminalEnv(),
			want:   termenv.Ascii,
		},
		{
			name:   "buffer destination is plain",
			writer: &bytes.Buffer{},
			env:    trueColorTerminalEnv(),
			want:   termenv.Ascii,
		},
		{
			name:   "nil destination is plain",
			writer: nil,
			env:    trueColorTerminalEnv(),
			want:   termenv.Ascii,
		},
		{
			name:   "terminal destination gets true color",
			writer: &bytes.Buffer{},
			tty:    true,
			env:    trueColorTerminalEnv(),
			want:   termenv.TrueColor,
		},
		{
			name:   "terminal destination gets 256 colors without COLORTERM",
			writer: &bytes.Buffer{},
			tty:    true,
			env:    testEnviron{"TERM": "xterm-256color"},
			want:   termenv.ANSI256,
		},
		{
			name:   "terminal destination honors NO_COLOR",
			writer: &bytes.Buffer{},
			tty:    true,
			env:    testEnviron{"TERM": "xterm-256color", "COLORTERM": "truecolor", "NO_COLOR": "1"},
			want:   termenv.Ascii,
		},
		{
			name:   "terminal destination honors CLICOLOR=0",
			writer: &bytes.Buffer{},
			tty:    true,
			env:    testEnviron{"TERM": "xterm-256color", "COLORTERM": "truecolor", "CLICOLOR": "0"},
			want:   termenv.Ascii,
		},
		{
			name:   "dumb terminal is plain",
			writer: &bytes.Buffer{},
			tty:    true,
			env:    testEnviron{"TERM": "dumb"},
			want:   termenv.Ascii,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := []termenv.OutputOption{termenv.WithEnvironment(tt.env)}
			if tt.tty {
				opts = append(opts, termenv.WithTTY(true))
			}

			if got := colorProfileFor(tt.writer, opts...); got != tt.want {
				t.Errorf("colorProfileFor() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestColorProfileFor_ExportedUsesProcessEnvironment covers the exported entry
// point, which reads the real environment: whatever the terminal advertises, a
// file destination must still be plain.
func TestColorProfileFor_ExportedUsesProcessEnvironment(t *testing.T) {
	t.Parallel()

	f, err := os.Create(filepath.Join(t.TempDir(), "report.txt"))
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if got := ColorProfileFor(f); got != termenv.Ascii {
		t.Errorf("ColorProfileFor(file) = %v, want %v", got, termenv.Ascii)
	}
}

// TestUseColorProfileFor cannot run in parallel: the styles are package level,
// so the profile they render with is process wide.
func TestUseColorProfileFor(t *testing.T) {
	// Stand in for the reproduction condition: under a pty, lipgloss resolves a
	// color profile from os.Stdout at init and every style binds to it.
	original := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(original) })

	if !strings.Contains(StyleHeader.Render("Scan Results:"), "\x1b") {
		t.Fatal("precondition failed: styles are not colored, cannot detect a leak")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "report.txt"))
	if err != nil {
		t.Fatalf("os.Create() error = %v", err)
	}
	defer f.Close()

	restore := UseColorProfileFor(f)

	if got := StyleHeader.Render("Scan Results:"); strings.Contains(got, "\x1b") {
		t.Errorf("styles still emit escapes for a file destination: %q", got)
	}
	if got := lipgloss.ColorProfile(); got != termenv.Ascii {
		t.Errorf("lipgloss.ColorProfile() = %v, want %v", got, termenv.Ascii)
	}

	restore()

	if got := lipgloss.ColorProfile(); got != termenv.TrueColor {
		t.Errorf("after restore lipgloss.ColorProfile() = %v, want %v", got, termenv.TrueColor)
	}
	if got := StyleHeader.Render("Scan Results:"); !strings.Contains(got, "\x1b") {
		t.Errorf("restore did not bring color back for the terminal: %q", got)
	}
}
