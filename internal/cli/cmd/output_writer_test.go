package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	ui "github.com/temporalio/deputy/internal/ui"
)

// asColorTerminal puts the process in the state a pty produces: lipgloss has
// resolved a color profile from stdout and every package level style renders
// with it. Tests that use it cannot be parallel, because that profile is
// process wide. It restores the previous profile on cleanup.
func asColorTerminal(t *testing.T) {
	t.Helper()

	original := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(original) })

	if !strings.Contains(ui.StyleHeader.Render("Scan Results:"), "\x1b") {
		t.Fatal("precondition failed: styles are not colored, an escape leak could not be detected")
	}
}

// TestOpenOutputWriter_FileDestinationIsNotColored is the regression test for
// #285: with a terminal on stdout, a report written to --output must not carry
// ANSI escapes into the file.
func TestOpenOutputWriter_FileDestinationIsNotColored(t *testing.T) {
	asColorTerminal(t)

	outPath := filepath.Join(t.TempDir(), "vulnerabilities.txt")
	cmd := &cobra.Command{Use: "test"}

	out, err := openOutputWriter(cmd, outPath)
	if err != nil {
		t.Fatalf("openOutputWriter() error = %v", err)
	}

	if _, err := out.Writer.Write([]byte(ui.StyleHeader.Render("Scan Results:") + "\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if bytes.Contains(content, []byte{0x1b}) {
		t.Errorf("output file contains ANSI escapes: %q", content)
	}
	if got, want := string(content), "Scan Results:\n"; got != want {
		t.Errorf("output file = %q, want %q", got, want)
	}
}

// TestOpenOutputWriter_RestoresColorForTheTerminal checks the other half of the
// contract: the file destination must not leave the process unable to color a
// later terminal write.
func TestOpenOutputWriter_RestoresColorForTheTerminal(t *testing.T) {
	asColorTerminal(t)

	cmd := &cobra.Command{Use: "test"}
	out, err := openOutputWriter(cmd, filepath.Join(t.TempDir(), "report.txt"))
	if err != nil {
		t.Fatalf("openOutputWriter() error = %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got := ui.StyleHeader.Render("Scan Results:"); !strings.Contains(got, "\x1b") {
		t.Errorf("color was not restored after the file destination closed: %q", got)
	}
}

// TestOpenOutputWriter_StdoutDestinationFollowsTheStream covers the "-" and
// empty cases, where the destination is whatever the command writes to. A
// buffer is not a terminal, so it must be plain too.
func TestOpenOutputWriter_StdoutDestinationFollowsTheStream(t *testing.T) {
	asColorTerminal(t)

	for _, outPath := range []string{"", "-"} {
		t.Run("outPath="+outPath, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := &cobra.Command{Use: "test"}
			cmd.SetOut(&buf)

			out, err := openOutputWriter(cmd, outPath)
			if err != nil {
				t.Fatalf("openOutputWriter() error = %v", err)
			}
			if _, err := out.Writer.Write([]byte(ui.StyleHeader.Render("Scan Results:"))); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			if err := out.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}

			if got := buf.String(); strings.Contains(got, "\x1b") {
				t.Errorf("non-terminal stdout contains ANSI escapes: %q", got)
			}
		})
	}
}
