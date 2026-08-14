package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	ui "github.com/temporalio/deputy/internal/ui"
)

// outputWriter is a report destination: the writer to render into, whatever
// needs closing afterwards, and the color decision made for it.
type outputWriter struct {
	Writer  io.Writer
	closer  io.Closer
	restore func()
}

// Close restores the color profile that was in effect before the destination
// was opened and closes the underlying writer if it's a file.
func (ow *outputWriter) Close() error {
	if ow.restore != nil {
		ow.restore()
		ow.restore = nil
	}
	if ow.closer != nil {
		return ow.closer.Close()
	}
	return nil
}

// openOutputWriter opens the destination named by outPath: stdout when it is
// empty or "-", otherwise a newly created file. Every command that can write a
// rendered report to --output goes through here, because this is also where the
// color profile is decided from the destination rather than from the process's
// stdout. Without that, a report written to a file while stdout is a terminal
// gets ANSI escapes it cannot use.
//
// The caller must Close the returned outputWriter, which is what ends the
// color decision as well as closing the file.
func openOutputWriter(cmd *cobra.Command, outPath string) (*outputWriter, error) {
	if outPath == "" || outPath == "-" {
		w := cmd.OutOrStdout()
		return &outputWriter{Writer: w, restore: ui.UseColorProfileFor(w)}, nil
	}

	f, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	return &outputWriter{Writer: f, closer: f, restore: ui.UseColorProfileFor(f)}, nil
}
