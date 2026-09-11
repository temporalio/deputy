package ui

import (
	"io"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// ColorProfileFor reports the color profile a destination can actually render,
// so styling is decided from the writer the output is going to instead of from
// the process's stdout. The styles in this package are package level, so they
// bind to lipgloss's default renderer, which probes os.Stdout once at init;
// without asking per destination, a report redirected to a file inherits the
// answer for the terminal and carries SGR escapes into the file.
//
// The answer is termenv.Ascii (no escapes at all, not even bold) for any
// destination that is not a terminal, which covers files, pipes, and in-memory
// buffers. Terminal destinations get the profile the environment advertises.
// NO_COLOR, CLICOLOR, CLICOLOR_FORCE, and CI are honored because termenv
// honors them.
func ColorProfileFor(w io.Writer) termenv.Profile {
	return colorProfileFor(w)
}

// colorProfileFor carries the termenv options seam that lets tests describe a
// destination (terminal or not, environment) instead of depending on the
// terminal the test process happens to have.
func colorProfileFor(w io.Writer, opts ...termenv.OutputOption) termenv.Profile {
	if w == nil {
		return termenv.Ascii
	}
	return termenv.NewOutput(w, opts...).EnvColorProfile()
}

// UseColorProfileFor points the styles in this package at what w can render and
// returns a function that restores the previous profile. Callers own the
// window: apply it when the destination opens, restore when it closes.
//
// The profile is process wide because the styles are, so while it is applied
// every writer renders with w's capabilities, including a progress spinner on
// stderr. That is why the restore exists: it keeps the window no longer than
// the destination's lifetime. Building styles per writer would remove the
// window entirely and is the larger follow-up.
func UseColorProfileFor(w io.Writer) (restore func()) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(ColorProfileFor(w))
	return func() { lipgloss.SetColorProfile(previous) }
}
