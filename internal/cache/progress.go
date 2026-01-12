package cache

import (
	"context"
	"io"
	"os"

	"github.com/picatz/deputy/internal/ui"
)

// UIProgressWriter adapts ui.Progress to the cache.ProgressWriter interface.
type UIProgressWriter struct {
	progress *ui.Progress
	ctx      context.Context
}

// NewUIProgressWriter creates a progress writer backed by ui.Progress.
// The message is displayed during the download operation.
func NewUIProgressWriter(ctx context.Context, w io.Writer, message string) *UIProgressWriter {
	if w == nil {
		w = os.Stderr
	}
	p := ui.NewProgress(w, message)
	return &UIProgressWriter{
		progress: p,
		ctx:      ctx,
	}
}

// Start begins the progress indicator animation.
func (p *UIProgressWriter) Start() {
	p.progress.Start(p.ctx)
}

// SetTotal implements ProgressWriter.
func (p *UIProgressWriter) SetTotal(total int64) {
	if total > 0 {
		p.progress.WithTotal(total)
	}
}

// Add implements ProgressWriter.
func (p *UIProgressWriter) Add(n int64) {
	p.progress.Increment(n)
}

// Done implements ProgressWriter.
func (p *UIProgressWriter) Done() {
	p.progress.Done()
}

// Fail marks the progress as failed.
func (p *UIProgressWriter) Fail() {
	p.progress.Fail()
}
