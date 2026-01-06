package ui

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ProgressStyle configures the appearance of progress indicators.
type ProgressStyle struct {
	Spinner    []string
	SpinnerFPS time.Duration
	DoneChar   string
	FailChar   string
	Style      lipgloss.Style
	DoneStyle  lipgloss.Style
	FailStyle  lipgloss.Style
}

// DefaultProgressStyle returns the standard progress indicator style.
func DefaultProgressStyle() ProgressStyle {
	return ProgressStyle{
		Spinner:    []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		SpinnerFPS: 80 * time.Millisecond,
		DoneChar:   "✓",
		FailChar:   "✗",
		Style:      lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF")),
		DoneStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("#32CD32")),
		FailStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")),
	}
}

// SimpleProgressStyle returns a simpler ASCII-based progress style.
func SimpleProgressStyle() ProgressStyle {
	return ProgressStyle{
		Spinner:    []string{"|", "/", "-", "\\"},
		SpinnerFPS: 100 * time.Millisecond,
		DoneChar:   "+",
		FailChar:   "x",
		Style:      lipgloss.NewStyle(),
		DoneStyle:  lipgloss.NewStyle(),
		FailStyle:  lipgloss.NewStyle(),
	}
}

// Progress represents a progress indicator for long-running operations.
type Progress struct {
	writer  io.Writer
	style   ProgressStyle
	message string

	mu       sync.Mutex
	running  bool
	done     chan struct{}
	frame    int
	total    int64
	current  atomic.Int64
	subMsg   string
	isTTY    bool
}

// NewProgress creates a new progress indicator.
// If writer is nil, os.Stderr is used.
func NewProgress(writer io.Writer, message string) *Progress {
	if writer == nil {
		writer = os.Stderr
	}
	return &Progress{
		writer:  writer,
		style:   DefaultProgressStyle(),
		message: message,
		isTTY:   IsTTY(writer),
	}
}

// WithStyle sets a custom progress style.
func (p *Progress) WithStyle(style ProgressStyle) *Progress {
	p.style = style
	return p
}

// WithTotal sets the total count for percentage-based progress.
func (p *Progress) WithTotal(total int64) *Progress {
	p.total = total
	return p
}

// Start begins the progress indicator animation.
// It runs in a goroutine until Stop is called.
func (p *Progress) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.done = make(chan struct{})
	p.mu.Unlock()

	go p.run(ctx)
}

// Update updates the current progress count.
func (p *Progress) Update(current int64) {
	p.current.Store(current)
}

// Increment adds delta to the current progress count.
func (p *Progress) Increment(delta int64) {
	p.current.Add(delta)
}

// SetSubMessage sets a secondary message shown after the main message.
func (p *Progress) SetSubMessage(msg string) {
	p.mu.Lock()
	p.subMsg = msg
	p.mu.Unlock()
}

// Stop stops the progress indicator and shows the final state.
func (p *Progress) Stop(success bool) {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	close(p.done)
	p.mu.Unlock()

	// Clear the line and show final state
	if p.isTTY {
		p.clearLine()
	}

	char := p.style.DoneChar
	style := p.style.DoneStyle
	if !success {
		char = p.style.FailChar
		style = p.style.FailStyle
	}

	if p.isTTY {
		fmt.Fprintf(p.writer, "%s %s\n", style.Render(char), p.message)
	}
}

// Done is a convenience method that calls Stop(true).
func (p *Progress) Done() {
	p.Stop(true)
}

// Fail is a convenience method that calls Stop(false).
func (p *Progress) Fail() {
	p.Stop(false)
}

// Clear stops the progress indicator and clears the line without printing
// a final status message. Use this when you want the spinner during an
// operation but want output to flow naturally afterward.
func (p *Progress) Clear() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	close(p.done)
	p.mu.Unlock()

	if p.isTTY {
		p.clearLine()
	}
}

func (p *Progress) run(ctx context.Context) {
	ticker := time.NewTicker(p.style.SpinnerFPS)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-ticker.C:
			p.render()
		}
	}
}

func (p *Progress) render() {
	if !p.isTTY {
		return
	}

	p.mu.Lock()
	frame := p.style.Spinner[p.frame%len(p.style.Spinner)]
	p.frame++
	subMsg := p.subMsg
	p.mu.Unlock()

	current := p.current.Load()

	var line string
	spinner := p.style.Style.Render(frame)

	if p.total > 0 {
		pct := float64(current) / float64(p.total) * 100
		if subMsg != "" {
			line = fmt.Sprintf("\r%s %s (%.0f%%) %s", spinner, p.message, pct, subMsg)
		} else {
			line = fmt.Sprintf("\r%s %s (%.0f%%)", spinner, p.message, pct)
		}
	} else if current > 0 {
		if subMsg != "" {
			line = fmt.Sprintf("\r%s %s (%d) %s", spinner, p.message, current, subMsg)
		} else {
			line = fmt.Sprintf("\r%s %s (%d)", spinner, p.message, current)
		}
	} else {
		if subMsg != "" {
			line = fmt.Sprintf("\r%s %s %s", spinner, p.message, subMsg)
		} else {
			line = fmt.Sprintf("\r%s %s", spinner, p.message)
		}
	}

	p.clearLine()
	fmt.Fprint(p.writer, line)
}

func (p *Progress) clearLine() {
	if p.isTTY {
		fmt.Fprint(p.writer, "\r\033[K")
	}
}

// IsTTY checks if writer is a terminal.
func IsTTY(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		info, err := f.Stat()
		if err != nil {
			return false
		}
		return (info.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

// MultiProgress manages multiple concurrent progress indicators.
type MultiProgress struct {
	writer io.Writer
	mu     sync.Mutex
	tasks  map[string]*taskState
	order  []string
	isTTY  bool
}

type taskState struct {
	message string
	status  string // "running", "done", "failed"
	detail  string
}

// NewMultiProgress creates a manager for multiple concurrent tasks.
func NewMultiProgress(writer io.Writer) *MultiProgress {
	if writer == nil {
		writer = os.Stderr
	}
	return &MultiProgress{
		writer: writer,
		tasks:  make(map[string]*taskState),
		isTTY:  IsTTY(writer),
	}
}

// AddTask adds a new task to track.
func (mp *MultiProgress) AddTask(id, message string) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if _, exists := mp.tasks[id]; !exists {
		mp.order = append(mp.order, id)
	}
	mp.tasks[id] = &taskState{
		message: message,
		status:  "running",
	}

	if !mp.isTTY {
		fmt.Fprintf(mp.writer, "  - %s...\n", message)
	}
}

// UpdateTask updates a task's detail message.
func (mp *MultiProgress) UpdateTask(id, detail string) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	if task, ok := mp.tasks[id]; ok {
		task.detail = detail
	}
}

// CompleteTask marks a task as done.
func (mp *MultiProgress) CompleteTask(id string, success bool) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	task, ok := mp.tasks[id]
	if !ok {
		return
	}

	if success {
		task.status = "done"
	} else {
		task.status = "failed"
	}

	if !mp.isTTY {
		status := "done"
		if !success {
			status = "FAILED"
		}
		fmt.Fprintf(mp.writer, "  - %s: %s\n", task.message, status)
	}
}

// Render displays the current state of all tasks.
// Call this in a loop or after state changes.
func (mp *MultiProgress) Render() {
	if !mp.isTTY {
		return
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	style := DefaultProgressStyle()

	for _, id := range mp.order {
		task := mp.tasks[id]
		var prefix string
		switch task.status {
		case "running":
			prefix = style.Style.Render("→")
		case "done":
			prefix = style.DoneStyle.Render(style.DoneChar)
		case "failed":
			prefix = style.FailStyle.Render(style.FailChar)
		}

		if task.detail != "" {
			fmt.Fprintf(mp.writer, "  %s %s (%s)\n", prefix, task.message, task.detail)
		} else {
			fmt.Fprintf(mp.writer, "  %s %s\n", prefix, task.message)
		}
	}
}

// ProgressFunc is a helper for wrapping a function with progress indication.
// It starts a progress indicator, runs the function, and stops with appropriate status.
func ProgressFunc[T any](ctx context.Context, w io.Writer, message string, fn func() (T, error)) (T, error) {
	p := NewProgress(w, message)
	p.Start(ctx)

	result, err := fn()

	if err != nil {
		p.Fail()
	} else {
		p.Done()
	}

	return result, err
}
