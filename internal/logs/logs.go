// Package logs provides context-aware structured logging for Deputy using slog.
// It supports attaching loggers to contexts, optional ANSI color formatting,
// and consistent logging patterns across the codebase.
package logs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	deputyotel "github.com/picatz/deputy/internal/otel"
)

type contextKey struct{}

var (
	loggerKey = contextKey{}
	// defaultLogger is used when no logger is attached to the context.
	defaultLogger atomic.Pointer[slog.Logger]
)

func init() {
	defaultLogger.Store(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
}

// Options configures logger behavior including output format and styling.
type Options struct {
	// Level sets the minimum log level (Debug, Info, Warn, Error).
	Level slog.Level

	// Format specifies the output format ("text", "json").
	Format string

	// Writer is the destination for log output (defaults to os.Stderr).
	Writer io.Writer

	// ColorEnabled enables ANSI color codes for level and fields (text format only).
	ColorEnabled bool

	// AddSource includes source file and line number in log output.
	AddSource bool

	// IncludeTraceContext adds trace_id and span_id to log records when available.
	IncludeTraceContext bool

	// ExportToOTel enables exporting logs to the OpenTelemetry collector.
	// When enabled, logs are sent both to the writer and to the OTel backend.
	ExportToOTel bool
}

// New creates a new configured slog.Logger based on the provided options.
func New(opts Options) *slog.Logger {
	if opts.Writer == nil {
		opts.Writer = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     opts.Level,
		AddSource: opts.AddSource,
	}

	var handler slog.Handler
	switch strings.ToLower(opts.Format) {
	case "json":
		handler = slog.NewJSONHandler(opts.Writer, handlerOpts)
	default:
		if opts.ColorEnabled {
			handler = NewColorHandler(opts.Writer, handlerOpts)
		} else {
			handler = slog.NewTextHandler(opts.Writer, handlerOpts)
		}
	}

	// Wrap with trace context handler if enabled
	if opts.IncludeTraceContext {
		handler = deputyotel.NewTraceContextHandler(handler)
	}

	// Add OTel handler for log export if enabled
	if opts.ExportToOTel {
		otelHandler := deputyotel.NewOTelHandler("deputy")
		handler = deputyotel.NewMultiHandler(handler, otelHandler)
	}

	return slog.New(handler)
}

// WithContext returns a new context with the logger attached.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext extracts the logger from the context, returning the default logger if none is found.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return defaultLogger.Load()
}

// WithField returns a new context with a logger that includes the specified key-value pair.
func WithField(ctx context.Context, key string, value any) context.Context {
	logger := FromContext(ctx).With(key, value)
	return WithContext(ctx, logger)
}

// WithFields returns a new context with a logger that includes all specified key-value pairs.
func WithFields(ctx context.Context, fields map[string]any) context.Context {
	logger := FromContext(ctx)
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger = logger.With(args...)
	return WithContext(ctx, logger)
}

// SetDefault sets the default logger used when no logger is attached to a context.
func SetDefault(logger *slog.Logger) {
	if logger != nil {
		defaultLogger.Store(logger)
	}
}

// Debug logs at Debug level using the logger from the context.
func Debug(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).DebugContext(ctx, msg, args...)
}

// Info logs at Info level using the logger from the context.
func Info(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).InfoContext(ctx, msg, args...)
}

// Warn logs at Warn level using the logger from the context.
func Warn(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).WarnContext(ctx, msg, args...)
}

// Error logs at Error level using the logger from the context.
func Error(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).ErrorContext(ctx, msg, args...)
}

// ColorHandler wraps slog.TextHandler to add ANSI color codes.
// It delegates all logic to the underlying TextHandler but intercepts
// the output to inject color codes for the log level.
type ColorHandler struct {
	internal slog.Handler
}

// NewColorHandler creates a handler that adds ANSI color codes to log levels.
func NewColorHandler(w io.Writer, opts *slog.HandlerOptions) *ColorHandler {
	// We wrap the writer with a colorWriter that injects ANSI codes on the fly.
	cw := &colorWriter{w: w}
	return &ColorHandler{
		internal: slog.NewTextHandler(cw, opts),
	}
}

// Enabled reports whether the handler handles records at the given level.
func (h *ColorHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.internal.Enabled(ctx, level)
}

// Handle formats the record with color-coded levels and writes it.
func (h *ColorHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.internal.Handle(ctx, r)
}

// WithAttrs returns a new handler with the given attributes added.
func (h *ColorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ColorHandler{
		internal: h.internal.WithAttrs(attrs),
	}
}

// WithGroup returns a new handler with the given group name prepended.
func (h *ColorHandler) WithGroup(name string) slog.Handler {
	return &ColorHandler{
		internal: h.internal.WithGroup(name),
	}
}

// colorWriter intercepts writes to inject ANSI color codes for log levels.
// It assumes the standard slog.TextHandler output format: "time=... level=LEVEL msg=..."
type colorWriter struct {
	w io.Writer
}

// Pre-computed level patterns to avoid allocations in Write hot path.
var (
	levelINFO  = []byte("level=INFO")
	levelWARN  = []byte("level=WARN")
	levelERROR = []byte("level=ERROR")
	levelDEBUG = []byte("level=DEBUG")
)

func (cw *colorWriter) Write(p []byte) (n int, err error) {
	// Fast path: if no level key is found, just write.
	// slog.TextHandler always writes "level=".
	// We look for "level=" followed by a known level string.

	// Note: This is a heuristic. It might match "level=" inside a message or key.
	// However, slog.TextHandler puts the level attribute early in the output.
	// For a CLI tool, this trade-off is acceptable for the benefit of robust formatting.

	// Check for standard levels using bytes.Index to avoid string conversion
	if idx := bytes.Index(p, levelINFO); idx != -1 {
		return cw.writeColored(p, idx+6, 4, colorBlue)
	}
	if idx := bytes.Index(p, levelWARN); idx != -1 {
		return cw.writeColored(p, idx+6, 4, colorYellow)
	}
	if idx := bytes.Index(p, levelERROR); idx != -1 {
		return cw.writeColored(p, idx+6, 5, colorRed)
	}
	if idx := bytes.Index(p, levelDEBUG); idx != -1 {
		return cw.writeColored(p, idx+6, 5, colorGray)
	}

	return cw.w.Write(p)
}

func (cw *colorWriter) writeColored(p []byte, start, length int, color string) (int, error) {
	var buf bytes.Buffer
	buf.Grow(len(p) + len(color) + len(colorReset))

	buf.Write(p[:start])
	buf.WriteString(color)
	buf.Write(p[start : start+length])
	buf.WriteString(colorReset)
	buf.Write(p[start+length:])

	// We return len(p) to satisfy io.Writer contract, even though we wrote more bytes.
	_, err := cw.w.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
)

// ParseLevel converts a string level name to slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level: %q", s)
	}
}

