package otel

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/trace"
)

// TraceContextHandler wraps an slog.Handler to add trace context attributes
// (trace_id, span_id) to log records when available.
type TraceContextHandler struct {
	base slog.Handler
}

// NewTraceContextHandler creates a new handler that adds trace context to logs.
func NewTraceContextHandler(base slog.Handler) *TraceContextHandler {
	return &TraceContextHandler{base: base}
}

// Enabled reports whether the handler handles records at the given level.
func (h *TraceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle adds trace context attributes and delegates to the base handler.
func (h *TraceContextHandler) Handle(ctx context.Context, r slog.Record) error {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		r.AddAttrs(
			slog.String("trace_id", span.SpanContext().TraceID().String()),
			slog.String("span_id", span.SpanContext().SpanID().String()),
		)
		if span.SpanContext().IsSampled() {
			r.AddAttrs(slog.Bool("trace_sampled", true))
		}
	}
	return h.base.Handle(ctx, r)
}

// WithAttrs returns a new handler with the given attributes added.
func (h *TraceContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TraceContextHandler{
		base: h.base.WithAttrs(attrs),
	}
}

// WithGroup returns a new handler with the given group name prepended.
func (h *TraceContextHandler) WithGroup(name string) slog.Handler {
	return &TraceContextHandler{
		base: h.base.WithGroup(name),
	}
}

// WrapHandler wraps an existing handler with trace context support.
// If the handler is already a TraceContextHandler, returns it unchanged.
func WrapHandler(h slog.Handler) slog.Handler {
	if _, ok := h.(*TraceContextHandler); ok {
		return h
	}
	return NewTraceContextHandler(h)
}

// TraceIDFromContext extracts the trace ID from the context, if present.
// Returns an empty string if no valid trace context exists.
func TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// SpanIDFromContext extracts the span ID from the context, if present.
// Returns an empty string if no valid trace context exists.
func SpanIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// LogWithTrace creates log attributes for trace context.
// Useful for manually adding trace context to log calls.
func LogWithTrace(ctx context.Context) []any {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return nil
	}
	return []any{
		"trace_id", span.SpanContext().TraceID().String(),
		"span_id", span.SpanContext().SpanID().String(),
	}
}

// NewOTelHandler creates an slog handler that exports logs via OpenTelemetry.
// The handler sends logs to the configured OTel collector endpoint.
// Use this as a base handler wrapped with TraceContextHandler for full correlation.
func NewOTelHandler(name string) slog.Handler {
	return otelslog.NewHandler(name)
}

// NewMultiHandler creates a handler that writes to multiple handlers.
// Useful for sending logs to both stdout and OTel collector.
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler creates a handler that fans out to multiple handlers.
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Enabled reports whether the handler handles records at the given level.
func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle writes the record to all handlers.
func (h *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			if err := handler.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// WithAttrs returns a new handler with the given attributes added.
func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: handlers}
}

// WithGroup returns a new handler with the given group name prepended.
func (h *MultiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		handlers[i] = handler.WithGroup(name)
	}
	return &MultiHandler{handlers: handlers}
}

// AuditHandler filters log records to only those matching audit event patterns
// and writes them as JSON to a dedicated audit log destination.
//
// Audit events are identified by message prefixes (e.g., "deputy.scan.",
// "deputy.policy.", "deputy.proxy."). This allows using standard slog calls
// for audit logging without a separate API.
//
// Usage:
//
//	auditFile, _ := os.OpenFile("audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
//	auditHandler := otel.NewAuditHandler(auditFile, "deputy.")
//	logger := slog.New(otel.NewMultiHandler(mainHandler, auditHandler))
//
//	// This goes to both main log and audit log:
//	logger.Info("deputy.scan.completed", "target", "github.com/example/repo", "vulns", 5)
//
//	// This only goes to main log (no "deputy." prefix):
//	logger.Debug("processing file", "path", "/tmp/foo")
type AuditHandler struct {
	base   slog.Handler
	prefix string
}

// NewAuditHandler creates a handler that filters for audit events and writes JSON.
// Only log records whose message starts with the given prefix are written.
// Common prefix values: "deputy." for all Deputy events.
func NewAuditHandler(w io.Writer, prefix string) *AuditHandler {
	return &AuditHandler{
		base:   slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}),
		prefix: prefix,
	}
}

// Enabled reports whether the handler handles records at the given level.
// The handler is always enabled; filtering happens in Handle based on message prefix.
func (h *AuditHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// Handle writes the record if its message matches the audit prefix.
func (h *AuditHandler) Handle(ctx context.Context, r slog.Record) error {
	if !strings.HasPrefix(r.Message, h.prefix) {
		return nil // Skip non-audit records
	}
	return h.base.Handle(ctx, r)
}

// WithAttrs returns a new handler with the given attributes added.
func (h *AuditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AuditHandler{
		base:   h.base.WithAttrs(attrs),
		prefix: h.prefix,
	}
}

// WithGroup returns a new handler with the given group name prepended.
func (h *AuditHandler) WithGroup(name string) slog.Handler {
	return &AuditHandler{
		base:   h.base.WithGroup(name),
		prefix: h.prefix,
	}
}
