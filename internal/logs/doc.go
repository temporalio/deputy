// Package logs provides structured logging utilities for Deputy.
//
// This package builds on the standard library's [log/slog] package,
// providing a preconfigured logger with support for text and JSON output,
// colored terminal output, and OpenTelemetry trace context injection.
//
// # Creating a Logger
//
// Use [New] to create a configured logger:
//
//	logger := logs.New(logs.Options{
//	    Level:        slog.LevelInfo,
//	    Format:       "text",
//	    Writer:       os.Stderr,
//	    ColorEnabled: true,
//	})
//	slog.SetDefault(logger)
//
// # Log Levels
//
// Parse log levels from strings:
//
//	level, err := logs.ParseLevel("debug")  // Returns slog.LevelDebug
//	level, err := logs.ParseLevel("info")   // Returns slog.LevelInfo
//	level, err := logs.ParseLevel("warn")   // Returns slog.LevelWarn
//	level, err := logs.ParseLevel("error")  // Returns slog.LevelError
//
// # Output Formats
//
// Two output formats are supported:
//   - "text": Human-readable format with optional colors
//   - "json": Structured JSON for log aggregation systems
//
// # Trace Context
//
// When OpenTelemetry is enabled, trace context is automatically included:
//
//	logger := logs.New(logs.Options{
//	    IncludeTraceContext: true,
//	    ExportToOTel:        true,
//	})
//
// This adds trace_id and span_id to log entries for correlation.
//
// # Default Logger
//
// A package-level default logger is available:
//
//	logs.SetDefault(logger)
//	logs.Default().Info("message", "key", "value")
package logs
