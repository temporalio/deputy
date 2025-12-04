package logs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestWithContextAndFromContext(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx := WithContext(context.Background(), logger)
	retrieved := FromContext(ctx)

	if retrieved != logger {
		t.Error("FromContext should return the same logger")
	}

	// Test that logging works through context
	Info(ctx, "test message", "key", "value")
	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("expected log output to contain 'test message', got: %s", output)
	}
	if !strings.Contains(output, "key") {
		t.Errorf("expected log output to contain 'key', got: %s", output)
	}
}

func TestFromContextDefault(t *testing.T) {
	// Test that FromContext returns default logger when none is set
	ctx := context.Background()
	logger := FromContext(ctx)
	if logger == nil {
		t.Error("FromContext should never return nil")
	}
}

func TestWithField(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx := WithContext(context.Background(), logger)
	ctx = WithField(ctx, "request_id", "12345")

	Info(ctx, "operation")
	output := buf.String()
	if !strings.Contains(output, "request_id") {
		t.Errorf("expected log to contain request_id field: %s", output)
	}
	if !strings.Contains(output, "12345") {
		t.Errorf("expected log to contain value 12345: %s", output)
	}
}

func TestWithFields(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, nil))

	ctx := WithContext(context.Background(), logger)
	ctx = WithFields(ctx, map[string]any{
		"user":   "alice",
		"action": "scan",
		"repo":   "deputy",
	})

	Info(ctx, "audit event")
	output := buf.String()

	for _, expected := range []string{"user", "alice", "action", "scan", "repo", "deputy"} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected log to contain %q: %s", expected, output)
		}
	}
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		name    string
		logFunc func(context.Context, string, ...any)
		want    string
	}{
		{"debug", Debug, "DEBUG"},
		{"info", Info, "INFO"},
		{"warn", Warn, "WARN"},
		{"error", Error, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))
			ctx := WithContext(context.Background(), logger)

			tt.logFunc(ctx, "test message")
			output := buf.String()
			if !strings.Contains(output, tt.want) {
				t.Errorf("expected %s level in output, got: %s", tt.want, output)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name   string
		opts   Options
		verify func(*testing.T, *bytes.Buffer)
	}{
		{
			name: "text format",
			opts: Options{
				Level:  slog.LevelInfo,
				Format: "text",
			},
			verify: func(t *testing.T, buf *bytes.Buffer) {
				if buf.Len() == 0 {
					t.Error("expected log output")
				}
			},
		},
		{
			name: "json format",
			opts: Options{
				Level:  slog.LevelInfo,
				Format: "json",
			},
			verify: func(t *testing.T, buf *bytes.Buffer) {
				if !strings.Contains(buf.String(), `"msg"`) {
					t.Error("expected JSON formatted output")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			tt.opts.Writer = buf
			logger := New(tt.opts)

			logger.Info("test message")
			tt.verify(t, buf)
		})
	}
}

func TestColorHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewColorHandler(buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	ctx := context.Background()

	// Test different levels produce different colors
	logger.DebugContext(ctx, "debug message")
	logger.InfoContext(ctx, "info message")
	logger.WarnContext(ctx, "warn message")
	logger.ErrorContext(ctx, "error message")

	output := buf.String()

	// Should contain ANSI escape codes
	if !strings.Contains(output, "\033[") {
		t.Error("expected ANSI color codes in output")
	}

	// Should contain all messages
	for _, msg := range []string{"debug message", "info message", "warn message", "error message"} {
		if !strings.Contains(output, msg) {
			t.Errorf("expected output to contain %q", msg)
		}
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input   string
		want    slog.Level
		wantErr bool
	}{
		{"debug", slog.LevelDebug, false},
		{"DEBUG", slog.LevelDebug, false},
		{"info", slog.LevelInfo, false},
		{"INFO", slog.LevelInfo, false},
		{"warn", slog.LevelWarn, false},
		{"warning", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"ERROR", slog.LevelError, false},
		{"invalid", slog.LevelInfo, true},
		{"  debug  ", slog.LevelDebug, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSetDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	customLogger := slog.New(slog.NewTextHandler(buf, nil))

	SetDefault(customLogger)

	// Use a fresh context with no logger
	ctx := context.Background()
	Info(ctx, "test with custom default")

	if buf.Len() == 0 {
		t.Error("expected custom default logger to be used")
	}

	// Reset to avoid affecting other tests
	SetDefault(slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil)))
}

func TestColorHandlerWithGroup(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewColorHandler(buf, nil)
	wrappedHandler := handler.WithGroup("test_group")
	logger := slog.New(wrappedHandler)

	logger.Info("grouped message", "key", "value")
	output := buf.String()

	if !strings.Contains(output, "test_group") {
		t.Errorf("expected output to contain group name: %s", output)
	}
}

func TestColorHandlerWithAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	handler := NewColorHandler(buf, nil)
	wrappedHandler := handler.WithAttrs([]slog.Attr{
		slog.String("service", "deputy"),
		slog.String("version", "1.0"),
	})
	logger := slog.New(wrappedHandler)

	logger.Info("test message")
	output := buf.String()

	if !strings.Contains(output, "service") || !strings.Contains(output, "deputy") {
		t.Errorf("expected output to contain service attribute: %s", output)
	}
}
